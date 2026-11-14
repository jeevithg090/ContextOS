"""Approval primitives shared by ingestion (REQUIRE_APPROVAL decisions) and the Approval Centre.

The Approvals work package extends this module (decide, expire, list) but MUST keep
``create_approval`` and ``get_approval_status`` signatures stable.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, NotFoundError
from app.core.ids import new_id
from app.core.timeutil import isoformat, utcnow
from app.domain.enums import ApprovalStatus
from app.engines.redaction import redact_text
from app.models import Approval, ToolInvocation
from app.services.audit import append_audit
from app.services.notify import notify
from app.services.scoping import get_scoped


def create_approval(
    db: Session,
    org_id: str,
    *,
    policy_decision_id: str,
    tool_invocation_id: str | None,
    agent_id: str,
    session_id: str,
    summary: str,
    risk_summary: dict[str, Any],
    timeout_s: int | None = None,
    is_simulation: bool = False,
) -> Approval:
    timeout = timeout_s or get_settings().approval_default_timeout_s
    now = utcnow()
    approval = Approval(
        id=new_id("approval"),
        organization_id=org_id,
        policy_decision_id=policy_decision_id,
        tool_invocation_id=tool_invocation_id,
        agent_id=agent_id,
        session_id=session_id,
        status=ApprovalStatus.PENDING,
        summary=summary,
        risk_summary=risk_summary,
        requested_at=now,
        expires_at=now + timedelta(seconds=timeout),
        is_simulation=is_simulation,
    )
    db.add(approval)
    db.flush()
    notify(db, org_id, "approval.created", id=approval.id)
    return approval


def get_approval_status(db: Session, org_id: str, approval_id: str) -> Approval:
    """Fetch an approval, lazily expiring it if its deadline passed.

    The expiry is a conditional UPDATE like every other transition out of ``pending``: a reviewer's
    decision committed after this request read the row is never overwritten with ``expired``.
    """
    approval = get_scoped(db, Approval, approval_id, org_id, label="Approval")
    now = utcnow()
    if _overdue(approval, now):
        closed = _close(db, org_id, approval.id, {"status": ApprovalStatus.EXPIRED, "decided_at": now})
        db.refresh(approval)
        if closed:
            notify(db, org_id, "approval.decided", id=approval.id, status=ApprovalStatus.EXPIRED.value)
    return approval


# -- Approval Centre: lifecycle (expiry, human decisions) ---------------------------------------
#
# Every transition out of ``pending`` is a conditional UPDATE (``WHERE status = 'pending'``), so two
# reviewers deciding at once, or a decision racing an expiry, can never both win: the loser gets a
# 409. The integration polls ``GET /decide/approvals/{id}``, which reads ``Approval.status``.

# Invocation statuses written when the approval closes. ``expired`` is in the ingestion pipeline's
# NOT_ALLOWED set, so a call that still runs afterwards is reported as "ran despite the decision".
_INVOCATION_STATUS = {
    ApprovalStatus.APPROVED: "approved",
    ApprovalStatus.REJECTED: "rejected",
    ApprovalStatus.EXPIRED: "expired",
}
_AWAITING = "pending_approval"
MAX_NOTE_CHARS = 2000


def _close(db: Session, org_id: str, approval_id: str, values: dict[str, Any]) -> bool:
    """Move one approval out of ``pending``. False when another request already closed it."""
    result = db.execute(
        update(Approval)
        .where(
            Approval.organization_id == org_id,
            Approval.id == approval_id,
            Approval.status == ApprovalStatus.PENDING,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1  # type: ignore[attr-defined]


def _settle_invocation(
    db: Session, org_id: str, approval: Approval, status: str
) -> tuple[str | None, str | None]:
    """Record the approval outcome on the paused call. Returns (status before, status after).

    Only a call still waiting (``pending_approval``) changes; a call the integration ran anyway
    keeps its ``completed`` / ``failed`` status (the result handler already flagged it).
    """
    if not approval.tool_invocation_id:
        return None, None
    before = db.scalar(
        select(ToolInvocation.status).where(
            ToolInvocation.organization_id == org_id, ToolInvocation.id == approval.tool_invocation_id
        )
    )
    if before is None:
        return None, None
    if before != _AWAITING:
        return before, before
    db.execute(
        update(ToolInvocation)
        .where(
            ToolInvocation.organization_id == org_id,
            ToolInvocation.id == approval.tool_invocation_id,
            ToolInvocation.status == _AWAITING,
        )
        .values(status=status)
        .execution_options(synchronize_session=False)
    )
    return before, status


def _record_expiry(db: Session, org_id: str, approval: Approval) -> None:
    before, after = _settle_invocation(db, org_id, approval, _INVOCATION_STATUS[ApprovalStatus.EXPIRED])
    append_audit(
        db,
        org_id,
        action="approval.expired",
        actor_type="system",
        target_type="approval",
        target_id=approval.id,
        details={
            "outcome": ApprovalStatus.EXPIRED.value,
            "tool_invocation_id": approval.tool_invocation_id,
            "policy_decision_id": approval.policy_decision_id,
            "agent_id": approval.agent_id,
            "session_id": approval.session_id,
            "invocation_status_before": before,
            "invocation_status": after,
            "expires_at": isoformat(approval.expires_at),
        },
    )


def _expire(db: Session, org_id: str, approval: Approval, now: datetime) -> bool:
    """Expire one overdue approval. False when another request closed it first (``approval`` is
    refreshed either way)."""
    closed = _close(db, org_id, approval.id, {"status": ApprovalStatus.EXPIRED, "decided_at": now})
    db.refresh(approval)
    if closed:
        _record_expiry(db, org_id, approval)
        notify(
            db,
            org_id,
            "approval.decided",
            id=approval.id,
            status=ApprovalStatus.EXPIRED.value,
            session_id=approval.session_id,
        )
    return closed


def _overdue(approval: Approval, now: datetime) -> bool:
    return (
        approval.status == ApprovalStatus.PENDING
        and approval.expires_at is not None
        and approval.expires_at <= now
    )


def _call_awaiting(db: Session, org_id: str, approval: Approval) -> bool:
    if not approval.tool_invocation_id:
        return False
    status = db.scalar(
        select(ToolInvocation.status).where(
            ToolInvocation.organization_id == org_id, ToolInvocation.id == approval.tool_invocation_id
        )
    )
    return status == _AWAITING


def expire_overdue(db: Session, org_id: str, *, now: datetime | None = None) -> int:
    """Expire pending approvals past their deadline; returns how many this call expired.

    Also settles approvals that integration polling (``get_approval_status``) expired lazily but
    whose call is still marked ``pending_approval``: the call becomes ``expired`` and the expiry is
    audited.
    """
    now = now or utcnow()
    overdue = list(
        db.scalars(
            select(Approval).where(
                Approval.organization_id == org_id,
                Approval.status == ApprovalStatus.PENDING,
                Approval.expires_at.is_not(None),
                Approval.expires_at <= now,
            )
        )
    )
    expired = sum(1 for approval in overdue if _expire(db, org_id, approval, now))
    unsettled = db.scalars(
        select(Approval)
        .join(
            ToolInvocation,
            (ToolInvocation.id == Approval.tool_invocation_id) & (ToolInvocation.organization_id == org_id),
        )
        .where(
            Approval.organization_id == org_id,
            Approval.status == ApprovalStatus.EXPIRED,
            ToolInvocation.status == _AWAITING,
        )
    ).all()
    for approval in unsettled:
        _record_expiry(db, org_id, approval)
    db.flush()
    return expired


def refresh_expiry(db: Session, org_id: str, approval: Approval) -> Approval:
    """Bring one approval up to date before showing it (lazy expiry + settling its call)."""
    now = utcnow()
    if _overdue(approval, now):
        _expire(db, org_id, approval, now)
    elif approval.status == ApprovalStatus.EXPIRED and _call_awaiting(db, org_id, approval):
        _record_expiry(db, org_id, approval)
    return approval


def decide_approval(
    db: Session, org_id: str, approval_id: str, *, approve: bool, note: str | None, user_id: str
) -> Approval:
    """Record a human decision. Raises ``ConflictError`` (409) unless the approval is still pending.

    An approval whose deadline has passed is expired first (the caller commits that before
    returning the 409): the integration has already been, or will be, told it timed out.
    """
    approval = get_scoped(db, Approval, approval_id, org_id, label="Approval")  # 404 across orgs
    refresh_expiry(db, org_id, approval)
    if approval.status == ApprovalStatus.EXPIRED:
        raise ConflictError(
            f"This request expired at {isoformat(approval.expires_at)} and can no longer be decided. "
            "The integration treats an expired request as not approved; the agent can ask again.",
            details={"status": approval.status, "expires_at": isoformat(approval.expires_at)},
        )
    if approval.status != ApprovalStatus.PENDING:
        raise ConflictError(
            _already_closed(approval),
            details={
                "status": approval.status,
                "decided_at": isoformat(approval.decided_at),
                "decided_by_user_id": approval.decided_by_user_id,
            },
        )

    status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
    clean_note = _clean_note(note)
    now = utcnow()
    if not _close(
        db,
        org_id,
        approval.id,
        {"status": status, "decided_at": now, "decided_by_user_id": user_id, "decision_note": clean_note},
    ):
        db.refresh(approval)
        raise ConflictError(_already_closed(approval), details={"status": approval.status})
    db.refresh(approval)
    before, after = _settle_invocation(db, org_id, approval, _INVOCATION_STATUS[status])
    waited = (now - approval.requested_at).total_seconds() if approval.requested_at else None
    append_audit(
        db,
        org_id,
        action="approval.decided",
        actor_type="user",
        actor_id=user_id,
        target_type="approval",
        target_id=approval.id,
        details={
            "outcome": status.value,
            "tool_invocation_id": approval.tool_invocation_id,
            "policy_decision_id": approval.policy_decision_id,
            "agent_id": approval.agent_id,
            "session_id": approval.session_id,
            "invocation_status_before": before,
            "invocation_status": after,
            "note": clean_note[:500] if clean_note else None,
            "waited_s": round(waited, 1) if waited is not None else None,
            "is_simulation": bool(approval.is_simulation),
        },
    )
    notify(
        db,
        org_id,
        "approval.decided",
        id=approval.id,
        status=status.value,
        session_id=approval.session_id,
        tool_invocation_id=approval.tool_invocation_id,
    )
    db.flush()
    return approval


def _clean_note(note: str | None) -> str | None:
    text = (note or "").strip()
    if not text:
        return None
    return redact_text(text[:MAX_NOTE_CHARS]).text


def _already_closed(approval: Approval) -> str:
    when = isoformat(approval.decided_at)
    if approval.status == ApprovalStatus.EXPIRED:
        return f"This request already expired{f' at {when}' if when else ''}."
    return f"This request was already {approval.status}{f' at {when}' if when else ''}."


MAX_CANCEL_REASON_CHARS = 500


def cancel_approval(
    db: Session,
    org_id: str,
    approval_id: str,
    *,
    actor_type: str,
    actor_id: str | None,
    reason: str | None = None,
    bound_agent_id: str | None = None,
) -> Approval:
    """An integration stopped waiting for a reviewer (its host timed out or the user aborted).

    The approval becomes ``cancelled`` and the paused call ``cancelled`` (a result reported later is
    flagged as "ran despite the decision"). Cancelling an already cancelled approval returns it
    unchanged; one a person already decided, or that expired, is a 409. An API key bound to one
    agent can only cancel that agent's approvals (others are not found).
    """
    approval = get_scoped(db, Approval, approval_id, org_id, label="Approval")  # 404 across orgs
    if bound_agent_id and approval.agent_id != bound_agent_id:
        raise NotFoundError(f"Approval '{approval_id}' not found")
    refresh_expiry(db, org_id, approval)
    if approval.status == ApprovalStatus.CANCELLED:
        return approval
    if approval.status != ApprovalStatus.PENDING:
        raise ConflictError(
            _already_closed(approval),
            details={"status": approval.status, "decided_at": isoformat(approval.decided_at)},
        )
    now = utcnow()
    if not _close(db, org_id, approval.id, {"status": ApprovalStatus.CANCELLED, "decided_at": now}):
        db.refresh(approval)
        if approval.status == ApprovalStatus.CANCELLED:
            return approval
        raise ConflictError(_already_closed(approval), details={"status": approval.status})
    db.refresh(approval)
    before, after = _settle_invocation(db, org_id, approval, ApprovalStatus.CANCELLED.value)
    clean = redact_text(reason.strip()[:MAX_CANCEL_REASON_CHARS]).text if reason and reason.strip() else None
    append_audit(
        db,
        org_id,
        action="approval.cancelled",
        actor_type=actor_type,
        actor_id=actor_id,
        target_type="approval",
        target_id=approval.id,
        details={
            "outcome": ApprovalStatus.CANCELLED.value,
            "tool_invocation_id": approval.tool_invocation_id,
            "policy_decision_id": approval.policy_decision_id,
            "agent_id": approval.agent_id,
            "session_id": approval.session_id,
            "invocation_status_before": before,
            "invocation_status": after,
            "reason": clean,
            "is_simulation": bool(approval.is_simulation),
        },
    )
    notify(
        db,
        org_id,
        "approval.decided",
        id=approval.id,
        status=ApprovalStatus.CANCELLED.value,
        session_id=approval.session_id,
        tool_invocation_id=approval.tool_invocation_id,
    )
    db.flush()
    return approval
