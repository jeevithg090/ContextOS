"""Approval Centre: tool calls paused by REQUIRE_APPROVAL policies, waiting for a human.

Authorisation: ``read`` for the queue, history and detail (users and read-scoped API keys; a key
bound to one agent sees only that agent's approvals); ``approve`` (signed-in users only) to decide.
Every lookup is scoped to the caller's organisation; another organisation's ids return 404.

Expiry is lazy: reading the queue or one approval first expires pending requests whose deadline has
passed (audited as ``approval.expired``), so the queue never shows a request that can no longer be
decided. Integrations poll ``GET /decide/approvals/{id}``, which reads the same ``Approval`` row.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.core.errors import ConflictError, PermissionDeniedError
from app.database.session import get_db
from app.domain.enums import ApprovalStatus, Permission
from app.schemas.approvals import ApprovalDecideIn, ApprovalDetailOut, ApprovalOut
from app.schemas.common import Page
from app.services import approvals as lifecycle
from app.services import approvals_query
from app.services.approvals_query import ApprovalFilters

router = APIRouter(prefix="/approvals", tags=["approvals"])

READ = Depends(require(Permission.READ.value))
APPROVE = Depends(require(Permission.APPROVE.value))


@router.get("", response_model=Page[ApprovalOut])
def list_approvals(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    status: list[ApprovalStatus] | None = Query(
        None, description="Repeat to match several statuses. Defaults to pending (the queue)."
    ),
    include_simulated: bool = Query(False, description="Include approvals opened by Simulation Lab runs"),
    agent_id: str | None = Query(None, max_length=40),
    session_id: str | None = Query(None, max_length=40),
    sort: str | None = Query(
        None,
        pattern="^(oldest|newest|recently_decided)$",
        description="Default: oldest first for the pending queue, latest decision first otherwise",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ApprovalOut]:
    """The pending queue (oldest first: closest to timing out) or the decision history."""
    lifecycle.expire_overdue(db, principal.org_id)
    db.commit()
    filters = ApprovalFilters(
        statuses=[s.value for s in status] if status else [ApprovalStatus.PENDING.value],
        include_simulated=include_simulated,
        agent_id=agent_id,
        session_id=session_id,
        bound_agent_id=principal.bound_agent_id,
    )
    items, total = approvals_query.list_approvals(
        db, principal.org_id, filters, sort=sort, limit=limit, offset=offset
    )
    return Page[ApprovalOut].model_validate(
        {"items": items, "total": total, "limit": limit, "offset": offset}
    )


@router.get("/{approval_id}", response_model=ApprovalDetailOut)
def get_approval(
    approval_id: str, principal: Principal = READ, db: Session = Depends(get_db)
) -> ApprovalDetailOut:
    """Everything a reviewer needs: the redacted arguments, resources (sensitive ones flagged), the
    destination and the checks run on it, why the policy paused the call, the session's trifecta
    evidence, the context the agent had received, related findings and the approval's audit trail."""
    approval = approvals_query.load_approval(
        db, principal.org_id, approval_id, bound_agent_id=principal.bound_agent_id
    )
    lifecycle.refresh_expiry(db, principal.org_id, approval)
    db.commit()
    return ApprovalDetailOut.model_validate(
        approvals_query.approval_detail(
            db, principal.org_id, approval_id, bound_agent_id=principal.bound_agent_id
        )
    )


@router.post("/{approval_id}/decide", response_model=ApprovalDetailOut)
def decide_approval(
    approval_id: str, body: ApprovalDecideIn, principal: Principal = APPROVE, db: Session = Depends(get_db)
) -> ApprovalDetailOut:
    """Approve or reject a pending request. 409 when it is no longer pending (already decided, or
    expired). The integration that paused the call receives the outcome on its next poll."""
    if principal.user_id is None:
        raise PermissionDeniedError("Only a signed-in person can decide an approval")
    try:
        lifecycle.decide_approval(
            db, principal.org_id, approval_id, approve=body.approve, note=body.note, user_id=principal.user_id
        )
    except ConflictError:
        db.commit()  # keep the lazy expiry (and its audit entry) the check may have recorded
        raise
    db.commit()
    return ApprovalDetailOut.model_validate(
        approvals_query.approval_detail(db, principal.org_id, approval_id)
    )
