"""Approval primitives shared by ingestion (REQUIRE_APPROVAL decisions) and the Approval Centre.

The Approvals work package extends this module (decide, expire, list) but MUST keep
``create_approval`` and ``get_approval_status`` signatures stable.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.domain.enums import ApprovalStatus
from app.models import Approval
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
    """Fetch an approval, lazily expiring it if its deadline passed."""
    approval = get_scoped(db, Approval, approval_id, org_id, label="Approval")
    if approval.status == ApprovalStatus.PENDING and approval.expires_at and approval.expires_at <= utcnow():
        approval.status = ApprovalStatus.EXPIRED
        approval.decided_at = utcnow()
        notify(db, org_id, "approval.decided", id=approval.id, status=approval.status)
    return approval
