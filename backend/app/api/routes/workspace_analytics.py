"""Engineering analytics and the security-remediation pipeline, computed from task, verification and
finding records (``read`` permission).

- ``GET /workspace/analytics`` — task flow, resolution time, verification failures and remediation
  coverage for a window (``7d`` … ``365d``). ``board_id`` narrows task metrics; finding metrics always
  cover the whole organisation.
- ``GET /workspace/analytics/remediation`` — open findings (most severe first) with their remediation
  state: ``no_task`` | ``task_open`` | ``task_done_unverified`` | ``verified``.

Ids from other organisations answer 404.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.workspace import SeverityName
from app.schemas.workspace_analytics import EngineeringAnalyticsOut, RemediationPageOut, RemediationStateName
from app.services import workspace_analytics as analytics

router = APIRouter(prefix="/workspace/analytics", tags=["workspace"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403


@router.get("", response_model=EngineeringAnalyticsOut)
def engineering_analytics(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    board_id: str | None = Query(None, description="Limit task metrics to one board"),
    window: str = Query("30d", pattern=r"^\d{1,3}d$", description="Look-back window in days, e.g. 7d, 30d, 90d"),
    include_simulated: bool = Query(False, description="Count findings produced by Simulation Lab runs"),
) -> EngineeringAnalyticsOut:
    return analytics.engineering_analytics(
        db, principal.org_id, board_id=board_id, window_days=analytics.parse_window(window),
        include_simulated=include_simulated,
    )


@router.get("/remediation", response_model=RemediationPageOut)
def remediation_pipeline(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    state: RemediationStateName | None = None,
    severity: SeverityName | None = None,
    q: str | None = Query(None, max_length=200, description="Finding title contains"),
    include_simulated: bool = Query(False, description="Include findings produced by Simulation Lab runs"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> RemediationPageOut:
    return analytics.remediation_pipeline(
        db, principal.org_id, state=state, severity=severity, q=q, include_simulated=include_simulated,
        limit=limit, offset=offset,
    )
