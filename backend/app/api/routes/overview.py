"""Security command centre aggregates (from persisted data only).

Authorisation: ``read`` (users and read-scoped API keys). Both endpoints summarise the whole
organisation, so an API key bound to a single agent is refused (403): it may only see that agent's
records through the endpoints that scope to it. Read-only: nothing here writes, audits or notifies.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.core.errors import PermissionDeniedError
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.overview import NavCountsOut, OverviewOut
from app.services import overview_service

router = APIRouter(prefix="/overview", tags=["overview"])


def _org_wide_reader(principal: Principal = Depends(require(Permission.READ.value))) -> Principal:
    if principal.bound_agent_id:
        raise PermissionDeniedError("This API key is bound to one agent; the organisation overview needs an unbound "
                                    "read key or a signed-in member")
    return principal


READ = Depends(_org_wide_reader)


@router.get("/nav-counts", response_model=NavCountsOut)
def nav_counts(principal: Principal = READ, db: Session = Depends(get_db)) -> NavCountsOut:
    """Sidebar badges: pending approvals (not past their deadline), open incidents and open findings.
    Simulation Lab rows are not counted."""
    return NavCountsOut.model_validate(overview_service.nav_counts(db, principal.org_id))


@router.get("", response_model=OverviewOut)
def get_overview(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    window: str = Query("24h", pattern="^(24h|7d|30d)$", description="Hourly buckets for 24h, daily otherwise"),
    include_simulated: bool = Query(False, description="Count Simulation Lab rows (each item is labelled)"),
) -> OverviewOut:
    """Current posture (agents, sessions, lethal-trifecta sessions, source trust, open findings,
    approvals and incidents), the window's decisions and enforcement coverage, event / finding /
    decision series, the riskiest agents, what needs attention, recently denied or paused tool calls,
    integration health, recent audit activity and onboarding progress."""
    return OverviewOut.model_validate(
        overview_service.overview(db, principal.org_id, window=window, include_simulated=include_simulated))
