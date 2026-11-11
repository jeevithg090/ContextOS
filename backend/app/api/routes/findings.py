"""Security Intelligence: findings, detection statistics and triage.

Authorisation: ``read`` for every GET (users and read-scoped API keys); ``write`` for triage and
incident linking. Every lookup is scoped to the caller's organisation; another organisation's ids
return 404. Static paths (``/stats``) are registered before ``/{finding_id}``.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import FindingCategory, FindingStatus, Permission, Severity
from app.schemas.common import Page
from app.schemas.findings import (
    FindingDetailOut,
    FindingIncidentIn,
    FindingIncidentOut,
    FindingStatsOut,
    FindingSummaryOut,
    FindingUpdateIn,
)
from app.services import findings as triage
from app.services import findings_query
from app.services.findings_query import FindingFilters

router = APIRouter(prefix="/findings", tags=["findings"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403
WRITE = Depends(require(Permission.WRITE.value))


@router.get("", response_model=Page[FindingSummaryOut])
def list_findings(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    status: list[FindingStatus] | None = Query(None, description="Repeat to match several statuses"),
    severity: list[Severity] | None = Query(None, description="Repeat to match several severities"),
    category: list[FindingCategory] | None = Query(None),
    agent_id: str | None = Query(None, max_length=40),
    session_id: str | None = Query(None, max_length=40),
    source_id: str | None = Query(None, max_length=40),
    incident_id: str | None = Query(None, max_length=40),
    include_simulated: bool = False,
    q: str | None = Query(None, max_length=200, description="Title, rule id, explanation or exact finding id"),
    since: datetime | None = Query(None, description="Only findings seen at or after this time"),
    sort: str = Query("severity", pattern="^(severity|recent|first_seen|occurrences)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[FindingSummaryOut]:
    """Findings, most severe first and then most recently seen."""
    filters = FindingFilters(
        statuses=[s.value for s in status] if status else None,
        severities=[s.value for s in severity] if severity else None,
        categories=[c.value for c in category] if category else None,
        agent_id=agent_id, session_id=session_id, source_id=source_id, incident_id=incident_id,
        include_simulated=include_simulated, q=q, since=since,
    )
    items, total = findings_query.list_findings(db, principal.org_id, filters, sort=sort, limit=limit, offset=offset)
    return Page[FindingSummaryOut].model_validate({"items": items, "total": total, "limit": limit, "offset": offset})


@router.get("/stats", response_model=FindingStatsOut)
def finding_stats(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    window: str = Query("7d", pattern="^(24h|7d|30d|90d)$"),
    include_simulated: bool = False,
) -> FindingStatsOut:
    """Open backlog, new findings in the window (by severity, category and status, trend, top sources)
    and mean time to resolve."""
    return FindingStatsOut.model_validate(
        findings_query.finding_stats(db, principal.org_id, window=window, include_simulated=include_simulated))


@router.get("/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> FindingDetailOut:
    """A finding with its evidence resolved to records, the related agent, session, source, context item,
    tool call, decision, destination, incident and remediation tasks, and its triage history."""
    return FindingDetailOut.model_validate(findings_query.finding_detail(db, principal.org_id, finding_id))


@router.patch("/{finding_id}", response_model=FindingDetailOut)
def update_finding(finding_id: str, body: FindingUpdateIn, principal: Principal = WRITE,
                   db: Session = Depends(get_db)) -> FindingDetailOut:
    """Triage: acknowledge, resolve, mark false positive (a reason is required) or reopen; or edit the
    resolution note of a closed finding. Invalid transitions return 409."""
    triage.update_finding_status(
        db, principal.org_id, finding_id,
        status=body.status.value if body.status else None, note=body.resolution_note,
        actor_type=principal.actor_type, actor_id=principal.actor_id,
    )
    db.commit()
    return FindingDetailOut.model_validate(findings_query.finding_detail(db, principal.org_id, finding_id))


@router.post("/{finding_id}/incident", response_model=FindingIncidentOut)
def link_incident(finding_id: str, body: FindingIncidentIn, principal: Principal = WRITE,
                  db: Session = Depends(get_db)) -> FindingIncidentOut:
    """Attach the finding to an existing open incident, or open a new incident for it."""
    incident, created = triage.link_finding_to_incident(
        db, principal.org_id, finding_id, incident_id=body.incident_id, title=body.title,
        actor_id=principal.user_id,
    )
    db.commit()
    return FindingIncidentOut.model_validate({
        "created": created,
        "incident": findings_query.incident_ref(incident),
        "finding": findings_query.finding_summary(db, principal.org_id, finding_id),
    })
