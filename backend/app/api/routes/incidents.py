"""Incidents, investigation timeline and evidence export.

Authorisation: ``read`` for every GET (users and read-scoped API keys; exporting is audited);
``write`` for opening, updating, annotating and linking findings (signed-in users only, since API
keys never carry ``write``). Another organisation's ids return 404.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.database.session import get_db
from app.domain.enums import IncidentStatus, Permission, Severity
from app.schemas.common import Page
from app.schemas.incidents import (
    ActivityOut,
    IncidentCreateIn,
    IncidentDetailOut,
    IncidentSummaryOut,
    IncidentTimelineOut,
    IncidentUpdateIn,
    LinkFindingsIn,
    LinkFindingsOut,
    NoteIn,
    TimelineEntryType,
)
from app.services import incidents as workflow
from app.services import incidents_query
from app.services.incidents_export import build_evidence_bundle
from app.services.incidents_query import IncidentFilters, actor_ref, user_names
from app.services.incidents_timeline import incident_timeline

router = APIRouter(prefix="/incidents", tags=["incidents"])

READ = Depends(require(Permission.READ.value))
WRITE = Depends(require(Permission.WRITE.value))


def _user_id(principal: Principal) -> str:
    # ``write`` is only ever granted to users; keep the actor explicit for activity entries.
    return principal.user_id or principal.actor_id or "system"


@router.get("", response_model=Page[IncidentSummaryOut])
def list_incidents(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    status: list[IncidentStatus] | None = Query(None, description="Repeat to match several statuses"),
    severity: list[Severity] | None = Query(None, description="Repeat to match several severities"),
    include_simulated: bool = False,
    q: str | None = Query(None, max_length=200, description="Title, INC-<number> or exact incident id"),
    assignee_user_id: str | None = Query(None, max_length=40),
    unassigned: bool = False,
    agent_id: str | None = Query(None, max_length=40),
    sort: str = Query("priority", pattern="^(priority|recent|updated)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[IncidentSummaryOut]:
    """Incidents with finding counts and primary agent. ``priority`` lists active, severe incidents first."""
    filters = IncidentFilters(
        statuses=[s.value for s in status] if status else None,
        severities=[s.value for s in severity] if severity else None,
        include_simulated=include_simulated, q=q, assignee_user_id=assignee_user_id, unassigned=unassigned,
        agent_id=agent_id,
    )
    items, total = incidents_query.list_incidents(db, principal.org_id, filters, sort=sort, limit=limit, offset=offset)
    return Page[IncidentSummaryOut].model_validate({"items": items, "total": total, "limit": limit, "offset": offset})


@router.post("", response_model=IncidentDetailOut, status_code=201)
def create_incident(body: IncidentCreateIn, principal: Principal = WRITE,
                    db: Session = Depends(get_db)) -> IncidentDetailOut:
    """Open an incident, optionally grouping existing findings (it is at least as severe as the worst one)."""
    incident = workflow.open_incident(
        db, principal.org_id, title=body.title, summary=body.summary, severity=body.severity.value,
        finding_ids=body.finding_ids, actor_id=_user_id(principal),
    )
    db.commit()
    return IncidentDetailOut.model_validate(incidents_query.incident_detail(db, principal.org_id, incident.id))


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(incident_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> IncidentDetailOut:
    """The investigator's view: findings, involved agents/sessions/sources/destinations, activity and tasks."""
    return IncidentDetailOut.model_validate(incidents_query.incident_detail(db, principal.org_id, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetailOut)
def update_incident(incident_id: str, body: IncidentUpdateIn, principal: Principal = WRITE,
                    db: Session = Depends(get_db)) -> IncidentDetailOut:
    """Change status (validated transitions; closing needs a resolution), severity, assignee or resolution."""
    fields = body.model_fields_set
    workflow.update_incident(
        db, principal.org_id, incident_id, actor_id=_user_id(principal),
        status=body.status.value if body.status else None,
        severity=body.severity.value if body.severity else None,
        resolution=body.resolution,
        **({"assignee_user_id": body.assignee_user_id} if "assignee_user_id" in fields else {}),
    )
    db.commit()
    return IncidentDetailOut.model_validate(incidents_query.incident_detail(db, principal.org_id, incident_id))


@router.post("/{incident_id}/notes", response_model=ActivityOut, status_code=201)
def add_note(incident_id: str, body: NoteIn, principal: Principal = WRITE, db: Session = Depends(get_db)) -> ActivityOut:
    """Add an investigation note. Secrets in the text are redacted before it is stored."""
    activity = workflow.add_note(db, principal.org_id, incident_id, body=body.body, actor_id=_user_id(principal))
    db.commit()
    names = user_names(db, principal.org_id, {activity.actor})
    return ActivityOut.model_validate({
        "id": activity.id, "kind": activity.kind, "actor": actor_ref(activity.actor, names), "body": activity.body,
        "details": activity.details or {}, "created_at": activity.created_at,
    })


@router.post("/{incident_id}/findings", response_model=LinkFindingsOut)
def link_findings(incident_id: str, body: LinkFindingsIn, principal: Principal = WRITE,
                  db: Session = Depends(get_db)) -> LinkFindingsOut:
    """Attach findings to an active incident (all or nothing)."""
    result = workflow.link_findings(db, principal.org_id, incident_id, body.finding_ids, actor_id=_user_id(principal))
    db.commit()
    return LinkFindingsOut.model_validate({
        **result, "incident": incidents_query.incident_detail(db, principal.org_id, incident_id),
    })


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineOut)
def get_timeline(
    incident_id: str,
    principal: Principal = READ,
    db: Session = Depends(get_db),
    type: list[TimelineEntryType] | None = Query(None, description="Repeat to include several entry types"),  # noqa: A002
    limit: int = Query(500, ge=1, le=2000),
) -> IncidentTimelineOut:
    """Merged, chronological entries: involved sessions' events, findings, policy decisions, approvals and
    incident activity. Server-time order; an observed sequence, not causation."""
    return IncidentTimelineOut.model_validate(
        incident_timeline(db, principal.org_id, incident_id, types=list(type) if type else None, limit=limit))


@router.get("/{incident_id}/export", response_class=JSONResponse)
def export_incident(incident_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> JSONResponse:
    """Evidence bundle (JSON download). The export is recorded in the incident activity and the audit chain,
    including the bundle's SHA-256."""
    bundle, filename = build_evidence_bundle(
        db, principal.org_id, incident_id, actor_type=principal.actor_type, actor_id=principal.actor_id)
    db.commit()
    return JSONResponse(content=bundle, headers={
        "Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store",
    })
