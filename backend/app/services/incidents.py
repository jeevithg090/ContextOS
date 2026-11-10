"""Incident primitives shared by ingestion (auto-escalation) and the Incidents feature.

The Incidents work package extends this module (status transitions, assignment, evidence export)
but MUST keep ``create_incident``, ``add_activity`` and ``escalate_finding`` signatures stable.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.domain.enums import SEVERITY_RANK, IncidentStatus, Severity
from app.models import Incident, IncidentActivity, SecurityFinding
from app.services.audit import append_audit
from app.services.notify import notify

# Findings at or above this severity open (or join) an incident automatically.
AUTO_ESCALATION_SEVERITY = Severity.CRITICAL
# Categories that escalate at HIGH as well, because they indicate an attempted data movement.
ESCALATE_AT_HIGH = {"exfiltration", "lethal_trifecta", "secret_exposure", "cross_agent_contamination"}


def add_activity(
    db: Session, org_id: str, incident_id: str, *, actor: str, kind: str, body: str = "", details: dict[str, Any] | None = None
) -> IncidentActivity:
    activity = IncidentActivity(
        id=new_id("incident_activity"),
        organization_id=org_id,
        incident_id=incident_id,
        actor=actor,
        kind=kind,
        body=body,
        details=details or {},
        created_at=utcnow(),
    )
    db.add(activity)
    return activity


def create_incident(
    db: Session,
    org_id: str,
    *,
    title: str,
    summary: str,
    severity: str,
    finding_ids: list[str] | None = None,
    primary_agent_id: str | None = None,
    primary_session_id: str | None = None,
    created_by: str = "system",
    is_simulation: bool = False,
) -> Incident:
    count = db.scalar(select(Incident.number).where(Incident.organization_id == org_id).order_by(Incident.number.desc()).limit(1)) or 0
    incident = Incident(
        id=new_id("incident"),
        organization_id=org_id,
        number=count + 1,
        title=title[:400],
        summary=summary,
        severity=severity,
        status=IncidentStatus.OPEN,
        primary_agent_id=primary_agent_id,
        primary_session_id=primary_session_id,
        created_by=created_by,
        opened_at=utcnow(),
        is_simulation=is_simulation,
    )
    db.add(incident)
    db.flush()
    add_activity(db, org_id, incident.id, actor=created_by, kind="created", body=summary)
    for fid in finding_ids or []:
        finding = db.scalar(select(SecurityFinding).where(SecurityFinding.organization_id == org_id, SecurityFinding.id == fid))
        if finding is not None:
            finding.incident_id = incident.id
            add_activity(db, org_id, incident.id, actor=created_by, kind="finding_linked", body=finding.title, details={"finding_id": fid})
    append_audit(
        db, org_id, action="incident.created",
        actor_type="system" if created_by == "system" else "user", actor_id=None if created_by == "system" else created_by,
        target_type="incident", target_id=incident.id, details={"severity": severity, "auto": created_by == "system"},
    )
    notify(db, org_id, "incident.created", id=incident.id)
    return incident


def should_escalate(finding: SecurityFinding) -> bool:
    rank = SEVERITY_RANK.get(finding.severity, 0)
    if rank >= SEVERITY_RANK[AUTO_ESCALATION_SEVERITY]:
        return True
    return finding.category in ESCALATE_AT_HIGH and rank >= SEVERITY_RANK[Severity.HIGH]


def escalate_finding(db: Session, finding: SecurityFinding) -> Incident | None:
    """Attach a qualifying finding to the open incident for its session, or open a new one."""
    if finding.incident_id or not should_escalate(finding):
        return None
    org_id = finding.organization_id
    incident = None
    if finding.session_id:
        incident = db.scalar(
            select(Incident).where(
                Incident.organization_id == org_id,
                Incident.primary_session_id == finding.session_id,
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]),
            )
        )
    if incident is None:
        return create_incident(
            db, org_id,
            title=finding.title,
            summary=f"Opened automatically from a {finding.severity} {finding.category.replace('_', ' ')} finding. {finding.explanation}",
            severity=finding.severity,
            finding_ids=[finding.id],
            primary_agent_id=finding.agent_id,
            primary_session_id=finding.session_id,
            is_simulation=finding.is_simulation,
        )
    finding.incident_id = incident.id
    if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
        incident.severity = finding.severity
    add_activity(db, org_id, incident.id, actor="system", kind="finding_linked", body=finding.title, details={"finding_id": finding.id})
    notify(db, org_id, "incident.updated", id=incident.id)
    return incident
