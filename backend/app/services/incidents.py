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


# ----------------------------------------------------------------------------- investigation workflow
#
# Analyst actions on top of the primitives above. Every change writes an IncidentActivity row (the
# incident's own feed), an audit entry and an ``incident.updated`` notification. Free text is redacted
# before it is stored. Read models live in ``incidents_query`` / ``incidents_timeline`` /
# ``incidents_export``.

ACTIVE_STATUSES = (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value, IncidentStatus.CONTAINED.value)
CLOSED_STATUSES = (IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value)

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    IncidentStatus.OPEN.value: (
        IncidentStatus.INVESTIGATING.value, IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value,
    ),
    IncidentStatus.INVESTIGATING.value: (
        IncidentStatus.OPEN.value, IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value,
    ),
    IncidentStatus.CONTAINED.value: (
        IncidentStatus.INVESTIGATING.value, IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value,
    ),
    # Reopening sends the incident back to investigation; a resolved incident can also be reclassified.
    IncidentStatus.RESOLVED.value: (IncidentStatus.INVESTIGATING.value, IncidentStatus.FALSE_POSITIVE.value),
    IncidentStatus.FALSE_POSITIVE.value: (IncidentStatus.INVESTIGATING.value,),
}

STATUS_WORDS = {
    IncidentStatus.OPEN.value: "open",
    IncidentStatus.INVESTIGATING.value: "under investigation",
    IncidentStatus.CONTAINED.value: "contained",
    IncidentStatus.RESOLVED.value: "resolved",
    IncidentStatus.FALSE_POSITIVE.value: "a false positive",
}

TITLE_LIMIT = 400
TEXT_LIMIT = 8000
_UNSET: Any = object()


def allowed_transitions(status: str) -> list[str]:
    return list(ALLOWED_TRANSITIONS.get(status, ()))


def incident_key(incident: Incident) -> str:
    return f"INC-{incident.number}"


def _clean(text: str | None, limit: int) -> str | None:
    from app.services.findings import clean_note

    return clean_note(text, limit)


def _max_severity(*values: str | None) -> str:
    present = [v for v in values if v]
    return max(present, key=lambda s: SEVERITY_RANK.get(s, 0)) if present else Severity.INFO.value


def _member_name(db: Session, org_id: str, user_id: str) -> str | None:
    """Name of an active member of the organisation, or ``None`` when the user is not one."""
    from app.models import Membership, User

    return db.scalar(
        select(User.name).join(Membership, Membership.user_id == User.id).where(
            Membership.organization_id == org_id, User.id == user_id, User.is_active.is_(True))
    )


def _findings_for_link(db: Session, org_id: str, finding_ids: list[str]) -> list[SecurityFinding]:
    from app.core.errors import NotFoundError

    wanted = list(dict.fromkeys(finding_ids))
    if not wanted:
        return []
    rows = {f.id: f for f in db.scalars(select(SecurityFinding).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(wanted)))}
    missing = [fid for fid in wanted if fid not in rows]
    if missing:
        raise NotFoundError(f"Finding '{missing[0]}' not found", details={"missing": missing})
    return [rows[fid] for fid in wanted]


def open_incident(
    db: Session,
    org_id: str,
    *,
    title: str,
    summary: str,
    severity: str,
    finding_ids: list[str],
    actor_id: str,
) -> Incident:
    """Open an incident by hand, optionally grouping existing findings.

    Findings already part of another incident are refused (409) — move them explicitly instead — and
    simulated findings cannot be mixed with real ones. The incident is at least as severe as its most
    severe finding, and its primary agent/session come from that finding.
    """
    from app.core.errors import ConflictError, ValidationFailedError
    from app.services.findings import INCIDENT_AUDIT_ACTION

    clean_title = _clean(title, TITLE_LIMIT)
    if not clean_title:
        raise ValidationFailedError("Give the incident a title")
    findings = _findings_for_link(db, org_id, finding_ids)
    taken = [f for f in findings if f.incident_id]
    if taken:
        owner = db.scalar(select(Incident).where(Incident.organization_id == org_id, Incident.id == taken[0].incident_id))
        where = f"incident {incident_key(owner)}" if owner else "another incident"
        raise ConflictError(f"Finding '{taken[0].title}' is already part of {where}",
                            details={"finding_ids": [f.id for f in taken]})
    simulated = {bool(f.is_simulation) for f in findings}
    if len(simulated) > 1:
        raise ConflictError("Simulated and real findings cannot be grouped into one incident")
    lead = max(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 0), -f.first_seen_at.timestamp())) \
        if findings else None
    final = _max_severity(severity, *(f.severity for f in findings))
    incident = create_incident(
        db, org_id,
        title=clean_title,
        summary=_clean(summary, TEXT_LIMIT) or "",
        severity=final,
        finding_ids=[f.id for f in findings],
        primary_agent_id=lead.agent_id if lead else None,
        primary_session_id=lead.session_id if lead else None,
        created_by=actor_id,
        is_simulation=simulated.pop() if simulated else False,
    )
    if final != severity:
        add_activity(db, org_id, incident.id, actor="system", kind="severity_change",
                     body=f"Severity set to {final} to match the most severe linked finding",
                     details={"from": severity, "to": final})
    for finding in findings:
        append_audit(db, org_id, action=INCIDENT_AUDIT_ACTION, actor_type="user", actor_id=actor_id,
                     target_type="finding", target_id=finding.id,
                     details={"incident_id": incident.id, "created": True})
        notify(db, org_id, "finding.updated", id=finding.id)
    db.flush()
    return incident


def link_findings(db: Session, org_id: str, incident_id: str, finding_ids: list[str], *, actor_id: str) -> dict[str, list[str]]:
    """Attach findings to an incident (all or nothing). Returns ``{"linked": [...], "already_linked": [...]}``.

    Uses the same rules as linking from Security Intelligence: the incident must be active, a finding
    in another incident is refused, simulated and real records are not mixed.
    """
    from app.services.findings import link_finding_to_incident
    from app.services.scoping import get_scoped

    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    findings = _findings_for_link(db, org_id, finding_ids)
    already = [f.id for f in findings if f.incident_id == incident.id]
    linked: list[str] = []
    for finding in findings:
        if finding.incident_id == incident.id:
            continue
        link_finding_to_incident(db, org_id, finding.id, incident_id=incident.id, title=None, actor_id=actor_id)
        linked.append(finding.id)
    if linked and incident.primary_session_id is None:
        lead = max((f for f in findings if f.id in linked and f.session_id),
                   key=lambda f: SEVERITY_RANK.get(f.severity, 0), default=None)
        if lead is not None:
            incident.primary_session_id = lead.session_id
            incident.primary_agent_id = incident.primary_agent_id or lead.agent_id
    db.flush()
    return {"linked": linked, "already_linked": already}


def update_incident(
    db: Session,
    org_id: str,
    incident_id: str,
    *,
    actor_id: str,
    status: str | None = None,
    severity: str | None = None,
    assignee_user_id: Any = _UNSET,
    resolution: str | None = None,
) -> Incident:
    """Apply an analyst's changes. Status changes follow ``ALLOWED_TRANSITIONS`` (409 otherwise);
    closing (resolved / false positive) requires a resolution; reopening clears it (the activity feed
    and audit trail keep the history). ``assignee_user_id=None`` unassigns; a non-member is refused."""
    from app.core.errors import ConflictError, ValidationFailedError
    from app.services.scoping import get_scoped

    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    changes: dict[str, dict[str, Any]] = {}
    text = _clean(resolution, TEXT_LIMIT) if resolution is not None else None

    if status is not None and status != incident.status:
        previous = incident.status
        if status not in ALLOWED_TRANSITIONS.get(previous, ()):
            raise ConflictError(
                f"An incident that is {STATUS_WORDS.get(previous, previous)} cannot be marked "
                f"{STATUS_WORDS.get(status, status)}",
                details={"from": previous, "to": status, "allowed": allowed_transitions(previous)},
            )
        if status in CLOSED_STATUSES and not text:
            word = "why this is a false positive" if status == IncidentStatus.FALSE_POSITIVE.value \
                else "how the incident was resolved"
            raise ValidationFailedError(f"Explain {word} in the resolution")
        incident.status = status
        if status in CLOSED_STATUSES:
            incident.resolved_at = utcnow()
            incident.resolution = text
        elif previous in CLOSED_STATUSES:
            incident.resolved_at = None
            incident.resolution = None
        changes["status"] = {"from": previous, "to": status}
        reason = f" — {text}" if text and status in CLOSED_STATUSES else ""
        add_activity(db, org_id, incident.id, actor=actor_id, kind="status_change",
                     body=f"Marked {STATUS_WORDS.get(status, status)}{reason}", details={"from": previous, "to": status})
    elif resolution is not None:
        if incident.status not in CLOSED_STATUSES:
            raise ConflictError("A resolution can only be recorded when resolving the incident or after it is closed")
        if not text:
            raise ValidationFailedError("The resolution of a closed incident cannot be empty")
        if text != incident.resolution:
            changes["resolution"] = {"updated": True}
            incident.resolution = text
            add_activity(db, org_id, incident.id, actor=actor_id, kind="resolution_updated", body=text)

    if severity is not None and severity != incident.severity:
        changes["severity"] = {"from": incident.severity, "to": severity}
        add_activity(db, org_id, incident.id, actor=actor_id, kind="severity_change",
                     body=f"Severity changed from {incident.severity} to {severity}",
                     details={"from": incident.severity, "to": severity})
        incident.severity = severity

    if assignee_user_id is not _UNSET and assignee_user_id != incident.assignee_user_id:
        name = None
        if assignee_user_id is not None:
            name = _member_name(db, org_id, assignee_user_id)
            if name is None:
                raise ValidationFailedError("The assignee must be an active member of this organisation",
                                            details={"assignee_user_id": assignee_user_id})
        changes["assignee_user_id"] = {"from": incident.assignee_user_id, "to": assignee_user_id}
        add_activity(db, org_id, incident.id, actor=actor_id, kind="assigned",
                     body=f"Assigned to {name}" if name else "Unassigned",
                     details={"from": incident.assignee_user_id, "to": assignee_user_id})
        incident.assignee_user_id = assignee_user_id

    if not changes:
        return incident
    db.flush()
    action = "incident.status_changed" if "status" in changes else (
        "incident.assigned" if set(changes) == {"assignee_user_id"} else "incident.updated")
    append_audit(db, org_id, action=action, actor_type="user", actor_id=actor_id,
                 target_type="incident", target_id=incident.id, details={"changes": changes})
    notify(db, org_id, "incident.updated", id=incident.id)
    return incident


def add_note(db: Session, org_id: str, incident_id: str, *, body: str, actor_id: str) -> IncidentActivity:
    """Record an investigator's note (redacted). Notes can be added to closed incidents too."""
    from app.core.errors import ValidationFailedError
    from app.services.scoping import get_scoped

    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    text = _clean(body, TEXT_LIMIT)
    if not text:
        raise ValidationFailedError("A note cannot be empty")
    activity = add_activity(db, org_id, incident.id, actor=actor_id, kind="note", body=text)
    incident.updated_at = utcnow()
    db.flush()
    append_audit(db, org_id, action="incident.note_added", actor_type="user", actor_id=actor_id,
                 target_type="incident", target_id=incident.id,
                 details={"activity_id": activity.id, "length": len(text)})
    notify(db, org_id, "incident.updated", id=incident.id)
    return activity
