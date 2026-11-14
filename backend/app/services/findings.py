"""Recording security findings (shared by ingestion, simulations and analysts).

Findings are de-duplicated by a fingerprint of (category, rule, the most specific subject), so a
README re-read 50 times produces one finding with ``occurrence_count == 50`` rather than 50 rows.
High-impact findings are escalated to incidents via ``app.services.incidents``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import sha256_hex
from app.core.timeutil import utcnow
from app.domain.enums import SEVERITY_RANK, FindingStatus
from app.models import SecurityFinding
from app.services.notify import notify


def finding_fingerprint(
    org_id: str,
    category: str,
    rule_id: str,
    *,
    session_id: str | None,
    source_id: str | None,
    tool_invocation_id: str | None,
    destination_id: str | None,
) -> str:
    subject = tool_invocation_id or destination_id or source_id or ""
    # Scope source-level findings per session so each affected session is visible, but repeated
    # reads within one session collapse.
    return sha256_hex("|".join([org_id, category, rule_id, session_id or "", subject]))


def record_finding(
    db: Session,
    org_id: str,
    *,
    category: str,
    rule_id: str,
    title: str,
    explanation: str,
    severity: str,
    confidence: float,
    evidence: list[dict[str, Any]],
    agent_id: str | None = None,
    session_id: str | None = None,
    source_id: str | None = None,
    context_item_id: str | None = None,
    tool_invocation_id: str | None = None,
    policy_decision_id: str | None = None,
    destination_id: str | None = None,
    remediation: str | None = None,
    is_simulation: bool = False,
) -> tuple[SecurityFinding, bool]:
    """Create or bump a finding. Returns ``(finding, created)``. Evidence excerpts must be redacted."""
    fp = finding_fingerprint(
        org_id,
        category,
        rule_id,
        session_id=session_id,
        source_id=source_id,
        tool_invocation_id=tool_invocation_id,
        destination_id=destination_id,
    )
    existing = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.organization_id == org_id,
            SecurityFinding.fingerprint == fp,
            SecurityFinding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        )
    )
    now = utcnow()
    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = severity
        existing.confidence = max(existing.confidence, confidence)
        known = {(e.get("type"), e.get("id")) for e in existing.evidence or []}
        merged = list(existing.evidence or [])
        for item in evidence:
            if (item.get("type"), item.get("id")) not in known and len(merged) < 50:
                merged.append(item)
        existing.evidence = merged
        notify(db, org_id, "finding.updated", id=existing.id)
        return existing, False

    finding = SecurityFinding(
        id=new_id("finding"),
        organization_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        category=category,
        rule_id=rule_id,
        title=title[:400],
        explanation=explanation,
        severity=severity,
        confidence=round(float(confidence), 3),
        status=FindingStatus.OPEN,
        evidence=evidence[:50],
        source_id=source_id,
        context_item_id=context_item_id,
        tool_invocation_id=tool_invocation_id,
        policy_decision_id=policy_decision_id,
        destination_id=destination_id,
        fingerprint=fp,
        first_seen_at=now,
        last_seen_at=now,
        remediation=remediation,
        is_simulation=is_simulation,
    )
    db.add(finding)
    db.flush()
    notify(db, org_id, "finding.created", id=finding.id, severity=severity, category=category)
    return finding, True


# ----------------------------------------------------------------------------- triage
#
# Analyst workflow on top of ``record_finding``. Every change is audited (``finding.<verb>``) and
# announced with ``finding.updated``. The resolving audit entry is also what mean-time-to-resolve is
# computed from (``findings_query.finding_stats``), so other features that close findings should call
# ``update_finding_status`` rather than writing ``status`` directly.

CLOSED_STATUSES = frozenset({FindingStatus.RESOLVED.value, FindingStatus.FALSE_POSITIVE.value})
ACTIVE_STATUSES = frozenset({FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value})

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    FindingStatus.OPEN.value: (
        FindingStatus.ACKNOWLEDGED.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.FALSE_POSITIVE.value,
    ),
    FindingStatus.ACKNOWLEDGED.value: (
        FindingStatus.OPEN.value,
        FindingStatus.RESOLVED.value,
        FindingStatus.FALSE_POSITIVE.value,
    ),
    FindingStatus.RESOLVED.value: (FindingStatus.OPEN.value, FindingStatus.FALSE_POSITIVE.value),
    FindingStatus.FALSE_POSITIVE.value: (FindingStatus.OPEN.value,),
}

STATUS_AUDIT_ACTIONS: dict[str, str] = {
    FindingStatus.OPEN.value: "finding.reopened",
    FindingStatus.ACKNOWLEDGED.value: "finding.acknowledged",
    FindingStatus.RESOLVED.value: "finding.resolved",
    FindingStatus.FALSE_POSITIVE.value: "finding.false_positive",
}
NOTE_AUDIT_ACTION = "finding.note_updated"
INCIDENT_AUDIT_ACTION = "finding.incident_linked"
TRIAGE_AUDIT_ACTIONS = (*STATUS_AUDIT_ACTIONS.values(), NOTE_AUDIT_ACTION, INCIDENT_AUDIT_ACTION)

_STATUS_WORDS = {
    FindingStatus.OPEN.value: "reopened",
    FindingStatus.ACKNOWLEDGED.value: "acknowledged",
    FindingStatus.RESOLVED.value: "resolved",
    FindingStatus.FALSE_POSITIVE.value: "marked as a false positive",
}
_NOTE_LIMIT = 4000
_CLOSED_INCIDENT = frozenset({"resolved", "false_positive"})


def allowed_transitions(status: str) -> list[str]:
    return list(ALLOWED_TRANSITIONS.get(status, ()))


def clean_note(note: str | None, limit: int = _NOTE_LIMIT) -> str | None:
    """Redact and bound free text before it is stored or audited. Empty text becomes ``None``."""
    if note is None:
        return None
    from app.engines.redaction import redact_text

    text = redact_text(note.strip()).text.strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def refresh_source_evidence(db: Session, org_id: str, source_id: str | None) -> bool:
    """Recompute a source's finding evidence (count + worst severity, false positives excluded).

    This is the evidence the trust engine uses, so marking a finding false positive lets the source's
    trust recover on its next assessment (or an explicit re-assessment in the Trust Centre). Returns
    True when the stored values changed.
    """
    from app.models import ContextSource
    from app.services.scoping import find_scoped
    from app.services.trust_service_assess import Evidence, finding_evidence

    source = find_scoped(db, ContextSource, source_id, org_id)
    if source is None:
        return False
    db.flush()
    evidence = finding_evidence(db, org_id, [source.id]).get(source.id, Evidence())
    before = (source.finding_count or 0, source.max_finding_severity)
    source.finding_count = evidence.count
    source.max_finding_severity = evidence.max_severity
    changed = before != (evidence.count, evidence.max_severity)
    if changed:
        notify(db, org_id, "trust.updated", id=source.id, kind="source")
    return changed


def update_finding_status(
    db: Session,
    org_id: str,
    finding_id: str,
    *,
    status: str | None,
    note: str | None,
    actor_type: str,
    actor_id: str | None,
) -> SecurityFinding:
    """Triage a finding: change its status (validated transition) and/or its resolution note.

    - resolved / false_positive record the resolver and the note; a false positive needs a reason.
    - reopening clears the resolver and note (the audit trail keeps both).
    - entering or leaving false_positive recomputes the source's finding evidence.
    - a linked incident gets a timeline entry so the investigation shows the triage.
    """
    from app.core.errors import ConflictError, ValidationFailedError
    from app.services.audit import append_audit
    from app.services.incidents import add_activity
    from app.services.scoping import get_scoped

    finding = get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")
    previous = finding.status
    text = clean_note(note)
    if status is None or status == previous:
        if note is None:
            raise ConflictError(f"This finding is already {_STATUS_WORDS.get(previous, previous)}")
        if previous not in CLOSED_STATUSES:
            raise ConflictError(
                "A resolution note can only be recorded on a resolved or false-positive finding"
            )
        if previous == FindingStatus.FALSE_POSITIVE.value and not text:
            raise ValidationFailedError("Explain why this finding is a false positive")
        finding.resolution_note = text
        db.flush()
        append_audit(
            db,
            org_id,
            action=NOTE_AUDIT_ACTION,
            actor_type=actor_type,
            actor_id=actor_id,
            target_type="finding",
            target_id=finding.id,
            details={"status": previous, "note": text},
        )
        notify(db, org_id, "finding.updated", id=finding.id, status=finding.status)
        return finding

    if status not in ALLOWED_TRANSITIONS.get(previous, ()):
        raise ConflictError(
            f"A {previous.replace('_', ' ')} finding cannot be {_STATUS_WORDS.get(status, status)}",
            details={"from": previous, "to": status, "allowed": allowed_transitions(previous)},
        )
    if status == FindingStatus.FALSE_POSITIVE.value and not text:
        raise ValidationFailedError("Explain why this finding is a false positive")

    finding.status = status
    if status in CLOSED_STATUSES:
        finding.resolved_by_user_id = actor_id if actor_type == "user" else None
        finding.resolution_note = text
    elif status == FindingStatus.OPEN.value:
        finding.resolved_by_user_id = None
        finding.resolution_note = None
    db.flush()

    if finding.source_id and FindingStatus.FALSE_POSITIVE.value in (previous, status):
        refresh_source_evidence(db, org_id, finding.source_id)
    if finding.incident_id:
        add_activity(
            db,
            org_id,
            finding.incident_id,
            actor=actor_id or "system",
            kind="finding_status",
            body=f"Finding {_STATUS_WORDS.get(status, status)}: {finding.title}"
            + (f" — {text}" if text else ""),
            details={"finding_id": finding.id, "from": previous, "to": status},
        )
        notify(db, org_id, "incident.updated", id=finding.incident_id)
    append_audit(
        db,
        org_id,
        action=STATUS_AUDIT_ACTIONS[status],
        actor_type=actor_type,
        actor_id=actor_id,
        target_type="finding",
        target_id=finding.id,
        details={
            "from": previous,
            "to": status,
            "note": text,
            "source_id": finding.source_id,
            "incident_id": finding.incident_id,
            "severity": finding.severity,
            "category": finding.category,
        },
    )
    notify(db, org_id, "finding.updated", id=finding.id, status=status)
    return finding


def link_finding_to_incident(
    db: Session,
    org_id: str,
    finding_id: str,
    *,
    incident_id: str | None,
    title: str | None,
    actor_id: str | None,
) -> tuple[Any, bool]:
    """Attach a finding to an existing incident, or open a new incident for it.

    Returns ``(incident, created)``. Re-attaching to the incident it already belongs to is a no-op.
    A finding linked to a different incident, a closed incident, and mixing simulated with real
    records are refused (409) so investigations stay coherent.
    """
    from app.core.errors import ConflictError
    from app.models import Incident
    from app.services.audit import append_audit
    from app.services.incidents import add_activity, create_incident
    from app.services.scoping import find_scoped, get_scoped

    finding = get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")
    actor = actor_id or "system"
    if finding.incident_id:
        current = find_scoped(db, Incident, finding.incident_id, org_id)
        if current is not None and incident_id == current.id:
            return current, False
        if current is not None:
            raise ConflictError(
                f"This finding is already part of incident INC-{current.number}",
                details={"incident_id": current.id},
            )

    if incident_id:
        incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
        if incident.status in _CLOSED_INCIDENT:
            raise ConflictError(
                f"Incident INC-{incident.number} is closed; reopen it before attaching findings"
            )
        if bool(incident.is_simulation) != bool(finding.is_simulation):
            raise ConflictError("Simulated findings and real incidents cannot be mixed (or the reverse)")
        finding.incident_id = incident.id
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = finding.severity
        add_activity(
            db,
            org_id,
            incident.id,
            actor=actor,
            kind="finding_linked",
            body=finding.title,
            details={"finding_id": finding.id},
        )
        notify(db, org_id, "incident.updated", id=incident.id)
        created = False
    else:
        category = finding.category.replace("_", " ")
        incident = create_incident(
            db,
            org_id,
            title=clean_note(title, 400) or finding.title,
            summary=f"Opened by an analyst from a {finding.severity} {category} finding. {finding.explanation}"[
                :4000
            ],
            severity=finding.severity,
            finding_ids=[finding.id],
            primary_agent_id=finding.agent_id,
            primary_session_id=finding.session_id,
            created_by=actor,
            is_simulation=bool(finding.is_simulation),
        )
        created = True
    db.flush()
    append_audit(
        db,
        org_id,
        action=INCIDENT_AUDIT_ACTION,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id,
        target_type="finding",
        target_id=finding.id,
        details={"incident_id": incident.id, "created": created},
    )
    notify(db, org_id, "finding.updated", id=finding.id)
    return incident, created
