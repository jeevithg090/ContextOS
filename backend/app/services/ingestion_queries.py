"""Read side of ingestion: the event log, stateless content scanning and approval polling.

Every query is scoped to the caller's organisation; an API key bound to one agent only sees that
agent's events and approvals (others are reported as not found).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import NotFoundError
from app.core.security import sha256_hex
from app.engines.detection import analyze_content
from app.engines.redaction import classify_sensitivity, redact_text
from app.models import Agent, AgentSession, Approval, IngestedEvent
from app.services.approvals import get_approval_status
from app.services.ingestion_state import preview_of, scrub_fragments

_EVENT_COLUMNS = (IngestedEvent, Agent.name.label("agent_name"), AgentSession.external_session_id)


def _event_query(org_id: str, bound_agent_id: str | None) -> Select[Any]:
    query = (
        select(*_EVENT_COLUMNS)
        .outerjoin(Agent, (Agent.id == IngestedEvent.agent_id) & (Agent.organization_id == org_id))
        .outerjoin(AgentSession, (AgentSession.id == IngestedEvent.session_id) & (AgentSession.organization_id == org_id))
        .where(IngestedEvent.organization_id == org_id)
    )
    if bound_agent_id:
        query = query.where(IngestedEvent.agent_id == bound_agent_id)
    return query


def _event_dict(row: Any, *, detail: bool) -> dict[str, Any]:
    event: IngestedEvent = row[0]
    out: dict[str, Any] = {
        "id": event.id, "client_event_id": event.client_event_id, "event_type": event.event_type,
        "schema_version": event.schema_version, "sequence": event.sequence, "agent_id": event.agent_id,
        "agent_name": row[1], "session_id": event.session_id, "external_session_id": row[2],
        "correlation_id": event.correlation_id, "integration": event.integration, "occurred_at": event.occurred_at,
        "received_at": event.received_at, "refs": event.refs or {}, "processing_status": event.processing_status,
        "processing_error": event.processing_error, "api_key_id": event.api_key_id,
        "is_simulation": bool(event.is_simulation),
    }
    if detail:
        out["payload_redacted"] = event.payload_redacted or {}
        out["payload_hash"] = event.payload_hash
    return out


def list_events(
    db: Session, org_id: str, *, bound_agent_id: str | None = None, agent_id: str | None = None,
    session_id: str | None = None, event_type: str | None = None, since: datetime | None = None,
    processing_status: str | None = None, is_simulation: bool | None = None, limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query = _event_query(org_id, bound_agent_id)
    if agent_id:
        query = query.where(IngestedEvent.agent_id == agent_id)
    if session_id:
        query = query.where(IngestedEvent.session_id == session_id)
    if event_type:
        query = query.where(IngestedEvent.event_type == event_type)
    if since is not None:
        query = query.where(IngestedEvent.received_at >= since)
    if processing_status:
        query = query.where(IngestedEvent.processing_status == processing_status)
    if is_simulation is not None:
        query = query.where(IngestedEvent.is_simulation.is_(is_simulation))
    query = query.order_by(IngestedEvent.sequence.desc())
    total = paginate_count(db, query)
    rows = db.execute(query.limit(limit).offset(offset)).all()
    return [_event_dict(r, detail=False) for r in rows], total


def paginate_count(db: Session, query: Select[Any]) -> int:
    return int(db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0)


def get_event(db: Session, org_id: str, event_id: str, *, bound_agent_id: str | None = None) -> dict[str, Any]:
    row = db.execute(_event_query(org_id, bound_agent_id).where(IngestedEvent.id == event_id)).first()
    if row is None:
        raise NotFoundError(f"Event '{event_id}' not found")
    return _event_dict(row, detail=True)


def poll_approval(db: Session, org_id: str, approval_id: str, *, bound_agent_id: str | None = None) -> Approval:
    approval = get_approval_status(db, org_id, approval_id)
    if bound_agent_id and approval.agent_id != bound_agent_id:
        raise NotFoundError(f"Approval '{approval_id}' not found")
    return approval


def scan_content(content: str, *, source_type: str | None, content_type: str | None) -> dict[str, Any]:
    """Detection + secret scan of ad-hoc content. Persists nothing; returns only redacted text."""
    redaction = redact_text(content)
    raw_secrets = [content[m.start : m.end] for m in redaction.matches if m.end - m.start >= 6]
    result = analyze_content(content, source_type=source_type, content_type=content_type)
    summary = result.to_summary()
    summary["hits"] = [
        {"rule_id": h.rule_id, "category": h.category, "title": h.title, "severity": h.severity,
         "confidence": h.confidence, "explanation": h.explanation, "technique": h.technique,
         "excerpt": scrub_fragments(h.excerpt, raw_secrets)}
        for h in result.hits
    ]
    secrets: dict[tuple[str, str], float] = {}
    for m in redaction.matches:
        key = (m.secret_type, m.fingerprint)
        secrets[key] = max(secrets.get(key, 0.0), m.confidence)
    return {
        "detection": summary,
        "secrets": [{"type": t, "confidence": c} for (t, _fp), c in secrets.items()],
        "sensitivity": str(classify_sensitivity(content, redaction.matches)),
        "content_length": len(content),
        "content_sha256": sha256_hex(content),
        "redacted_preview": preview_of(redaction.text, get_settings().preview_chars),
    }
