"""Shared query building blocks for the Context Explorer (items, receipts, sources).

Every helper filters on the caller's organisation, and on the bound agent for agent-bound API keys.
Free text read from rows is passed through redaction again before it leaves the server.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.domain.enums import FindingStatus, ProvenanceNodeType, ProvenanceRelation
from app.engines.redaction import redact_text
from app.models import (
    Agent,
    AgentSession,
    ContextItem,
    ContextSource,
    ProvenanceEdge,
    SecurityFinding,
    Tool,
    ToolInvocation,
)

CTX = ProvenanceNodeType.CONTEXT_ITEM.value
OPEN_STATUSES = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value)


def clean(text: str | None, limit: int | None = None) -> str | None:
    """Re-redact stored free text (defence in depth) and optionally truncate it."""
    if text is None:
        return None
    out = redact_text(text).text
    return out if limit is None or len(out) <= limit else out[: limit - 1] + "…"


def hit_count() -> Any:
    """SQL expression: number of detection hits recorded on a context item."""
    return func.coalesce(ContextItem.detection_summary["hit_count"].as_integer(), 0)


@dataclass(frozen=True)
class ItemFilters:
    q: str | None = None
    source_id: str | None = None
    source_type: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    trust_levels: tuple[str, ...] = ()
    sensitivities: tuple[str, ...] = ()
    has_detections: bool | None = None
    contains_secrets: bool | None = None
    since: datetime | None = None
    include_simulated: bool = False


def conditions(org_id: str, f: ItemFilters, bound_agent_id: str | None, *,
               skip: frozenset[str] = frozenset()) -> list[Any]:
    """WHERE clauses over ContextItem / ContextSource. ``skip`` drops one facet's own filter."""
    conds: list[Any] = [ContextItem.organization_id == org_id]
    if bound_agent_id:
        conds.append(ContextItem.agent_id == bound_agent_id)
    if f.q and f.q.strip():
        q = f.q.strip()
        conds.append(or_(
            ContextItem.redacted_preview.icontains(q, autoescape=True),
            ContextSource.identifier.icontains(q, autoescape=True),
            ContextSource.display_name.icontains(q, autoescape=True),
            ContextItem.content_hash == q.lower(),
            ContextItem.id == q,
        ))
    for value, column in ((f.source_id, ContextItem.source_id), (f.agent_id, ContextItem.agent_id),
                          (f.session_id, ContextItem.session_id)):
        if value:
            conds.append(column == value)
    if f.source_type and "source_type" not in skip:
        conds.append(ContextSource.source_type == f.source_type)
    if f.trust_levels and "trust_level" not in skip:
        conds.append(ContextItem.trust_level.in_(f.trust_levels))
    if f.sensitivities and "sensitivity" not in skip:
        conds.append(ContextItem.sensitivity.in_(f.sensitivities))
    if f.has_detections is not None and "has_detections" not in skip:
        conds.append(hit_count() > 0 if f.has_detections else hit_count() == 0)
    if f.contains_secrets is not None and "contains_secrets" not in skip:
        conds.append(ContextItem.contains_secrets.is_(f.contains_secrets))
    if f.since is not None:
        conds.append(ContextItem.received_at >= f.since)
    if not f.include_simulated and "include_simulated" not in skip:
        conds.append(ContextItem.is_simulation.is_(False))
    return conds


def source_join(org_id: str) -> Any:
    return and_(ContextSource.id == ContextItem.source_id, ContextSource.organization_id == org_id)


def item_select(org_id: str) -> Any:
    """Rows of (ContextItem, ContextSource, agent name, external session id, session status)."""
    return (
        select(ContextItem, ContextSource, Agent.name, AgentSession.external_session_id, AgentSession.status)
        .join(ContextSource, source_join(org_id))
        .outerjoin(Agent, and_(Agent.id == ContextItem.agent_id, Agent.organization_id == org_id))
        .outerjoin(AgentSession, and_(AgentSession.id == ContextItem.session_id, AgentSession.organization_id == org_id))
    )


def source_ref(source: ContextSource) -> dict[str, Any]:
    return {"id": source.id, "source_type": source.source_type, "identifier": clean(source.identifier),
            "display_name": clean(source.display_name), "domain": source.domain, "trust_level": source.trust_level}


def detection_counts(summary: dict[str, Any] | None) -> dict[str, Any]:
    s = summary or {}
    return {"score": float(s.get("score") or 0.0), "max_severity": s.get("max_severity"),
            "hit_count": int(s.get("hit_count") or 0), "rule_ids": list(s.get("rule_ids") or []),
            "categories": list(s.get("categories") or [])}


def item_summary(row: Any, finding_ids: dict[str, set[str]]) -> dict[str, Any]:
    item: ContextItem = row[0]
    return {
        "id": item.id, "source": source_ref(row[1]), "trust_level": item.trust_level,
        "trust_capabilities": list(item.trust_capabilities or []), "sensitivity": item.sensitivity,
        "contains_secrets": bool(item.contains_secrets), "detection": detection_counts(item.detection_summary),
        "finding_count": len(finding_ids.get(item.id, ())),
        "agent": {"id": item.agent_id, "name": row[2]},
        "session": {"id": item.session_id, "external_session_id": row[3], "status": row[4]},
        "collected_via": item.collected_via, "collected_at": item.collected_at, "received_at": item.received_at,
        "content_type": item.content_type, "content_length": item.content_length,
        "tool_invocation_id": item.tool_invocation_id, "is_simulation": bool(item.is_simulation),
    }


def finding_ids_by_item(db: Session, org_id: str, item_ids: list[str]) -> dict[str, set[str]]:
    """Findings linked to each item: by ``context_item_id`` or by an item→finding edge (deduplicated
    findings keep the first item as ``context_item_id`` but get an edge from every later item)."""
    out: dict[str, set[str]] = defaultdict(set)
    if not item_ids:
        return out
    for item_id, fid in db.execute(select(SecurityFinding.context_item_id, SecurityFinding.id).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.context_item_id.in_(item_ids))):
        out[str(item_id)].add(fid)
    for item_id, fid in db.execute(select(ProvenanceEdge.src_id, ProvenanceEdge.dst_id).where(
            ProvenanceEdge.organization_id == org_id, ProvenanceEdge.src_type == CTX,
            ProvenanceEdge.relation == ProvenanceRelation.ITEM_TRIGGERED_FINDING.value,
            ProvenanceEdge.src_id.in_(item_ids))):
        out[item_id].add(fid)
    return out


def list_items(db: Session, org_id: str, f: ItemFilters, *, bound_agent_id: str | None = None,
               limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Item summaries matching ``f``, newest first by server receive time."""
    conds = conditions(org_id, f, bound_agent_id)
    total = db.scalar(select(func.count(ContextItem.id)).select_from(ContextItem)
                      .join(ContextSource, source_join(org_id)).where(*conds)) or 0
    rows = db.execute(item_select(org_id).where(*conds)
                      .order_by(ContextItem.received_at.desc(), ContextItem.id.desc()).limit(limit).offset(offset)).all()
    found = finding_ids_by_item(db, org_id, [r[0].id for r in rows])
    return [item_summary(r, found) for r in rows], int(total)


def load_item(db: Session, org_id: str, item_id: str, bound_agent_id: str | None) -> Any:
    query = item_select(org_id).where(ContextItem.organization_id == org_id, ContextItem.id == item_id)
    if bound_agent_id:
        query = query.where(ContextItem.agent_id == bound_agent_id)
    row = db.execute(query).first()
    if row is None:
        raise NotFoundError(f"Context item '{item_id}' not found")
    return row


def finding_ref(f: SecurityFinding) -> dict[str, Any]:
    return {"id": f.id, "title": clean(f.title, 400), "category": f.category, "rule_id": f.rule_id,
            "severity": f.severity, "status": f.status, "confidence": f.confidence, "last_seen_at": f.last_seen_at,
            "incident_id": f.incident_id}


def load_findings(db: Session, org_id: str, ids: set[str]) -> list[SecurityFinding]:
    if not ids:
        return []
    return list(db.scalars(select(SecurityFinding).where(SecurityFinding.organization_id == org_id,
                                                          SecurityFinding.id.in_(ids))
                           .order_by(SecurityFinding.last_seen_at.desc())))


def invocation_ref(db: Session, org_id: str, invocation_id: str | None) -> dict[str, Any] | None:
    if not invocation_id:
        return None
    row = db.execute(select(ToolInvocation, Tool).outerjoin(
        Tool, and_(Tool.id == ToolInvocation.tool_id, Tool.organization_id == org_id)).where(
        ToolInvocation.organization_id == org_id, ToolInvocation.id == invocation_id)).first()
    if row is None:
        return None
    inv, tool = row
    return {"id": inv.id, "tool_name": tool.name if tool else None, "tool_provider": tool.provider if tool else None,
            "tool_category": tool.category if tool else None, "status": inv.status, "decision": inv.decision,
            "enforcement": inv.enforcement, "requested_at": inv.requested_at, "completed_at": inv.completed_at}
