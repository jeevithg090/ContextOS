"""Context Explorer read side: what information entered the organisation's agents, and from where.

Context items double as Context Receipts. A receipt is re-verified on every read by recomputing the
canonical fields from the stored row (``ingestion_context.receipt_input``) and checking the HMAC that
was recorded at ingest, so a row altered after signing reports ``signature_valid = False``.

Rules: every query filters on the caller's organisation; an API key bound to one agent sees only
that agent's items (anything else is "not found"). Only persisted, already-redacted values are
returned, and free text is passed through redaction again before it leaves the server. Provenance
edges and "subsequent events" are observed relationships and sequence, never causation.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, and_, case, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import NotFoundError
from app.core.timeutil import utcnow
from app.domain.enums import FindingStatus, ProvenanceNodeType, ProvenanceRelation
from app.engines.provenance import OBSERVED_RELATIONSHIP_NOTE, RECEIPT_PURPOSE, receipt_fields, verify_receipt
from app.engines.redaction import redact_text, redact_value
from app.models import (
    Agent,
    AgentSession,
    ContextItem,
    ContextSource,
    IngestedEvent,
    ProvenanceEdge,
    SecurityFinding,
    Tool,
    ToolInvocation,
    TrustRule,
)
from app.services.ingestion_context import OPERATOR_SOURCE_TYPES, label_for, receipt_input

CTX = ProvenanceNodeType.CONTEXT_ITEM.value
OPEN_STATUSES = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value)
SUBSEQUENT_NOTE = ("Events recorded in the same session after this item, in server order. This is an observed "
                   "sequence only: it does not show that the agent acted because of this content.")
_CATEGORY_EXPLANATIONS = {
    "prompt_injection": "Text addressed to the agent that tries to manipulate it through data it is only meant to read.",
    "instruction_override": "Text that tries to cancel or replace the agent's existing instructions.",
    "credential_access": "Text that steers the agent toward credentials, keys or environment secrets.",
    "exfiltration": "Text that instructs the agent to send data to an outside location.",
    "secret_exposure": "Content that contains a credential or other secret.",
    "untrusted_source": "Instructions in content from a source that is not allowed to direct the agent.",
}
_OPERATOR_NOTE = ("Hits in the operator's own prompts (user or system prompts) are recorded on the item but do "
                  "not raise findings: the operator is allowed to instruct the agent.")


def _clean(text: str | None, limit: int | None = None) -> str | None:
    if text is None:
        return None
    out = redact_text(text).text
    return out if limit is None or len(out) <= limit else out[: limit - 1] + "…"


def _hit_count() -> Any:
    return func.coalesce(ContextItem.detection_summary["hit_count"].as_integer(), 0)


# -- item queries ----------------------------------------------------------------------------------


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


def _conditions(org_id: str, f: ItemFilters, bound_agent_id: str | None, *, skip: frozenset[str] = frozenset()) -> list[Any]:
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
        conds.append(_hit_count() > 0 if f.has_detections else _hit_count() == 0)
    if f.contains_secrets is not None and "contains_secrets" not in skip:
        conds.append(ContextItem.contains_secrets.is_(f.contains_secrets))
    if f.since is not None:
        conds.append(ContextItem.received_at >= f.since)
    if not f.include_simulated and "include_simulated" not in skip:
        conds.append(ContextItem.is_simulation.is_(False))
    return conds


def _source_join(org_id: str) -> Any:
    return and_(ContextSource.id == ContextItem.source_id, ContextSource.organization_id == org_id)


def _item_select(org_id: str) -> Any:
    return (
        select(ContextItem, ContextSource, Agent.name, AgentSession.external_session_id, AgentSession.status)
        .join(ContextSource, _source_join(org_id))
        .outerjoin(Agent, and_(Agent.id == ContextItem.agent_id, Agent.organization_id == org_id))
        .outerjoin(AgentSession, and_(AgentSession.id == ContextItem.session_id, AgentSession.organization_id == org_id))
    )


def _source_ref(source: ContextSource) -> dict[str, Any]:
    return {"id": source.id, "source_type": source.source_type, "identifier": _clean(source.identifier),
            "display_name": _clean(source.display_name), "domain": source.domain, "trust_level": source.trust_level}


def _counts(summary: dict[str, Any] | None) -> dict[str, Any]:
    s = summary or {}
    return {"score": float(s.get("score") or 0.0), "max_severity": s.get("max_severity"),
            "hit_count": int(s.get("hit_count") or 0), "rule_ids": list(s.get("rule_ids") or []),
            "categories": list(s.get("categories") or [])}


def _summary(row: Any, finding_ids: dict[str, set[str]]) -> dict[str, Any]:
    item: ContextItem = row[0]
    return {
        "id": item.id, "source": _source_ref(row[1]), "trust_level": item.trust_level,
        "trust_capabilities": list(item.trust_capabilities or []), "sensitivity": item.sensitivity,
        "contains_secrets": bool(item.contains_secrets), "detection": _counts(item.detection_summary),
        "finding_count": len(finding_ids.get(item.id, ())),
        "agent": {"id": item.agent_id, "name": row[2]},
        "session": {"id": item.session_id, "external_session_id": row[3], "status": row[4]},
        "collected_via": item.collected_via, "collected_at": item.collected_at, "received_at": item.received_at,
        "content_type": item.content_type, "content_length": item.content_length,
        "tool_invocation_id": item.tool_invocation_id, "is_simulation": bool(item.is_simulation),
    }


def _finding_ids_by_item(db: Session, org_id: str, item_ids: list[str]) -> dict[str, set[str]]:
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
    conds = _conditions(org_id, f, bound_agent_id)
    total = db.scalar(select(func.count(ContextItem.id)).select_from(ContextItem)
                      .join(ContextSource, _source_join(org_id)).where(*conds)) or 0
    rows = db.execute(_item_select(org_id).where(*conds)
                      .order_by(ContextItem.received_at.desc(), ContextItem.id.desc()).limit(limit).offset(offset)).all()
    found = _finding_ids_by_item(db, org_id, [r[0].id for r in rows])
    return [_summary(r, found) for r in rows], int(total)


def facets(db: Session, org_id: str, f: ItemFilters, *, bound_agent_id: str | None = None) -> dict[str, Any]:
    def count(skip: frozenset[str] = frozenset(), *extra: Any) -> int:
        conds = _conditions(org_id, f, bound_agent_id, skip=skip)
        return int(db.scalar(select(func.count(ContextItem.id)).select_from(ContextItem)
                             .join(ContextSource, _source_join(org_id)).where(*conds, *extra)) or 0)

    def grouped(column: Any, key: str) -> list[dict[str, Any]]:
        conds = _conditions(org_id, f, bound_agent_id, skip=frozenset({key}))
        rows = db.execute(select(column, func.count(ContextItem.id)).select_from(ContextItem)
                          .join(ContextSource, _source_join(org_id)).where(*conds).group_by(column)).all()
        return sorted(({"value": v, "count": int(c)} for v, c in rows if v), key=lambda r: -r["count"])

    return {
        "total": count(),
        "by_trust_level": grouped(ContextItem.trust_level, "trust_level"),
        "by_sensitivity": grouped(ContextItem.sensitivity, "sensitivity"),
        "by_source_type": grouped(ContextSource.source_type, "source_type"),
        "with_detections": count(frozenset({"has_detections"}), _hit_count() > 0),
        "with_secrets": count(frozenset({"contains_secrets"}), ContextItem.contains_secrets.is_(True)),
        "simulated_total": count(frozenset({"include_simulated"}), ContextItem.is_simulation.is_(True)),
    }


# -- item detail -----------------------------------------------------------------------------------


def _load_item(db: Session, org_id: str, item_id: str, bound_agent_id: str | None) -> Any:
    query = _item_select(org_id).where(ContextItem.organization_id == org_id, ContextItem.id == item_id)
    if bound_agent_id:
        query = query.where(ContextItem.agent_id == bound_agent_id)
    row = db.execute(query).first()
    if row is None:
        raise NotFoundError(f"Context item '{item_id}' not found")
    return row


def _finding_ref(f: SecurityFinding) -> dict[str, Any]:
    return {"id": f.id, "title": _clean(f.title, 400), "category": f.category, "rule_id": f.rule_id,
            "severity": f.severity, "status": f.status, "confidence": f.confidence, "last_seen_at": f.last_seen_at,
            "incident_id": f.incident_id}


def _findings(db: Session, org_id: str, ids: set[str]) -> list[SecurityFinding]:
    if not ids:
        return []
    return list(db.scalars(select(SecurityFinding).where(SecurityFinding.organization_id == org_id,
                                                          SecurityFinding.id.in_(ids))
                           .order_by(SecurityFinding.last_seen_at.desc())))


def _excerpt_for(finding: SecurityFinding, item_id: str) -> str | None:
    for ev in finding.evidence or []:
        if isinstance(ev, dict) and ev.get("type") == "context_item" and ev.get("id") == item_id and ev.get("excerpt"):
            return _clean(str(ev["excerpt"]), 400)
    return None


def _hits(item: ContextItem, findings: list[SecurityFinding]) -> list[dict[str, Any]]:
    by_rule = {f.rule_id: f for f in reversed(findings)}  # newest wins
    out = []
    for hit in (item.detection_summary or {}).get("hits") or []:
        if not isinstance(hit, dict) or not hit.get("rule_id"):
            continue
        finding = by_rule.get(hit["rule_id"])
        category = str(hit.get("category") or "")
        explanation = _clean(finding.explanation) if finding else _CATEGORY_EXPLANATIONS.get(
            category, "Content matched a ContextOS detection rule.")
        out.append({
            "rule_id": hit["rule_id"], "category": category, "title": _clean(str(hit.get("title") or hit["rule_id"])),
            "severity": hit.get("severity") or "info", "confidence": float(hit.get("confidence") or 0.0),
            "technique": hit.get("technique") or "plain", "explanation": explanation,
            "explanation_source": "finding" if finding else "category",
            "excerpt": _excerpt_for(finding, item.id) if finding else None, "finding_id": finding.id if finding else None,
        })
    return out


def _invocation_ref(db: Session, org_id: str, invocation_id: str | None) -> dict[str, Any] | None:
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


def _edges(db: Session, org_id: str, item_id: str) -> list[dict[str, Any]]:
    rows = db.scalars(select(ProvenanceEdge).where(
        ProvenanceEdge.organization_id == org_id,
        or_(and_(ProvenanceEdge.src_type == CTX, ProvenanceEdge.src_id == item_id),
            and_(ProvenanceEdge.dst_type == CTX, ProvenanceEdge.dst_id == item_id)),
    ).order_by(ProvenanceEdge.observed_at, ProvenanceEdge.id))
    return [{"id": e.id, "relation": e.relation, "src": {"type": e.src_type, "id": e.src_id},
             "dst": {"type": e.dst_type, "id": e.dst_id}, "confidence": e.confidence, "observed_at": e.observed_at}
            for e in rows]


def get_item(db: Session, org_id: str, item_id: str, *, bound_agent_id: str | None = None) -> dict[str, Any]:
    row = _load_item(db, org_id, item_id, bound_agent_id)
    item: ContextItem = row[0]
    source: ContextSource = row[1]
    linked = _finding_ids_by_item(db, org_id, [item.id])
    findings = _findings(db, org_id, linked.get(item.id, set()))
    preview = _clean(item.redacted_preview)
    secret_types = Counter(str(fp.get("type") or "secret") for fp in item.secret_fingerprints or [] if isinstance(fp, dict))
    summary = item.detection_summary or {}
    hits = _hits(item, findings)
    origin = None
    if item.origin_agent_id:
        name = db.scalar(select(Agent.name).where(Agent.organization_id == org_id, Agent.id == item.origin_agent_id))
        origin = {"id": item.origin_agent_id, "name": name}
    metadata, _ = redact_value(item.item_metadata or {})
    return {
        **_summary(row, linked),
        "event_id": item.event_id, "content_hash": item.content_hash, "redacted_preview": preview,
        "preview_stored": preview is not None,
        "preview_truncated": bool(preview and preview.endswith("…") and len(preview) >= get_settings().preview_chars),
        "secret_fingerprint_count": len(item.secret_fingerprints or []),
        "secret_types": [{"type": t, "count": c} for t, c in sorted(secret_types.items())],
        "detection": {**_counts(summary), "classifier_score": summary.get("classifier_score"), "hits": hits,
                      "findings_suppressed_reason": _OPERATOR_NOTE if hits and source.source_type in OPERATOR_SOURCE_TYPES
                      else None},
        "findings": [_finding_ref(f) for f in findings],
        "tool_invocation": _invocation_ref(db, org_id, item.tool_invocation_id),
        "origin_agent": origin, "origin_session_id": item.origin_session_id,
        "item_metadata": metadata if isinstance(metadata, dict) else {},
        "provenance": _edges(db, org_id, item.id), "provenance_note": OBSERVED_RELATIONSHIP_NOTE,
        "has_receipt_signature": bool(item.receipt_signature),
    }


# -- receipts --------------------------------------------------------------------------------------


_EVENT_LABELS = {
    "tool.requested": "Requested tool {tool}", "tool.completed": "Tool {tool} returned a result",
    "tool.failed": "Tool {tool} failed", "context.ingested": "Context from {kind} {source}",
    "agent.delegated": "Delegated work to agent {child}", "agent.message": "Message from agent {sender}",
    "mcp.server_connected": "MCP server {source} connected", "prompt.submitted": "User prompt submitted",
    "session.started": "Session started", "session.ended": "Session ended",
}


def _event_summary(event: IngestedEvent) -> tuple[str, str | None]:
    """One-line description of a recorded event, built from its redacted payload."""
    p = event.payload_redacted if isinstance(event.payload_redacted, dict) else {}

    def part(*path: str) -> str | None:
        value: Any = p
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        return _clean(str(value), 120) if value not in (None, "") else None

    tool = part("tool", "name")
    template = _EVENT_LABELS.get(event.event_type)
    if template is None:
        return event.event_type.replace(".", " ").replace("_", " ").capitalize(), tool
    text = template.format(
        tool=tool or "unknown", kind=label_for(part("source", "type") or "other"), source=part("source", "identifier")
        or "unknown", child=part("delegation", "child_agent", "name") or "unknown",
        sender=part("message", "from_agent") or "unknown")
    return text, tool


def _subsequent(db: Session, org_id: str, item: ContextItem, limit: int) -> tuple[list[dict[str, Any]], bool]:
    seq = db.scalar(select(IngestedEvent.sequence).where(IngestedEvent.organization_id == org_id,
                                                         IngestedEvent.id == item.event_id))
    if seq is None:
        return [], False
    events = list(db.scalars(select(IngestedEvent).where(
        IngestedEvent.organization_id == org_id, IngestedEvent.session_id == item.session_id,
        IngestedEvent.sequence > seq).order_by(IngestedEvent.sequence).limit(limit + 1)))
    out = []
    for ev in events[:limit]:
        refs = ev.refs or {}
        summary, tool = _event_summary(ev)
        out.append({
            "id": ev.id, "sequence": ev.sequence, "event_type": ev.event_type, "summary": summary,
            "occurred_at": ev.occurred_at, "received_at": ev.received_at, "processing_status": ev.processing_status,
            "tool_name": tool, "decision": refs.get("decision"), "enforcement": refs.get("enforcement"),
            "tool_invocation_id": refs.get("tool_invocation_id"), "policy_decision_id": refs.get("policy_decision_id"),
            "context_item_id": refs.get("context_item_id"), "finding_ids": list(refs.get("finding_ids") or []),
        })
    return out, len(events) > limit


def _verification(status: str) -> dict[str, Any]:
    text = {
        "valid": "The signature matches the receipt fields recomputed from the stored record just now, so the "
                 "record has not been altered since ContextOS signed it at ingest.",
        "invalid": "The signature does NOT match the receipt fields recomputed from the stored record. The record "
                   "was changed after it was signed (for example its hash, source or classification), or this "
                   "server's signing secret was rotated. Treat these fields as unverified.",
        "missing": "No signature was recorded for this item, so its fields cannot be verified.",
    }[status]
    return {"status": status, "algorithm": "HMAC-SHA256", "purpose": RECEIPT_PURPOSE, "explanation": text}


def _statement(item: ContextItem, source: ContextSource, agent: str | None, session: str | None,
               status: str) -> dict[str, Any]:
    label = label_for(source.source_type)
    ident = _clean(source.identifier, 300)
    who = f"session {_clean(session or item.session_id, 200)} of agent '{_clean(agent or item.agent_id, 200)}'"
    received = item.received_at.isoformat().replace("+00:00", "Z")
    rules = sorted((item.detection_summary or {}).get("rule_ids") or [])
    hits = f"{len(rules)} detection rule(s) matched ({', '.join(rules)})" if rules else "no detection rule matched"
    summary = (f"ContextOS recorded content with SHA-256 {item.content_hash or 'unknown'} "
               f"({item.content_length} characters) from {label} {ident} for {who}, received at {received} "
               f"(server time) via {item.collected_via}.")
    if status != "valid":
        summary = f"UNVERIFIED — the stored record does not carry a valid signature. As stored: {summary}"
    if status == "valid":
        proves = [
            "These receipt fields are exactly what ContextOS signed when it recorded the item; the signature still "
            "verifies with this server's key.",
            f"ContextOS received content whose SHA-256 is {item.content_hash} and whose length is "
            f"{item.content_length} characters at {received} by the server clock. Anyone holding the original "
            "content can hash it and compare.",
            f"The content was attributed to {label} {ident} and to {who}, as observed via {item.collected_via}.",
            f"At ingest ContextOS classified it {item.trust_level} and {hits}.",
        ]
        if item.contains_secrets:
            proves.append("Secrets were detected and redacted before storage; only keyed fingerprints were kept.")
    else:
        proves = ["Nothing beyond the existence of this record: its fields cannot be verified against a valid "
                  "signature, so do not rely on them as an attestation."]
    now_trust = f" (the source is now classified {source.trust_level})" if source.trust_level != item.trust_level else ""
    does_not_prove = [
        "That the model read, relied on or acted on this content. Later events in the session are an observed "
        "sequence, not evidence of causation.",
        f"That the content is accurate or safe. Trust and detection are ContextOS's classification at ingest "
        f"time{now_trust}.",
        "Who published the content. The source identifier is what the integration reported, or what ContextOS "
        "derived from the tool call that returned it; ContextOS did not fetch or authenticate the source itself.",
        "When the agent actually collected it. The client-reported collection time is untrusted; only the server "
        "receive time is authoritative.",
        "Anything to a party without access to this server: the signature is a keyed HMAC under this deployment's "
        "secret, so only this server can verify it, and rotating the secret invalidates existing receipts.",
        "What the content said. ContextOS keeps only the hash, length and a redacted preview, so the original "
        "cannot be recovered from the receipt.",
    ]
    return {"summary": summary, "proves": proves, "does_not_prove": does_not_prove}


def get_receipt(db: Session, org_id: str, item_id: str, *, bound_agent_id: str | None = None,
                events_limit: int = 10) -> dict[str, Any]:
    row = _load_item(db, org_id, item_id, bound_agent_id)
    item: ContextItem = row[0]
    source: ContextSource = row[1]
    fields = receipt_fields(receipt_input(item, source))
    signature = item.receipt_signature
    valid = verify_receipt(fields, signature)
    status = "missing" if not signature else ("valid" if valid else "invalid")
    linked = _finding_ids_by_item(db, org_id, [item.id])
    events, more = _subsequent(db, org_id, item, events_limit)
    skew = (item.received_at - item.collected_at).total_seconds()
    return {
        "receipt": fields, "signature": signature, "signature_valid": valid, "verification": _verification(status),
        "timestamps": {
            "collected_at": item.collected_at, "received_at": item.received_at, "skew_seconds": round(skew, 3),
            "explanation": "collected_at is reported by the integration and is not trusted; received_at is "
                           "ContextOS's own clock when the event arrived and is the authoritative time.",
        },
        "statement": _statement(item, source, row[2], row[3], status),
        "related": {
            "source": _source_ref(source), "agent": {"id": item.agent_id, "name": row[2]},
            "session": {"id": item.session_id, "external_session_id": row[3], "status": row[4]},
            "tool_invocation": _invocation_ref(db, org_id, item.tool_invocation_id),
            "findings": [_finding_ref(f) for f in _findings(db, org_id, linked.get(item.id, set()))],
            "subsequent_events": events, "more_subsequent_events": more, "subsequent_events_note": SUBSEQUENT_NOTE,
        },
        "is_simulation": bool(item.is_simulation), "generated_at": utcnow(),
    }


# -- sources ---------------------------------------------------------------------------------------


def _source_stats(org_id: str, include_simulated: bool, bound_agent_id: str | None) -> tuple[Any, Any]:
    item_conds: list[Any] = [ContextItem.organization_id == org_id]
    finding_conds: list[Any] = [SecurityFinding.organization_id == org_id, SecurityFinding.source_id.is_not(None)]
    if not include_simulated:
        item_conds.append(ContextItem.is_simulation.is_(False))
        finding_conds.append(SecurityFinding.is_simulation.is_(False))
    if bound_agent_id:
        item_conds.append(ContextItem.agent_id == bound_agent_id)
        finding_conds.append(SecurityFinding.agent_id == bound_agent_id)
    items = select(
        ContextItem.source_id.label("sid"), func.count(ContextItem.id).label("n_items"),
        func.count(distinct(ContextItem.agent_id)).label("n_agents"),
        func.count(distinct(ContextItem.session_id)).label("n_sessions"),
        func.sum(case((_hit_count() > 0, 1), else_=0)).label("n_detected"),
    ).where(*item_conds).group_by(ContextItem.source_id).subquery()
    findings = select(
        SecurityFinding.source_id.label("sid"), func.count(SecurityFinding.id).label("n_findings"),
        func.sum(case((SecurityFinding.status.in_(OPEN_STATUSES), 1), else_=0)).label("n_open"),
    ).where(*finding_conds).group_by(SecurityFinding.source_id).subquery()
    return items, findings


def _source_select(org_id: str, include_simulated: bool, bound_agent_id: str | None, *,
                   hide_simulation_only: bool = True) -> tuple[Select[Any], dict[str, Any], Any]:
    items, findings = _source_stats(org_id, include_simulated, bound_agent_id)
    any_items = select(ContextItem.source_id).where(ContextItem.organization_id == org_id)
    if bound_agent_id:
        any_items = any_items.where(ContextItem.agent_id == bound_agent_id)
    item_count, finding_count = func.coalesce(items.c.n_items, 0), func.coalesce(findings.c.n_findings, 0)
    query = (select(ContextSource, item_count, func.coalesce(items.c.n_agents, 0), func.coalesce(items.c.n_sessions, 0),
                    func.coalesce(items.c.n_detected, 0), finding_count, func.coalesce(findings.c.n_open, 0))
             .outerjoin(items, items.c.sid == ContextSource.id)
             .outerjoin(findings, findings.c.sid == ContextSource.id)
             .where(ContextSource.organization_id == org_id))
    if bound_agent_id:
        query = query.where(ContextSource.id.in_(any_items))
    elif hide_simulation_only and not include_simulated:  # sources observed only by simulations
        query = query.where(or_(item_count > 0, ContextSource.id.not_in(any_items)))
    sorts = {"last_seen": ContextSource.last_seen_at, "items": item_count, "findings": finding_count}
    return query, sorts, finding_count


def _source_summary(row: Any) -> dict[str, Any]:
    s: ContextSource = row[0]
    return {
        **_source_ref(s), "owner": _clean(s.owner), "trust_capabilities": list(s.trust_capabilities or []),
        "manually_classified": bool(s.manually_classified), "first_seen_at": s.first_seen_at,
        "last_seen_at": s.last_seen_at, "observation_count": s.observation_count or 0, "item_count": int(row[1]),
        "agent_count": int(row[2]), "session_count": int(row[3]), "items_with_detections": int(row[4]),
        "finding_count": int(row[5]), "open_finding_count": int(row[6]), "max_finding_severity": s.max_finding_severity,
    }


def list_sources(db: Session, org_id: str, *, q: str | None = None, source_type: str | None = None,
                 trust_level: str | None = None, has_findings: bool | None = None, include_simulated: bool = False,
                 sort: str = "last_seen", bound_agent_id: str | None = None, limit: int = 50,
                 offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    query, sorts, finding_count = _source_select(org_id, include_simulated, bound_agent_id)
    if q and q.strip():
        term = q.strip()
        query = query.where(or_(ContextSource.identifier.icontains(term, autoescape=True),
                                ContextSource.display_name.icontains(term, autoescape=True),
                                ContextSource.domain.icontains(term, autoescape=True)))
    if source_type:
        query = query.where(ContextSource.source_type == source_type)
    if trust_level:
        query = query.where(ContextSource.trust_level == trust_level)
    if has_findings is not None:
        query = query.where(finding_count > 0 if has_findings else finding_count == 0)
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    order = sorts.get(sort, ContextSource.last_seen_at)
    rows = db.execute(query.order_by(order.desc(), ContextSource.last_seen_at.desc(), ContextSource.id)
                      .limit(limit).offset(offset)).all()
    return [_source_summary(r) for r in rows], int(total)


def get_source(db: Session, org_id: str, source_id: str, *, include_simulated: bool = False,
               bound_agent_id: str | None = None) -> dict[str, Any]:
    # A source seen only by simulations is still reachable by id (e.g. from a simulated item).
    query, _sorts, _count = _source_select(org_id, include_simulated, bound_agent_id, hide_simulation_only=False)
    row = db.execute(query.where(ContextSource.id == source_id)).first()
    if row is None:
        raise NotFoundError(f"Context source '{source_id}' not found")
    source: ContextSource = row[0]
    rule = db.scalar(select(TrustRule).where(TrustRule.organization_id == org_id, TrustRule.id == source.trust_rule_id)) \
        if source.trust_rule_id else None
    items, _ = list_items(db, org_id, ItemFilters(source_id=source.id, include_simulated=include_simulated),
                          bound_agent_id=bound_agent_id, limit=20)
    finding_q = select(SecurityFinding).where(SecurityFinding.organization_id == org_id,
                                              SecurityFinding.source_id == source.id)
    if not include_simulated:
        finding_q = finding_q.where(SecurityFinding.is_simulation.is_(False))
    if bound_agent_id:
        finding_q = finding_q.where(SecurityFinding.agent_id == bound_agent_id)
    findings = db.scalars(finding_q.order_by(SecurityFinding.last_seen_at.desc()).limit(25))
    consumer_conds = _conditions(org_id, ItemFilters(include_simulated=include_simulated), bound_agent_id)
    consumers = db.execute(
        select(ContextItem.agent_id, Agent.name, func.count(ContextItem.id), func.count(distinct(ContextItem.session_id)),
               func.max(ContextItem.received_at))
        .outerjoin(Agent, and_(Agent.id == ContextItem.agent_id, Agent.organization_id == org_id))
        .where(*consumer_conds, ContextItem.source_id == source.id)
        .group_by(ContextItem.agent_id, Agent.name).order_by(func.max(ContextItem.received_at).desc()).limit(20)).all()
    metadata, _ = redact_value(source.source_metadata or {})
    return {
        **_source_summary(row),
        "trust_reasons": [r for r in (_clean(str(x), 1000) for x in source.trust_reasons or []) if r],
        "trust_rule": {"id": rule.id, "name": rule.name, "pattern": rule.pattern, "trust_level": rule.trust_level,
                       "enabled": rule.enabled} if rule else None,
        "source_metadata": metadata if isinstance(metadata, dict) else {},
        "recent_items": items,
        "findings": [_finding_ref(f) for f in findings],
        "consumers": [{"agent": {"id": a, "name": n}, "item_count": int(c), "session_count": int(s), "last_received_at": t}
                      for a, n, c, s, t in consumers],
    }
