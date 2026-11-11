"""Context Explorer read side: what information entered the organisation's agents, and from where.

This module is the service facade the routes use. Item detail and facets live here; the shared query
building blocks are in ``context_service_common``, receipts in ``context_service_receipts`` and
sources in ``context_service_sources``.

Context items double as Context Receipts. A receipt is re-verified on every read by recomputing the
canonical fields from the stored row and checking the HMAC recorded at ingest, so a row altered after
signing reports ``signature_valid = False``.

Rules: every query filters on the caller's organisation; an API key bound to one agent sees only
that agent's items (anything else is "not found"). Only persisted, already-redacted values are
returned, and free text is passed through redaction again before it leaves the server. Provenance
edges and "subsequent events" are observed relationships and sequence, never causation.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.engines.provenance import OBSERVED_RELATIONSHIP_NOTE
from app.engines.redaction import redact_value
from app.models import Agent, ContextItem, ContextSource, ProvenanceEdge, SecurityFinding
from app.services.context_service_common import (
    CTX,
    ItemFilters,
    clean,
    conditions,
    detection_counts,
    finding_ids_by_item,
    finding_ref,
    hit_count,
    invocation_ref,
    item_summary,
    list_items,
    load_findings,
    load_item,
    source_join,
)
from app.services.context_service_receipts import get_receipt
from app.services.context_service_sources import get_source, list_sources
from app.services.ingestion_context import OPERATOR_SOURCE_TYPES

__all__ = ["ItemFilters", "facets", "get_item", "get_receipt", "get_source", "list_items", "list_sources"]

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


def facets(db: Session, org_id: str, f: ItemFilters, *, bound_agent_id: str | None = None) -> dict[str, Any]:
    """Counts by trust, sensitivity and source type. Each facet ignores its own filter so the UI can
    show the full distribution while that filter narrows the list."""

    def count(skip: frozenset[str] = frozenset(), *extra: Any) -> int:
        conds = conditions(org_id, f, bound_agent_id, skip=skip)
        return int(db.scalar(select(func.count(ContextItem.id)).select_from(ContextItem)
                             .join(ContextSource, source_join(org_id)).where(*conds, *extra)) or 0)

    def grouped(column: Any, key: str) -> list[dict[str, Any]]:
        conds = conditions(org_id, f, bound_agent_id, skip=frozenset({key}))
        rows = db.execute(select(column, func.count(ContextItem.id)).select_from(ContextItem)
                          .join(ContextSource, source_join(org_id)).where(*conds).group_by(column)).all()
        return sorted(({"value": v, "count": int(c)} for v, c in rows if v), key=lambda r: -r["count"])

    return {
        "total": count(),
        "by_trust_level": grouped(ContextItem.trust_level, "trust_level"),
        "by_sensitivity": grouped(ContextItem.sensitivity, "sensitivity"),
        "by_source_type": grouped(ContextSource.source_type, "source_type"),
        "with_detections": count(frozenset({"has_detections"}), hit_count() > 0),
        "with_secrets": count(frozenset({"contains_secrets"}), ContextItem.contains_secrets.is_(True)),
        "simulated_total": count(frozenset({"include_simulated"}), ContextItem.is_simulation.is_(True)),
    }


def _excerpt_for(finding: SecurityFinding, item_id: str) -> str | None:
    for ev in finding.evidence or []:
        if isinstance(ev, dict) and ev.get("type") == "context_item" and ev.get("id") == item_id and ev.get("excerpt"):
            return clean(str(ev["excerpt"]), 400)
    return None


def _hits(item: ContextItem, findings: list[SecurityFinding]) -> list[dict[str, Any]]:
    """Detection hits recorded on the item, explained by the finding they raised when there is one,
    otherwise by a plain-language description of the rule category."""
    by_rule = {f.rule_id: f for f in reversed(findings)}  # newest wins
    out = []
    for hit in (item.detection_summary or {}).get("hits") or []:
        if not isinstance(hit, dict) or not hit.get("rule_id"):
            continue
        finding = by_rule.get(hit["rule_id"])
        category = str(hit.get("category") or "")
        explanation = clean(finding.explanation) if finding else _CATEGORY_EXPLANATIONS.get(
            category, "Content matched a ContextOS detection rule.")
        out.append({
            "rule_id": hit["rule_id"], "category": category, "title": clean(str(hit.get("title") or hit["rule_id"])),
            "severity": hit.get("severity") or "info", "confidence": float(hit.get("confidence") or 0.0),
            "technique": hit.get("technique") or "plain", "explanation": explanation,
            "explanation_source": "finding" if finding else "category",
            "excerpt": _excerpt_for(finding, item.id) if finding else None, "finding_id": finding.id if finding else None,
        })
    return out


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
    row = load_item(db, org_id, item_id, bound_agent_id)
    item: ContextItem = row[0]
    source: ContextSource = row[1]
    linked = finding_ids_by_item(db, org_id, [item.id])
    findings = load_findings(db, org_id, linked.get(item.id, set()))
    preview = clean(item.redacted_preview)
    secret_types = Counter(str(fp.get("type") or "secret") for fp in item.secret_fingerprints or [] if isinstance(fp, dict))
    summary = item.detection_summary or {}
    hits = _hits(item, findings)
    origin = None
    if item.origin_agent_id:
        name = db.scalar(select(Agent.name).where(Agent.organization_id == org_id, Agent.id == item.origin_agent_id))
        origin = {"id": item.origin_agent_id, "name": name}
    metadata, _ = redact_value(item.item_metadata or {})
    return {
        **item_summary(row, linked),
        "event_id": item.event_id, "content_hash": item.content_hash, "redacted_preview": preview,
        "preview_stored": preview is not None,
        "preview_truncated": bool(preview and preview.endswith("…") and len(preview) >= get_settings().preview_chars),
        "secret_fingerprint_count": len(item.secret_fingerprints or []),
        "secret_types": [{"type": t, "count": c} for t, c in sorted(secret_types.items())],
        "detection": {**detection_counts(summary), "classifier_score": summary.get("classifier_score"), "hits": hits,
                      "findings_suppressed_reason": _OPERATOR_NOTE if hits and source.source_type in OPERATOR_SOURCE_TYPES
                      else None},
        "findings": [finding_ref(f) for f in findings],
        "tool_invocation": invocation_ref(db, org_id, item.tool_invocation_id),
        "origin_agent": origin, "origin_session_id": item.origin_session_id,
        "item_metadata": metadata if isinstance(metadata, dict) else {},
        "provenance": _edges(db, org_id, item.id), "provenance_note": OBSERVED_RELATIONSHIP_NOTE,
        "has_receipt_signature": bool(item.receipt_signature),
    }
