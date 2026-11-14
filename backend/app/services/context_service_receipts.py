"""Context Receipts: the signed record of one context item, re-verified on every read.

The canonical fields are recomputed from the stored row (``ingestion_context.receipt_input``) and the
HMAC recorded at ingest is checked against them, so a row altered after signing reports
``signature_valid = False``. "Subsequent events" are the observed sequence in the same session after
the item, never a claim that the agent acted because of the content.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.engines.provenance import RECEIPT_PURPOSE, receipt_fields, verify_receipt
from app.models import ContextItem, ContextSource, IngestedEvent
from app.services.context_service_common import (
    clean,
    finding_ids_by_item,
    finding_ref,
    invocation_ref,
    load_findings,
    load_item,
    source_ref,
)
from app.services.ingestion_context import label_for, receipt_input

SUBSEQUENT_NOTE = (
    "Events recorded in the same session after this item, in server order. This is an observed "
    "sequence only: it does not show that the agent acted because of this content."
)
_EVENT_LABELS = {
    "tool.requested": "Requested tool {tool}",
    "tool.completed": "Tool {tool} returned a result",
    "tool.failed": "Tool {tool} failed",
    "context.ingested": "Context from {kind} {source}",
    "agent.delegated": "Delegated work to agent {child}",
    "agent.message": "Message from agent {sender}",
    "mcp.server_connected": "MCP server {source} connected",
    "prompt.submitted": "User prompt submitted",
    "session.started": "Session started",
    "session.ended": "Session ended",
}


def _event_summary(event: IngestedEvent) -> tuple[str, str | None]:
    """One-line description of a recorded event, built from its redacted payload."""
    p = event.payload_redacted if isinstance(event.payload_redacted, dict) else {}

    def part(*path: str) -> str | None:
        value: Any = p
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        return clean(str(value), 120) if value not in (None, "") else None

    tool = part("tool", "name")
    template = _EVENT_LABELS.get(event.event_type)
    if template is None:
        return event.event_type.replace(".", " ").replace("_", " ").capitalize(), tool
    text = template.format(
        tool=tool or "unknown",
        kind=label_for(part("source", "type") or "other"),
        source=part("source", "identifier") or "unknown",
        child=part("delegation", "child_agent", "name") or "unknown",
        sender=part("message", "from_agent") or "unknown",
    )
    return text, tool


def _subsequent(db: Session, org_id: str, item: ContextItem, limit: int) -> tuple[list[dict[str, Any]], bool]:
    seq = db.scalar(
        select(IngestedEvent.sequence).where(
            IngestedEvent.organization_id == org_id, IngestedEvent.id == item.event_id
        )
    )
    if seq is None:
        return [], False
    events = list(
        db.scalars(
            select(IngestedEvent)
            .where(
                IngestedEvent.organization_id == org_id,
                IngestedEvent.session_id == item.session_id,
                IngestedEvent.sequence > seq,
            )
            .order_by(IngestedEvent.sequence)
            .limit(limit + 1)
        )
    )
    out = []
    for ev in events[:limit]:
        refs = ev.refs or {}
        summary, tool = _event_summary(ev)
        out.append(
            {
                "id": ev.id,
                "sequence": ev.sequence,
                "event_type": ev.event_type,
                "summary": summary,
                "occurred_at": ev.occurred_at,
                "received_at": ev.received_at,
                "processing_status": ev.processing_status,
                "tool_name": tool,
                "decision": refs.get("decision"),
                "enforcement": refs.get("enforcement"),
                "tool_invocation_id": refs.get("tool_invocation_id"),
                "policy_decision_id": refs.get("policy_decision_id"),
                "context_item_id": refs.get("context_item_id"),
                "finding_ids": list(refs.get("finding_ids") or []),
            }
        )
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


def _statement(
    item: ContextItem, source: ContextSource, agent: str | None, session: str | None, status: str
) -> dict[str, Any]:
    label = label_for(source.source_type)
    ident = clean(source.identifier, 300)
    who = f"session {clean(session or item.session_id, 200)} of agent '{clean(agent or item.agent_id, 200)}'"
    received = item.received_at.isoformat().replace("+00:00", "Z")
    rules = sorted((item.detection_summary or {}).get("rule_ids") or [])
    hits = (
        f"{len(rules)} detection rule(s) matched ({', '.join(rules)})"
        if rules
        else "no detection rule matched"
    )
    summary = (
        f"ContextOS recorded content with SHA-256 {item.content_hash or 'unknown'} "
        f"({item.content_length} characters) from {label} {ident} for {who}, received at {received} "
        f"(server time) via {item.collected_via}."
    )
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
            proves.append(
                "Secrets were detected and redacted before storage; only keyed fingerprints were kept."
            )
    else:
        proves = [
            "Nothing beyond the existence of this record: its fields cannot be verified against a valid "
            "signature, so do not rely on them as an attestation."
        ]
    now_trust = (
        f" (the source is now classified {source.trust_level})"
        if source.trust_level != item.trust_level
        else ""
    )
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


def get_receipt(
    db: Session, org_id: str, item_id: str, *, bound_agent_id: str | None = None, events_limit: int = 10
) -> dict[str, Any]:
    row = load_item(db, org_id, item_id, bound_agent_id)
    item: ContextItem = row[0]
    source: ContextSource = row[1]
    fields = receipt_fields(receipt_input(item, source))
    signature = item.receipt_signature
    valid = verify_receipt(fields, signature)
    status = "missing" if not signature else ("valid" if valid else "invalid")
    linked = finding_ids_by_item(db, org_id, [item.id])
    events, more = _subsequent(db, org_id, item, events_limit)
    skew = (item.received_at - item.collected_at).total_seconds()
    return {
        "receipt": fields,
        "signature": signature,
        "signature_valid": valid,
        "verification": _verification(status),
        "timestamps": {
            "collected_at": item.collected_at,
            "received_at": item.received_at,
            "skew_seconds": round(skew, 3),
            "explanation": "collected_at is reported by the integration and is not trusted; received_at is "
            "ContextOS's own clock when the event arrived and is the authoritative time.",
        },
        "statement": _statement(item, source, row[2], row[3], status),
        "related": {
            "source": source_ref(source),
            "agent": {"id": item.agent_id, "name": row[2]},
            "session": {"id": item.session_id, "external_session_id": row[3], "status": row[4]},
            "tool_invocation": invocation_ref(db, org_id, item.tool_invocation_id),
            "findings": [finding_ref(f) for f in load_findings(db, org_id, linked.get(item.id, set()))],
            "subsequent_events": events,
            "more_subsequent_events": more,
            "subsequent_events_note": SUBSEQUENT_NOTE,
        },
        "is_simulation": bool(item.is_simulation),
        "generated_at": utcnow(),
    }
