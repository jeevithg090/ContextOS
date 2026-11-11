"""Evidence bundle export: a self-describing JSON copy of what ContextOS recorded about an incident.

The bundle carries the incident, its findings, the policy decisions (with the exact redacted input they
were evaluated on), context receipts re-verified at export time, the involved sessions' recorded events
(redacted payloads), the audit entries for these records with their chain hashes and the result of
verifying the organisation's audit chain. ``integrity.sha256`` covers the canonical JSON of every other
top-level field; the same digest is written to the keyed audit chain (``incident.exported``).

Nothing in a bundle is raw content: payloads were redacted before they were stored and are passed
through redaction again here.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import sha256_hex
from app.core.timeutil import isoformat, utcnow
from app.engines.provenance import receipt_fields, verify_receipt
from app.engines.redaction import redact_value
from app.models import (
    Agent,
    AgentSession,
    Approval,
    AuditEvent,
    ContextItem,
    ContextSource,
    Incident,
    IngestedEvent,
    PolicyDecision,
)
from app.services.audit import append_audit, verify_chain
from app.services.incidents import add_activity, incident_key
from app.services.incidents_query import incident_detail, involvement, user_names
from app.services.incidents_timeline import decisions_for
from app.services.ingestion_context import receipt_input
from app.services.notify import notify
from app.services.scoping import get_scoped, scoped
from app.services.sessions_service import timeline_query

BUNDLE_VERSION = "1"
MAX_EVENTS = 5000
MAX_RECEIPTS = 2000
MAX_AUDIT = 5000
_CHUNK = 400
CANONICALIZATION = ("JSON of the bundle without its 'integrity' field: keys sorted, separators ',' and ':', "
                    "UTF-8 without ASCII escaping, numbers as Python's json module writes them")


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return isoformat(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


def _scrub(value: Any) -> Any:
    """Redact again before export (defence in depth: stored values were already redacted)."""
    redacted, _ = redact_value(value)
    return redacted


def canonical_body(bundle: dict[str, Any]) -> str:
    body = {k: v for k, v in bundle.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _chunks(values: set[str]) -> list[list[str]]:
    items = sorted(values)
    return [items[i:i + _CHUNK] for i in range(0, len(items), _CHUNK)]


def _events(db: Session, org_id: str, session_ids: list[str]) -> tuple[list[dict[str, Any]], bool]:
    sessions = list(db.scalars(scoped(AgentSession, org_id).where(AgentSession.id.in_(session_ids)))) \
        if session_ids else []
    agent_ids = {s.agent_id for s in sessions}
    agents: dict[str, str] = {aid: name for aid, name in db.execute(select(Agent.id, Agent.name).where(
        Agent.organization_id == org_id, Agent.id.in_(agent_ids)))} if agent_ids else {}
    rows: dict[str, IngestedEvent] = {}
    for s in sessions:
        query = timeline_query(org_id, s, agents.get(s.agent_id, "")).order_by(IngestedEvent.sequence)
        for ev in db.scalars(query.limit(MAX_EVENTS + 1)):
            rows.setdefault(ev.id, ev)
    ordered = sorted(rows.values(), key=lambda e: e.sequence)
    return [{
        "id": e.id, "sequence": e.sequence, "event_type": e.event_type, "schema_version": e.schema_version,
        "agent_id": e.agent_id, "session_id": e.session_id, "correlation_id": e.correlation_id,
        "integration": e.integration, "occurred_at": e.occurred_at, "received_at": e.received_at,
        "payload_redacted": _scrub(e.payload_redacted or {}), "payload_hash": e.payload_hash,
        "refs": e.refs or {}, "processing_status": e.processing_status,
        "processing_error": _scrub(e.processing_error), "is_simulation": bool(e.is_simulation),
    } for e in ordered[:MAX_EVENTS]], len(ordered) > MAX_EVENTS


def _receipts(db: Session, org_id: str, session_ids: list[str], item_ids: set[str]) -> tuple[list[dict[str, Any]], bool]:
    options = []
    if session_ids:
        options.append(ContextItem.session_id.in_(session_ids))
    if item_ids:
        options.append(ContextItem.id.in_(item_ids))
    if not options:
        return [], False
    rows = list(db.execute(select(ContextItem, ContextSource).join(ContextSource, ContextSource.id == ContextItem.source_id)
                           .where(ContextItem.organization_id == org_id, or_(*options))
                           .order_by(ContextItem.received_at, ContextItem.id).limit(MAX_RECEIPTS + 1)))
    out = []
    for item, source in rows[:MAX_RECEIPTS]:
        fields = receipt_fields(receipt_input(item, source))
        valid = verify_receipt(fields, item.receipt_signature)
        out.append({
            "context_item_id": item.id, "receipt": fields, "signature": item.receipt_signature,
            "signature_valid": valid,
            "signature_status": "missing" if not item.receipt_signature else ("valid" if valid else "invalid"),
            "source_trust_level_now": source.trust_level,
            "cited_by_finding": item.id in item_ids,
        })
    return out, len(rows) > MAX_RECEIPTS


def _decision(d: PolicyDecision) -> dict[str, Any]:
    return {
        "id": d.id, "agent_id": d.agent_id, "session_id": d.session_id, "tool_invocation_id": d.tool_invocation_id,
        "event_id": d.event_id, "decision": d.decision, "enforcement": d.enforcement,
        "matched_policies": _scrub(d.matched_policies or []), "monitor_matches": _scrub(d.monitor_matches or []),
        "explanation": _scrub(d.explanation), "input_snapshot": _scrub(d.input_snapshot or {}),
        "evaluated_at": d.evaluated_at, "latency_ms": d.latency_ms, "is_simulation": bool(d.is_simulation),
    }


def _approval(a: Approval) -> dict[str, Any]:
    return {
        "id": a.id, "policy_decision_id": a.policy_decision_id, "tool_invocation_id": a.tool_invocation_id,
        "agent_id": a.agent_id, "session_id": a.session_id, "status": a.status, "summary": _scrub(a.summary),
        "risk_summary": _scrub(a.risk_summary or {}), "requested_at": a.requested_at, "expires_at": a.expires_at,
        "decided_at": a.decided_at, "decided_by_user_id": a.decided_by_user_id,
        "decision_note": _scrub(a.decision_note),
    }


def _finding(f: Any) -> dict[str, Any]:
    return {
        "id": f.id, "category": f.category, "rule_id": f.rule_id, "title": _scrub(f.title),
        "explanation": _scrub(f.explanation), "severity": f.severity, "confidence": f.confidence,
        "status": f.status, "agent_id": f.agent_id, "session_id": f.session_id, "source_id": f.source_id,
        "context_item_id": f.context_item_id, "tool_invocation_id": f.tool_invocation_id,
        "policy_decision_id": f.policy_decision_id, "destination_id": f.destination_id,
        "evidence": _scrub(f.evidence or []), "fingerprint": f.fingerprint, "occurrence_count": f.occurrence_count,
        "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at, "remediation": _scrub(f.remediation),
        "resolution_note": _scrub(f.resolution_note), "resolved_by_user_id": f.resolved_by_user_id,
        "is_simulation": bool(f.is_simulation),
    }


def _audit(db: Session, org_id: str, targets: set[str]) -> tuple[list[dict[str, Any]], bool]:
    rows: dict[str, AuditEvent] = {}
    for chunk in _chunks(targets):
        for e in db.scalars(scoped(AuditEvent, org_id).where(AuditEvent.target_id.in_(chunk))):
            rows[e.id] = e
    ordered = sorted(rows.values(), key=lambda e: e.seq)
    return [{
        "id": e.id, "seq": e.seq, "occurred_at": e.occurred_at, "actor_type": e.actor_type, "actor_id": e.actor_id,
        "action": e.action, "target_type": e.target_type, "target_id": e.target_id, "details": e.details or {},
        "prev_hash": e.prev_hash, "hash": e.hash,
    } for e in ordered[:MAX_AUDIT]], len(ordered) > MAX_AUDIT


def _attestation(key: str, receipts: list[dict[str, Any]], chain: dict[str, Any]) -> dict[str, Any]:
    invalid = sum(1 for r in receipts if r["signature_status"] != "valid")
    chain_text = ("verified intact" if chain.get("valid")
                  else f"FAILED verification ({chain.get('reason')}); treat the audit entries as unverified")
    return {
        "statement": (f"This bundle is a copy of the records ContextOS held about incident {key} at generated_at. "
                      f"The organisation's audit chain was {chain_text} at export time."),
        "attests": [
            "The incident, findings, policy decisions, approvals, events and audit entries are copied from "
            "ContextOS's database as they were at generated_at.",
            "Each policy decision includes the redacted input snapshot it was actually evaluated against.",
            "Each context receipt's signature was re-checked against fields recomputed from the stored record; "
            "signature_valid is the result of that check"
            + (f" ({invalid} receipt(s) did not verify)." if invalid else "."),
            "Audit entries carry their keyed chain hashes (hash, prev_hash) so they can be re-verified by this "
            "server; audit_chain_verification is the result for the whole organisation chain at export time.",
            "integrity.sha256 is the SHA-256 of the canonical bundle body. The same digest is recorded in the "
            "audit chain as an 'incident.exported' entry, so a later copy can be checked against it.",
        ],
        "limits": [
            "It contains no raw content: payloads, previews and arguments were redacted before storage and again "
            "before export, so the original content cannot be recovered from it.",
            "The sequence of events is what ContextOS observed. It does not show that the agent acted because "
            "of any piece of content; provenance links are observed relationships, not causation.",
            "Client-reported times (occurred_at, collected_at) are untrusted; received_at and other server "
            "timestamps are ContextOS's own clock.",
            "A plain SHA-256 detects changes to the file but anyone who edits it can recompute one; compare "
            "it with the digest in the ContextOS audit trail to confirm the file is unchanged.",
            "Receipt signatures and audit hashes are keyed HMACs: only this ContextOS deployment (holding its "
            "secret) can verify them, and rotating that secret invalidates them.",
            "Only records linked to this incident's findings and sessions are included, up to the limits in "
            "'truncation'; it is not a complete export of the organisation.",
        ],
    }


def build_evidence_bundle(db: Session, org_id: str, incident_id: str, *, actor_type: str,
                          actor_id: str | None) -> tuple[dict[str, Any], str]:
    """Build the bundle, record the export (activity + audit + notification) and return ``(bundle, filename)``."""
    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    detail = incident_detail(db, org_id, incident.id)
    inv = involvement(db, org_id, incident)
    session_ids = inv.session_ids
    decisions = decisions_for(db, org_id, session_ids, inv.policy_decisions)
    approvals = list(db.scalars(scoped(Approval, org_id).where(Approval.session_id.in_(session_ids))
                                .order_by(Approval.requested_at))) if session_ids else []
    events, events_cut = _events(db, org_id, session_ids)
    receipts, receipts_cut = _receipts(db, org_id, session_ids, inv.context_items)
    targets = ({incident.id} | {f.id for f in inv.findings} | {d.id for d in decisions}
               | {d.tool_invocation_id for d in decisions if d.tool_invocation_id} | inv.tool_invocations
               | {a.id for a in approvals} | set(inv.sources) | set(inv.destinations) | {e["id"] for e in events})
    audit_entries, audit_cut = _audit(db, org_id, targets)
    chain = verify_chain(db, org_id)
    generated_by = {"type": actor_type, "id": actor_id,
                    "name": user_names(db, org_id, {actor_id}).get(actor_id or "") if actor_type == "user" else None}
    key = incident_key(incident)
    body: dict[str, Any] = _jsonable({
        "bundle_version": BUNDLE_VERSION,
        "generated_at": utcnow(),
        "generated_by": generated_by,
        "organization_id": org_id,
        "incident": {k: v for k, v in detail.items() if k not in ("findings",)},
        "findings": [_finding(f) for f in inv.findings],
        "policy_decisions": [_decision(d) for d in decisions],
        "approvals": [_approval(a) for a in approvals],
        "context_receipts": receipts,
        "events": events,
        "audit_entries": audit_entries,
        "audit_chain_verification": chain,
        "truncation": {"events": events_cut, "context_receipts": receipts_cut, "audit_entries": audit_cut,
                       "limits": {"events": MAX_EVENTS, "context_receipts": MAX_RECEIPTS, "audit_entries": MAX_AUDIT}},
        "attestation": _attestation(key, receipts, chain),
    })
    digest = sha256_hex(canonical_body(body).encode("utf-8"))
    bundle = {**body, "integrity": {"algorithm": "sha256", "sha256": digest, "canonicalization": CANONICALIZATION,
                                    "covers": "every top-level field except 'integrity'"}}
    counts = {"findings": len(body["findings"]), "policy_decisions": len(decisions), "events": len(events),
              "context_receipts": len(receipts), "audit_entries": len(audit_entries)}
    add_activity(db, org_id, incident.id, actor=actor_id if actor_type == "user" and actor_id else "system",
                 kind="exported", body=f"Evidence bundle exported (sha256 {digest[:16]}…)",
                 details={"sha256": digest, "actor_type": actor_type, **counts})
    append_audit(db, org_id, action="incident.exported", actor_type=actor_type, actor_id=actor_id,
                 target_type="incident", target_id=incident.id,
                 details={"sha256": digest, "bundle_version": BUNDLE_VERSION, **counts})
    notify(db, org_id, "incident.updated", id=incident.id)
    return bundle, f"contextos-{key.lower()}-evidence.json"
