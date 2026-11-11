"""Provenance node resolution and inspector descriptions (used by ``provenance_service``).

``resolve`` turns ``(type, record id)`` keys into display nodes (``GraphNodeOut``) plus the attributes the
provenance engine's risky-path analysis reads (documented in ``engines/provenance/signals.py``).
``describe`` produces the inspector's fields and notes for one node.

Everything shown comes from persisted rows, which the ingestion pipeline redacted before storage;
secret fingerprints are reduced to counts and types here. Every query is scoped to the organisation.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.timeutil import isoformat
from app.domain.enums import ApprovalStatus, Decision, EnforcementMode, ProvenanceNodeType, ProvenanceRelation
from app.models import (
    Agent,
    AgentSession,
    Approval,
    ContextItem,
    ContextSource,
    Destination,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.schemas.provenance import GraphNodeOut
from app.services.scoping import find_scoped, get_scoped, scoped

N = ProvenanceNodeType
_CHUNK = 400
_SENSITIVE_LEVELS = {"confidential", "secret"}
_RAN = {"completed", "failed"}
_PREVIEW_MAX = 1200


@dataclass
class Resolved:
    out: GraphNodeOut
    engine: dict[str, Any]  # node dict for engines.provenance.build_graph


def compact(text: str | None, max_len: int = 48) -> str:
    """Identifier without URL scheme, shortened from the left so the most specific part stays visible."""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", (text or "").strip(), flags=re.IGNORECASE)
    return value if len(value) <= max_len else "…" + value[-(max_len - 1):]


def _words(value: str | None) -> str:
    return (value or "").replace("_", " ")


def _rows(db: Session, model: Any, org_id: str, ids: Iterable[str]) -> list[Any]:
    items, found = sorted(set(ids)), []
    for i in range(0, len(items), _CHUNK):
        found.extend(db.scalars(scoped(model, org_id).where(model.id.in_(items[i:i + _CHUNK]))))
    return found


def _make(node_type: N, ref_id: str, label: str, engine: dict[str, Any] | None = None, **out: Any) -> Resolved:
    gid = f"{node_type.value}:{ref_id}"
    node = GraphNodeOut(id=gid, type=node_type.value, ref_id=ref_id, label=(label or ref_id)[:200], **out)
    return Resolved(node, {"id": gid, "type": node_type.value, "label": node.label, **(engine or {})})


def resource_meta(edges: Iterable[Any]) -> dict[str, dict[str, Any]]:
    """Sensitivity of resource nodes, read from the metadata of the edges that accessed them."""
    meta: dict[str, dict[str, Any]] = {}
    for e in edges:
        if e.dst[0] != N.RESOURCE.value:
            continue
        entry = meta.setdefault(e.dst[1], {"sensitive": False, "reason": None, "access_count": 0})
        if e.relation == ProvenanceRelation.INVOCATION_ACCESSED_RESOURCE.value:
            entry["access_count"] += 1
            entry["sensitive"] = entry["sensitive"] or bool((e.metadata or {}).get("sensitive"))
            entry["reason"] = entry["reason"] or (e.metadata or {}).get("reason")
    return meta


# -- loaders ---------------------------------------------------------------------------------------


def _sources(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for s in _rows(db, ContextSource, org, ids):
        yield _make(
            N.SOURCE, s.id, s.display_name or compact(s.identifier, 56), {"trust_level": s.trust_level},
            subtitle=f"{_words(s.source_type)} · seen {s.observation_count}×", trust_level=s.trust_level,
            severity=s.max_finding_severity, observed_at=s.last_seen_at,
            attributes={"source_type": s.source_type, "identifier": s.identifier, "finding_count": s.finding_count},
        )


def _items(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    items = _rows(db, ContextItem, org, ids)
    sources = {s.id: s for s in _rows(db, ContextSource, org, {i.source_id for i in items})}
    for i in items:
        src = sources.get(i.source_id)
        summary = i.detection_summary or {}
        via = (i.collected_via or "").split(":")[-1]
        yield _make(
            N.CONTEXT_ITEM, i.id, compact(src.display_name or src.identifier) if src else "Context item",
            {"trust_level": i.trust_level, "detection_summary": summary, "contains_secrets": i.contains_secrets,
             "sensitivity": i.sensitivity, "received_at": i.received_at},
            subtitle=" · ".join(p for p in (via, i.content_type, f"{i.content_length} chars") if p),
            session_id=i.session_id, trust_level=i.trust_level, severity=summary.get("max_severity"),
            sensitive=i.sensitivity in _SENSITIVE_LEVELS, contains_secrets=i.contains_secrets,
            is_simulation=i.is_simulation, observed_at=i.received_at,
            attributes={"source_id": i.source_id, "source_type": src.source_type if src else None,
                        "collected_via": i.collected_via, "detection_rule_ids": list(summary.get("rule_ids") or [])[:10],
                        "detection_hits": summary.get("hit_count", 0), "origin_session_id": i.origin_session_id},
        )


def _sessions(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    sessions = _rows(db, AgentSession, org, ids)
    agents = {a.id: a for a in _rows(db, Agent, org, {s.agent_id for s in sessions})}
    for s in sessions:
        agent = agents.get(s.agent_id)
        risk = s.risk_state or {}
        yield _make(
            N.SESSION, s.id, agent.name if agent else "Session", {"started_at": s.started_at},
            subtitle=f"{compact(s.external_session_id, 24)} · {s.event_count} events", session_id=s.id,
            risk_level=risk.get("level"), risk_score=s.risk_score, is_simulation=s.is_simulation, observed_at=s.started_at,
            attributes={"agent_id": s.agent_id, "status": s.status, "trifecta": bool(risk.get("trifecta")),
                        "parent_session_id": s.parent_session_id},
        )


def ran_despite_block(inv: ToolInvocation, approvals: dict[str, Approval]) -> bool:
    """The call reported a result although ContextOS denied it or held it for an approval that was
    never granted — so the decision was not honoured, whatever the enforcement mode claimed."""
    if inv.status not in _RAN:
        return False
    if inv.decision == Decision.DENY.value:
        return True
    if inv.decision == Decision.REQUIRE_APPROVAL.value:
        approval = approvals.get(inv.approval_id or "")
        return approval is None or approval.status != ApprovalStatus.APPROVED.value
    return False


def _invocations(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    invs = _rows(db, ToolInvocation, org, ids)
    tools = {t.id: t for t in _rows(db, Tool, org, {i.tool_id for i in invs})}
    approvals = {a.id: a for a in _rows(db, Approval, org, {i.approval_id for i in invs if i.approval_id})}
    for inv in invs:
        tool = tools.get(inv.tool_id)
        resources = [r for r in inv.resources or [] if isinstance(r, dict)]
        matched = len(inv.matched_session_fingerprints or [])
        ran_anyway = ran_despite_block(inv, approvals)
        yield _make(
            N.TOOL_INVOCATION, inv.id, tool.name if tool else "Tool call",
            # A blocking decision the integration did not honour prevented nothing: tell the risky-path
            # analysis so its outcome reads "not prevented" instead of trusting the enforcement label.
            {"tool_name": tool.name if tool else None, "decision": inv.decision,
             "enforcement": EnforcementMode.OBSERVED.value if ran_anyway else inv.enforcement,
             "status": inv.status, "sensitive_data_detected": inv.sensitive_data_detected,
             "secret_fingerprints": len(inv.secret_fingerprints or []), "matched_session_fingerprints": matched,
             "requested_at": inv.requested_at},
            subtitle=f"{_words(tool.category) if tool else 'tool'} · {_words(inv.status)}", session_id=inv.session_id,
            decision=inv.decision, enforcement=inv.enforcement, is_simulation=inv.is_simulation,
            sensitive=inv.sensitive_data_detected or any(r.get("sensitive") for r in resources),
            contains_secrets=bool(inv.secret_fingerprints) or matched > 0, observed_at=inv.requested_at,
            attributes={"tool_id": inv.tool_id, "tool_category": tool.category if tool else None, "status": inv.status,
                        "matched_secret_count": matched, "resource_count": len(resources), "ran_despite_block": ran_anyway},
        )


def _resources(db: Session, org: str, ids: list[str], meta: dict) -> Iterable[Resolved]:
    for ref in ids:
        kind, _, ident = ref.partition(":")
        info = meta.get(ref, {})
        sensitive = bool(info.get("sensitive"))
        yield _make(
            N.RESOURCE, ref, compact(ident or ref), {"sensitive": sensitive},
            subtitle=_words(kind) + (" · sensitive" if sensitive else ""), sensitive=sensitive,
            attributes={"kind": kind, "identifier": ident, "reason": info.get("reason")},
        )


def _destinations(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for d in _rows(db, Destination, org, ids):
        yield _make(
            N.DESTINATION, d.id, d.display_name or compact(d.identifier), {"classification": d.classification},
            subtitle=f"{_words(d.kind)} · {d.transfer_count} sent · {d.blocked_count} blocked", trust_level=d.classification,
            observed_at=d.last_seen_at, attributes={"kind": d.kind, "identifier": d.identifier,
                                                   "sensitive_transfer_count": d.sensitive_transfer_count},
        )


def _findings(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for f in _rows(db, SecurityFinding, org, ids):
        yield _make(
            N.FINDING, f.id, f.title, {"severity": f.severity}, subtitle=f"{_words(f.category)} · {_words(f.status)}",
            session_id=f.session_id, severity=f.severity, is_simulation=f.is_simulation, observed_at=f.first_seen_at,
            attributes={"category": f.category, "status": f.status, "rule_id": f.rule_id, "incident_id": f.incident_id},
        )


def _decisions(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for d in _rows(db, PolicyDecision, org, ids):
        names = [str(m.get("name")) for m in d.matched_policies or [] if isinstance(m, dict) and m.get("name")]
        yield _make(
            N.POLICY_DECISION, d.id, _words(d.decision).capitalize(), {"decision": d.decision, "enforcement": d.enforcement},
            subtitle=(names[0] if names else "no policy matched") + (f" +{len(names) - 1}" if len(names) > 1 else ""),
            session_id=d.session_id, decision=d.decision, enforcement=d.enforcement, is_simulation=d.is_simulation,
            observed_at=d.evaluated_at, attributes={"matched_policies": names[:10]},
        )


def _tools(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for t in _rows(db, Tool, org, ids):
        yield _make(N.TOOL, t.id, t.name, {}, subtitle=f"{_words(t.category)} · {t.risk_level} risk", risk_level=t.risk_level,
                    observed_at=t.last_seen_at, attributes={"provider": t.provider, "category": t.category})


def _agents(db: Session, org: str, ids: list[str], _: dict) -> Iterable[Resolved]:
    for a in _rows(db, Agent, org, ids):
        yield _make(N.AGENT, a.id, a.name, {}, subtitle=f"{a.framework} · {a.environment}", risk_score=a.risk_score,
                    is_simulation=a.is_simulation, observed_at=a.last_seen_at,
                    attributes={"framework": a.framework, "environment": a.environment, "status": a.status})


_LOADERS: dict[str, Callable[[Session, str, list[str], dict], Iterable[Resolved]]] = {
    N.SOURCE.value: _sources, N.CONTEXT_ITEM.value: _items, N.SESSION.value: _sessions,
    N.TOOL_INVOCATION.value: _invocations, N.RESOURCE.value: _resources, N.DESTINATION.value: _destinations,
    N.FINDING.value: _findings, N.POLICY_DECISION.value: _decisions, N.TOOL.value: _tools, N.AGENT.value: _agents,
}


def resolve(db: Session, org_id: str, keys: Iterable[tuple[str, str]],
            meta: dict[str, dict[str, Any]] | None = None) -> dict[tuple[str, str], Resolved]:
    """Resolve node keys within the organisation. Keys whose record does not exist (or belongs to
    another organisation) are left out, so edges to them are dropped and counted by build_graph."""
    by_type: dict[str, list[str]] = defaultdict(list)
    for node_type, ref in keys:
        by_type[node_type].append(ref)
    found: dict[tuple[str, str], Resolved] = {}
    for node_type, refs in by_type.items():
        loader = _LOADERS.get(node_type)
        if loader is None:
            continue
        for node in loader(db, org_id, refs, meta or {}):
            found[(node.out.type, node.out.ref_id)] = node
    return found


# -- inspector descriptions ------------------------------------------------------------------------

Described = tuple[list[dict[str, Any]], list[str], str | None, str | None]  # fields, notes, preview, preview label


def _f(key: str, label: str, value: Any, kind: str = "text") -> dict[str, Any]:
    if isinstance(value, datetime):
        value, kind = isoformat(value), "datetime"
    return {"key": key, "label": label, "value": value, "kind": kind}


def _clean(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in fields if f["value"] not in (None, "", [])]


def _note(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("explanation") or value.get("detail") or value.get("reason") or value.get("message") or "")
    return str(value or "")


def _describe_source(db: Session, org: str, ref: str) -> Described:
    s = get_scoped(db, ContextSource, ref, org, label="Source")
    return [
        _f("identifier", "Identifier", s.identifier, "mono"), _f("source_type", "Source type", _words(s.source_type)),
        _f("trust_level", "Trust", s.trust_level, "trust"),
        _f("trust_capabilities", "Trusted for", [str(c) for c in s.trust_capabilities or []], "list"),
        _f("manually_classified", "Classified by a person", s.manually_classified, "bool"),
        _f("observation_count", "Times observed", s.observation_count, "number"),
        _f("finding_count", "Findings raised", s.finding_count, "number"),
        _f("max_finding_severity", "Worst finding", s.max_finding_severity, "severity"),
        _f("first_seen_at", "First seen", s.first_seen_at), _f("last_seen_at", "Last seen", s.last_seen_at),
    ], [n for n in map(_note, s.trust_reasons or []) if n], None, None


def _describe_item(db: Session, org: str, ref: str) -> Described:
    i = get_scoped(db, ContextItem, ref, org, label="Context item")
    src = find_scoped(db, ContextSource, i.source_id, org)
    summary = i.detection_summary or {}
    secret_types = sorted({str(fp.get("type")) for fp in i.secret_fingerprints or [] if isinstance(fp, dict) and fp.get("type")})
    notes = ["Trust is the source's classification at the moment this content was received."]
    if i.contains_secrets:
        notes.append("Secrets in this content were redacted before storage; only keyed fingerprints are kept.")
    return [
        _f("source", "Source", src.identifier if src else None, "mono"), _f("collected_via", "Collected via", i.collected_via, "mono"),
        _f("collected_at", "Collected (client)", i.collected_at), _f("received_at", "Received (server)", i.received_at),
        _f("trust_level", "Trust at ingest", i.trust_level, "trust"),
        _f("max_severity", "Highest detection", summary.get("max_severity"), "severity"),
        _f("detection_score", "Detection score", summary.get("score"), "number"),
        _f("rule_ids", "Detection rules", [str(r) for r in summary.get("rule_ids") or []], "list"),
        _f("sensitivity", "Sensitivity", i.sensitivity), _f("contains_secrets", "Contains secrets", i.contains_secrets, "bool"),
        _f("secret_types", "Secret types", secret_types, "list"), _f("content_type", "Content type", i.content_type),
        _f("content_length", "Length (chars)", i.content_length, "number"), _f("content_hash", "SHA-256", i.content_hash, "mono"),
        _f("receipt_signed", "Receipt signed", i.receipt_signature is not None, "bool"),
    ], notes, (i.redacted_preview or "")[:_PREVIEW_MAX] or None, "Content preview (redacted)"


def _describe_session(db: Session, org: str, ref: str) -> Described:
    s = get_scoped(db, AgentSession, ref, org, label="Session")
    agent = find_scoped(db, Agent, s.agent_id, org)
    risk = s.risk_state or {}
    notes = [str(risk["summary"])] if risk.get("summary") else []
    notes += [f"{_note(f.get('label'))}: {_note(f)}" for f in risk.get("factors") or [] if isinstance(f, dict) and _note(f)]
    return [
        _f("agent", "Agent", agent.name if agent else None), _f("external_session_id", "Session id (integration)", s.external_session_id, "mono"),
        _f("status", "Status", s.status), _f("risk_score", "Risk score", s.risk_score, "number"),
        _f("risk_level", "Risk level", risk.get("level"), "risk"),
        _f("trifecta", "Lethal-trifecta conditions", bool(risk.get("trifecta")), "bool"),
        _f("untrusted_exposure", "Saw untrusted content", risk.get("untrusted_exposure"), "bool"),
        _f("sensitive_access", "Accessed sensitive data", risk.get("sensitive_access"), "bool"),
        _f("outbound_channel", "Had an outbound channel", risk.get("outbound_channel"), "bool"),
        _f("event_count", "Events", s.event_count, "number"), _f("started_at", "Started", s.started_at),
        _f("last_event_at", "Last event", s.last_event_at), _f("ended_at", "Ended", s.ended_at),
        _f("parent_session_id", "Delegated from", s.parent_session_id, "mono"),
    ], notes, None, None


def _describe_invocation(db: Session, org: str, ref: str) -> Described:
    inv = get_scoped(db, ToolInvocation, ref, org, label="Tool call")
    tool = find_scoped(db, Tool, inv.tool_id, org)
    dest = find_scoped(db, Destination, inv.destination_id, org)
    decision = find_scoped(db, PolicyDecision, inv.policy_decision_id, org)
    resources = [f"{r.get('kind')}: {r.get('id')}" + (" (sensitive)" if r.get("sensitive") else "")
                 for r in inv.resources or [] if isinstance(r, dict)]
    notes = [decision.explanation] if decision and decision.explanation else []
    if inv.matched_session_fingerprints:
        notes.append("Secret fingerprints in the arguments match secrets previously seen in this session's context "
                     "(an inferred relationship based on keyed fingerprints).")
    approval = find_scoped(db, Approval, inv.approval_id, org)
    ran_anyway = ran_despite_block(inv, {approval.id: approval} if approval else {})
    if ran_anyway:
        notes.insert(0, f"The tool reported a result although ContextOS returned {inv.decision}: the decision was not "
                        "honoured, so nothing was prevented.")
    if inv.error:
        notes.append(f"Error: {inv.error[:300]}")
    args = json.dumps(inv.arguments_redacted or {}, indent=2, default=str)[:_PREVIEW_MAX] if inv.arguments_redacted else None
    return _clean([
        _f("tool", "Tool", tool.name if tool else None), _f("tool_category", "Category", _words(tool.category) if tool else None),
        _f("tool_risk", "Tool risk", tool.risk_level if tool else None, "risk"), _f("status", "Status", _words(inv.status)),
        _f("decision", "Decision", inv.decision, "decision"), _f("enforcement", "Enforcement", inv.enforcement, "enforcement"),
        _f("ran_despite_block", "Ran despite the decision", True if ran_anyway else None, "bool"),
        _f("requested_at", "Requested", inv.requested_at), _f("completed_at", "Completed", inv.completed_at),
        _f("resources", "Resources", resources[:20], "list"), _f("destination", "Destination", dest.identifier if dest else None, "mono"),
        _f("sensitive_data_detected", "Secrets in arguments", inv.sensitive_data_detected, "bool"),
        _f("matched_secrets", "Session secrets matched", len(inv.matched_session_fingerprints or []), "number"),
        _f("result_summary", "Result (redacted)", (inv.result_summary or "")[:300]),
        _f("correlation_id", "Correlation id", inv.correlation_id, "mono"),
    ]), notes, args, "Arguments (redacted)"


def _describe_destination(db: Session, org: str, ref: str) -> Described:
    d = get_scoped(db, Destination, ref, org, label="Destination")
    notes = [f"{v.get('check')}: {v.get('result')}" + (f" — {v['detail']}" if v.get("detail") else "")
             for v in d.verification or [] if isinstance(v, dict) and v.get("check")]
    return [
        _f("identifier", "Identifier", d.identifier, "mono"), _f("kind", "Kind", d.kind),
        _f("classification", "Classification", d.classification, "trust"),
        _f("transfer_count", "Transfers allowed", d.transfer_count, "number"),
        _f("blocked_count", "Transfers blocked", d.blocked_count, "number"),
        _f("sensitive_transfer_count", "Sensitive transfers", d.sensitive_transfer_count, "number"),
        _f("first_seen_at", "First seen", d.first_seen_at), _f("last_seen_at", "Last seen", d.last_seen_at),
    ], notes, None, None


def _describe_finding(db: Session, org: str, ref: str) -> Described:
    f = get_scoped(db, SecurityFinding, ref, org, label="Finding")
    notes = [f.explanation] + ([f"Remediation: {f.remediation}"] if f.remediation else [])
    return _clean([
        _f("category", "Category", _words(f.category)), _f("severity", "Severity", f.severity, "severity"),
        _f("status", "Status", _words(f.status)), _f("rule_id", "Rule", f.rule_id, "mono"),
        _f("confidence", "Confidence", round(f.confidence * 100), "number"),
        _f("occurrence_count", "Occurrences", f.occurrence_count, "number"),
        _f("first_seen_at", "First seen", f.first_seen_at), _f("last_seen_at", "Last seen", f.last_seen_at),
        _f("incident_id", "Incident", f.incident_id, "mono"),
    ]), notes, None, None


def _describe_decision(db: Session, org: str, ref: str) -> Described:
    d = get_scoped(db, PolicyDecision, ref, org, label="Policy decision")
    matched = [f"{m.get('name')} ({m.get('outcome')}, {m.get('mode')})" for m in d.matched_policies or [] if isinstance(m, dict)]
    return [
        _f("decision", "Decision", d.decision, "decision"), _f("enforcement", "Enforcement", d.enforcement, "enforcement"),
        _f("matched_policies", "Matched policies", matched, "list"),
        _f("monitor_matches", "Monitor-mode matches (recorded only)", len(d.monitor_matches or []), "number"),
        _f("evaluated_at", "Evaluated", d.evaluated_at), _f("latency_ms", "Latency (ms)", round(d.latency_ms, 2), "number"),
    ], [d.explanation] if d.explanation else [], None, None


def _describe_tool(db: Session, org: str, ref: str) -> Described:
    t = get_scoped(db, Tool, ref, org, label="Tool")
    return _clean([
        _f("name", "Name", t.name, "mono"), _f("provider", "Provider", t.provider), _f("server", "MCP server", t.server),
        _f("category", "Category", _words(t.category)), _f("risk_level", "Risk", t.risk_level, "risk"),
        _f("invocation_count", "Calls", t.invocation_count, "number"), _f("last_seen_at", "Last used", t.last_seen_at),
    ]), [t.description] if t.description else [], None, None


def _describe_agent(db: Session, org: str, ref: str) -> Described:
    a = get_scoped(db, Agent, ref, org, label="Agent")
    return _clean([
        _f("framework", "Framework", a.framework), _f("environment", "Environment", a.environment),
        _f("status", "Status", a.status), _f("version", "Version", a.version, "mono"), _f("owner", "Owner", a.owner),
        _f("risk_score", "Risk score", a.risk_score, "number"), _f("last_seen_at", "Last seen", a.last_seen_at),
    ]), [a.description] if a.description else [], None, None


def _describe_resource(meta: dict[str, Any], ref: str) -> Described:
    kind, _, ident = ref.partition(":")
    notes = [f"Flagged as sensitive: {meta['reason']}" if meta.get("reason") else "Flagged as sensitive."] if meta.get("sensitive") else []
    return [
        _f("kind", "Kind", kind), _f("identifier", "Identifier", ident or ref, "mono"),
        _f("sensitive", "Sensitive", bool(meta.get("sensitive")), "bool"),
        _f("access_count", "Recorded accesses (shown)", meta.get("access_count", 0), "number"),
    ], notes, None, None


_DESCRIBERS: dict[str, Callable[[Session, str, str], Described]] = {
    N.SOURCE.value: _describe_source, N.CONTEXT_ITEM.value: _describe_item, N.SESSION.value: _describe_session,
    N.TOOL_INVOCATION.value: _describe_invocation, N.DESTINATION.value: _describe_destination,
    N.FINDING.value: _describe_finding, N.POLICY_DECISION.value: _describe_decision, N.TOOL.value: _describe_tool,
    N.AGENT.value: _describe_agent,
}


def describe(db: Session, org_id: str, node_type: str, ref_id: str, meta: dict[str, dict[str, Any]]) -> Described:
    if node_type == N.RESOURCE.value:
        return _describe_resource(meta.get(ref_id, {}), ref_id)
    fields, notes, preview, label = _DESCRIBERS[node_type](db, org_id, ref_id)
    return _clean(fields), [n for n in notes if n], preview, label
