"""Tool requests: server-side classification, resources, destinations, credential flow, policy
evaluation and the persisted decision (``ToolInvocation`` + ``PolicyDecision`` + optional ``Approval``).

Arguments are redacted before anything else looks at them; classification, resource extraction,
detection and the policy input all work on the redacted form, so nothing downstream can persist a
raw secret. Secret fingerprints (keyed HMAC) are what links a credential in the arguments to the
same credential previously seen in this session's context.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import select

from app.core.ids import new_id
from app.core.security import sha256_hex
from app.domain.enums import Decision, ProvenanceNodeType, ProvenanceRelation, TrustLevel
from app.engines.detection import DetectionResult, analyze_tool_request
from app.engines.policy import EvaluationInput, EvaluationResult, evaluate
from app.engines.redaction import HIGH_CONFIDENCE, redact_value
from app.engines.risk import (
    SessionRisk,
    ToolClassification,
    classify_tool,
    compute_session_risk,
    extract_destination,
    extract_resources,
)
from app.engines.trust import DestinationAssessment, DestinationHistory, assess_destination
from app.engines.trust.destinations import parse_destination
from app.events.envelope import ToolRef
from app.models import Approval, Destination, PolicyDecision, Tool, ToolInvocation
from app.services.approvals import create_approval
from app.services.audit import append_audit
from app.services.ingestion_entities import add_edge, tool_identity, upsert_tool
from app.services.ingestion_known_secrets import (
    as_matches,
    find_known,
    redact_known,
    redact_session_text,
    session_fingerprints,
)
from app.services.ingestion_risk import SessionView, session_risk_input, session_view
from app.services.ingestion_state import ENFORCING_INTEGRATIONS, PipelineState, redact_str
from app.services.ingestion_tool_findings import record_tool_findings

N = ProvenanceNodeType
R = ProvenanceRelation
SAFE_DESTINATIONS = frozenset({TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value})

_STATUS_BY_DECISION = {
    Decision.ALLOW: "allowed", Decision.AUDIT: "allowed", Decision.RESTRICT: "restricted",
    Decision.DENY: "denied", Decision.REQUIRE_APPROVAL: "pending_approval",
}


@dataclass
class ToolAnalysis:
    tool: Tool
    tool_name: str
    provider: str
    server: str | None
    cls: ToolClassification
    arguments: dict[str, Any]  # redacted
    argument_hash: str
    resources: list[dict[str, Any]]
    destination: Destination | None
    destination_assessment: DestinationAssessment | None
    secrets_in_arguments: list[dict[str, str]]
    all_argument_fingerprints: list[dict[str, Any]]
    session_secret_matches: list[dict[str, str]]  # + "context_item_id"
    detection: DetectionResult
    destination_reported_only: bool = False

    @property
    def sensitive_resources(self) -> list[str]:
        return [r["id"] for r in self.resources if r.get("sensitive")]

    @property
    def outbound(self) -> bool:
        return self.cls.outbound or self.destination is not None

    @property
    def target(self) -> str | None:
        if self.destination is not None:
            return self.destination.identifier
        for res in self.resources:
            if res.get("kind") in ("file", "url", "command", "email", "channel", "table", "agent"):
                return str(res["id"])[:200]
        return None


def _argument_hash(arguments: dict[str, Any]) -> str:
    return sha256_hex(json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str))


def analyze_tool_call(st: PipelineState, ref: ToolRef, raw_arguments: dict[str, Any] | None) -> ToolAnalysis:
    redacted, matches = redact_value(raw_arguments or {})
    arguments = redacted if isinstance(redacted, dict) else {"value": redacted}
    known = find_known(st, arguments)  # session secrets in a form no detector recognises
    if known:
        arguments = redact_known(arguments, known)
    provider, name, server = tool_identity(ref, st.integration_kind)
    hint = ref.category_hint.value if ref.category_hint else None
    tool = upsert_tool(st, provider=provider, name=name, server=server, category_hint=hint,
                       description=ref.description, count_invocation=True)
    cls = classify_tool(ref.name, provider, category_hint=hint, server=server, arguments=arguments)
    resources = extract_resources(cls.category, arguments) if arguments else []
    dest_ref = extract_destination(cls.category, arguments, resources)
    reported_only = False
    if dest_ref is None and st.env.destination is not None:
        dest_ref = {"kind": st.env.destination.kind, "identifier": st.env.destination.identifier}
        reported_only = True
    destination, assessment = (None, None)
    if dest_ref:
        destination, assessment = upsert_destination(st, dest_ref, reported_only=reported_only)

    fingerprints: dict[str, dict[str, Any]] = {}
    for m in matches:
        entry = fingerprints.setdefault(m.fingerprint, {"type": m.secret_type, "fingerprint": m.fingerprint,
                                                        "confidence": m.confidence})
        entry["confidence"] = max(entry["confidence"], m.confidence)
    for k in as_matches(known):
        fingerprints.setdefault(k["fingerprint"], k)
    high = [{"type": f["type"], "fingerprint": f["fingerprint"]} for f in fingerprints.values()
            if f["confidence"] >= HIGH_CONFIDENCE]
    detection = analyze_tool_request(ref.name, cls.category, arguments, resources=[str(r["id"]) for r in resources])
    detection.hits = [replace(h, excerpt=st.scrub(h.excerpt)) for h in detection.hits]
    return ToolAnalysis(
        tool=tool, tool_name=name, provider=provider, server=server, cls=cls, arguments=arguments,
        argument_hash=_argument_hash(arguments), resources=resources, destination=destination,
        destination_assessment=assessment, secrets_in_arguments=high,
        all_argument_fingerprints=list(fingerprints.values()),
        session_secret_matches=_session_matches(st, fingerprints), detection=detection,
        destination_reported_only=reported_only,
    )


def _session_matches(st: PipelineState, fingerprints: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """Argument secrets previously observed (high confidence) in this session's context."""
    if not fingerprints:
        return []
    seen = session_fingerprints(st)
    return [
        {"type": f["type"], "fingerprint": fp, "context_item_id": seen[fp][1]}
        for fp, f in fingerprints.items() if fp in seen
    ]


def upsert_destination(st: PipelineState, dest_ref: dict[str, str], *, reported_only: bool) -> tuple[Destination, DestinationAssessment]:
    db, org = st.db, st.ctx.org_id
    kind = dest_ref.get("kind") or "unknown"
    identifier = (redact_session_text(st, dest_ref.get("identifier") or "") or "")[:1024]
    target = parse_destination(kind, identifier)  # canonical form, to look up the history first
    canonical = (target.canonical or identifier)[:1024]
    row = db.scalar(select(Destination).where(
        Destination.organization_id == org, Destination.kind == target.kind, Destination.identifier == canonical))
    history = DestinationHistory(previously_seen=row is not None, transfer_count=row.transfer_count if row else 0)
    assessment = assess_destination(kind, identifier, rules=st.destination_rules(), history=history)
    if reported_only:
        assessment.checks.append({"check": "reported_by_integration", "result": "warn",
                                  "detail": "The integration reported this destination; ContextOS could not derive "
                                            "it from the call's arguments, so it cannot be treated as trusted."})
        if assessment.classification in SAFE_DESTINATIONS:
            assessment.reasons.append("Treated as UNKNOWN because the destination was reported, not derived "
                                      "from the arguments.")
            assessment.classification = TrustLevel.UNKNOWN.value
    if row is None:
        row = Destination(id=new_id("destination"), organization_id=org, kind=assessment.kind or target.kind,
                          identifier=canonical, display_name=canonical[:400], first_seen_at=st.now,
                          transfer_count=0, blocked_count=0, sensitive_transfer_count=0, verification=[])
        db.add(row)
    row.classification = assessment.classification
    row.trust_rule_id = assessment.matched_rule_id
    row.verification = [{**c, "detail": redact_str(c.get("detail"), limit=500)} for c in assessment.checks]
    row.last_seen_at = st.now
    db.flush()
    st.refs["destination_id"] = row.id
    return row, assessment


def build_input(st: PipelineState, a: ToolAnalysis, risk: SessionRisk, context: dict[str, Any]) -> EvaluationInput:
    assert st.agent is not None
    agent = st.agent
    destination: dict[str, Any] = {}
    if a.destination is not None and a.destination_assessment is not None:
        destination = {"kind": a.destination.kind, "identifier": a.destination.identifier,
                       "classification": a.destination_assessment.classification,
                       "checks": list(a.destination.verification or [])}
    return EvaluationInput(
        agent={"id": agent.id, "name": agent.name, "environment": agent.environment,
               "labels": list(agent.labels or []), "framework": agent.framework},
        tool={"name": a.tool_name, "category": a.cls.category, "provider": a.provider, "server": a.server,
              "risk_level": a.cls.risk_level},
        arguments=a.arguments,
        resources=a.resources,
        sensitive_resources=a.sensitive_resources,
        destination=destination,
        secrets_in_arguments=a.secrets_in_arguments,
        session_secret_matches=[{"type": m["type"], "fingerprint": m["fingerprint"]} for m in a.session_secret_matches],
        session=session_risk_input(risk),
        context=context,
        detection={"rule_ids": sorted({h.rule_id for h in a.detection.hits}), "max_severity": a.detection.max_severity,
                   "categories": sorted({h.category for h in a.detection.hits})},
        integration={"kind": st.integration_kind,
                     "supports_enforcement": st.via_decide and st.integration_kind in ENFORCING_INTEGRATIONS},
    )


@dataclass
class DecisionOutcome:
    invocation: ToolInvocation
    decision: PolicyDecision
    result: EvaluationResult
    approval: Approval | None
    risk: SessionRisk
    analysis: ToolAnalysis
    view: SessionView  # signals including this call (with its final status), reusable for session risk


def decide_request(st: PipelineState, *, started: float, completed: bool = False) -> DecisionOutcome:
    """Evaluate and persist one tool request. ``completed`` marks a call first seen at completion."""
    assert st.agent is not None and st.session is not None and st.env.tool is not None
    env, db, org = st.env, st.db, st.ctx.org_id
    a = analyze_tool_call(st, env.tool, env.arguments)
    invocation_id = new_id("tool_invocation")
    pending = {
        "id": invocation_id, "tool_name": a.tool_name, "category": a.cls.category, "status": "requested",
        "decision": None, "sensitive_resources": a.sensitive_resources,
        "destination_classification": a.destination_assessment.classification if a.destination_assessment else None,
        "outbound": a.outbound, "sensitive_data_detected": bool(a.secrets_in_arguments),
        "matched_session_fingerprints": a.session_secret_matches,
    }
    view = session_view(st, pending=pending)
    risk = compute_session_risk(view.signals)
    inp = build_input(st, a, risk, view.context)
    result = evaluate(inp, st.policies(), default_decision=str(st.settings.get("default_decision") or "ALLOW"))
    result = replace(result, explanation=_prospective_note(result.explanation, view, pending, risk))
    enforcement = st.enforcement

    decision = PolicyDecision(
        id=new_id("policy_decision"), organization_id=org, agent_id=st.agent.id, session_id=st.session.id,
        tool_invocation_id=invocation_id, event_id=st.event.id, decision=result.decision, enforcement=enforcement,
        matched_policies=[m.to_dict() for m in result.matched],
        monitor_matches=[m.to_dict() for m in result.monitor_matches],
        explanation=result.explanation, input_snapshot=inp.to_dict(), evaluated_at=st.now,
        is_simulation=st.ctx.is_simulation,
    )
    status = "requested" if enforcement == "observed" else _STATUS_BY_DECISION.get(result.decision, "allowed")
    pending.update(status=status, decision=result.decision)  # the same dict is in view.signals
    invocation = ToolInvocation(
        id=invocation_id, organization_id=org, agent_id=st.agent.id, session_id=st.session.id, tool_id=a.tool.id,
        request_event_id=st.event.id, correlation_id=env.correlation_id, status=status, decision=result.decision,
        enforcement=enforcement, policy_decision_id=decision.id, arguments_redacted=a.arguments,
        argument_hash=a.argument_hash, resources=a.resources,
        destination_id=a.destination.id if a.destination else None,
        sensitive_data_detected=bool(a.secrets_in_arguments),
        secret_fingerprints=[{"type": f["type"], "fingerprint": f["fingerprint"]} for f in a.all_argument_fingerprints],
        matched_session_fingerprints=a.session_secret_matches, requested_at=st.now,
        is_simulation=st.ctx.is_simulation,
    )
    db.add_all([invocation, decision])
    db.flush()
    st.refs.update({"tool_invocation_id": invocation.id, "policy_decision_id": decision.id, "tool_id": a.tool.id,
                    "decision": result.decision, "enforcement": enforcement,
                    "restrictions": result.restrictions,
                    "risk": {"score": risk.score, "level": risk.level, "trifecta": risk.trifecta}})

    approval = None
    if result.decision == Decision.REQUIRE_APPROVAL and enforcement != "observed":
        approval = create_approval(
            db, org, policy_decision_id=decision.id, tool_invocation_id=invocation.id, agent_id=st.agent.id,
            session_id=st.session.id, summary=approval_summary(st, a), risk_summary=_risk_summary(a, risk, result),
            timeout_s=int(st.settings.get("approval_timeout_s") or 0) or None, is_simulation=st.ctx.is_simulation,
        )
        invocation.approval_id = approval.id
        st.refs["approval_id"] = approval.id
    if not st.ctx.is_simulation:  # simulated calls never inflate a destination's transfer history
        _count_transfer(a, result.decision, enforcement)
    _edges(st, a, invocation, decision)
    if result.decision in (Decision.DENY, Decision.REQUIRE_APPROVAL):
        append_audit(
            db, org, action="tool.denied" if result.decision == Decision.DENY else "tool.approval_required",
            actor_type=st.ctx.actor_type, actor_id=st.ctx.actor_id, target_type="tool_invocation",
            target_id=invocation.id,
            details={"decision": result.decision, "enforcement": enforcement, "tool": a.tool_name,
                     "agent_id": st.agent.id, "session_id": st.session.id, "policy_decision_id": decision.id,
                     "deciding_policy_id": result.deciding_policy_id, "approval_id": approval.id if approval else None},
        )
    record_tool_findings(st, a, invocation, decision, result, completed=completed)
    decision.latency_ms = round((time.perf_counter() - started) * 1000, 3)
    return DecisionOutcome(invocation=invocation, decision=decision, result=result, approval=approval, risk=risk,
                           analysis=a, view=view)


def approval_summary(st: PipelineState, a: ToolAnalysis) -> str:
    agent = st.agent.name if st.agent else "An agent"
    target = a.target
    return f"{agent} wants to {a.tool_name} {target}"[:1000] if target else f"{agent} wants to use {a.tool_name}"


PROSPECTIVE_TRIFECTA_NOTE = (
    " Note: session.trifecta counts this requested call as the session's outbound channel; the session's "
    "recorded trifecta becomes true only if the call runs."
)


def _prospective_note(explanation: str, view: SessionView, pending: dict[str, Any], risk: SessionRisk) -> str:
    """Say so when the trifecta holds only because this (not yet executed) call is counted.

    The request is evaluated as if it ran — that is what is being decided — while the session's
    persisted state counts executed calls only, so an explanation citing ``session.trifecta`` would
    otherwise contradict every other view of a session whose call was held or denied.
    """
    if not risk.trifecta or "session.trifecta" not in explanation:
        return explanation
    others = [i for i in view.signals.tool_invocations if i is not pending]
    if compute_session_risk(replace(view.signals, tool_invocations=others)).trifecta:
        return explanation
    text = explanation.rstrip()
    return text + ("" if text.endswith(".") else ".") + PROSPECTIVE_TRIFECTA_NOTE


def _risk_summary(a: ToolAnalysis, risk: SessionRisk, result: EvaluationResult) -> dict[str, Any]:
    return {
        "session_score": risk.score, "session_level": risk.level, "trifecta": risk.trifecta,
        "session_summary": risk.summary, "tool_category": a.cls.category, "tool_risk": a.cls.risk_level,
        "destination": ({"identifier": a.destination.identifier, "classification": a.destination.classification}
                        if a.destination else None),
        "sensitive_resources": a.sensitive_resources[:20],
        "secrets_in_arguments": len(a.secrets_in_arguments),
        "session_secret_matches": len(a.session_secret_matches),
        "detections": sorted({h.rule_id for h in a.detection.hits}),
        "matched_policies": [m.name for m in result.matched],
        "reason": result.explanation[:2000],
    }


def _count_transfer(a: ToolAnalysis, decision: str, enforcement: str) -> None:
    dest = a.destination
    if dest is None:
        return
    held = decision == Decision.REQUIRE_APPROVAL and enforcement != "observed"
    blocked = decision == Decision.DENY and enforcement == "enforced"
    if blocked:
        dest.blocked_count = (dest.blocked_count or 0) + 1
    elif not held:
        dest.transfer_count = (dest.transfer_count or 0) + 1
        if a.secrets_in_arguments or a.session_secret_matches or a.sensitive_resources:
            dest.sensitive_transfer_count = (dest.sensitive_transfer_count or 0) + 1


def _edges(st: PipelineState, a: ToolAnalysis, invocation: ToolInvocation, decision: PolicyDecision) -> None:
    assert st.session is not None
    add_edge(st, N.SESSION, st.session.id, N.TOOL_INVOCATION, invocation.id, R.SESSION_INVOKED_TOOL)
    add_edge(st, N.TOOL_INVOCATION, invocation.id, N.TOOL, a.tool.id, R.INVOCATION_USED_TOOL)
    for res in a.resources[:50]:
        add_edge(st, N.TOOL_INVOCATION, invocation.id, N.RESOURCE, f"{res.get('kind')}:{res.get('id')}"[:2048],
                 R.INVOCATION_ACCESSED_RESOURCE, metadata={"sensitive": bool(res.get("sensitive")),
                                                           "reason": res.get("reason")})
    if a.destination is not None:
        add_edge(st, N.TOOL_INVOCATION, invocation.id, N.DESTINATION, a.destination.id, R.INVOCATION_SENT_TO,
                 metadata={"classification": a.destination.classification})
    add_edge(st, N.TOOL_INVOCATION, invocation.id, N.POLICY_DECISION, decision.id, R.INVOCATION_DECIDED_BY,
             metadata={"decision": decision.decision, "enforcement": decision.enforcement})
