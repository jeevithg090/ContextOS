"""Findings raised by tool requests: credentials in outbound calls, risky destinations, suspicious
tool use detected in the arguments, and policy DENY decisions.

Wording is honest about enforcement: "blocked" only when the decision was returned at an enforcing
integration; advisory and observed decisions say the call may have run, or did run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.domain.enums import Decision, FindingCategory, Severity, TrustLevel
from app.engines.policy import EvaluationResult
from app.models import PolicyDecision, ToolInvocation
from app.services.ingestion_findings import raise_finding
from app.services.ingestion_state import PipelineState

if TYPE_CHECKING:  # pragma: no cover - typing only (avoids an import cycle)
    from app.services.ingestion_tools import ToolAnalysis

F = FindingCategory
_SAFE = frozenset({TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value})
_RISKY = {TrustLevel.BLOCKED.value: Severity.HIGH.value, TrustLevel.SUSPICIOUS.value: Severity.MEDIUM.value}


def enforcement_phrase(st: PipelineState, decision: str, enforcement: str) -> str:
    if enforcement == "enforced":
        if decision == Decision.DENY:
            return "ContextOS returned DENY to an enforcing integration, so the call was blocked before it ran."
        if decision == Decision.REQUIRE_APPROVAL:
            return "The call is held at an enforcing integration until a person approves or rejects it."
        if decision == Decision.RESTRICT:
            return "The call was allowed only with restrictions applied by the integration."
        return f"ContextOS returned {decision}, so the call was allowed to run."
    if enforcement == "advisory":
        return (f"ContextOS returned {decision}, but the '{st.integration_kind}' integration may not enforce "
                "decisions, so the call may have run anyway.")
    return f"This call was reported after the fact (would have been {decision}); nothing was prevented."


def _invocation_evidence(a: ToolAnalysis, inv: ToolInvocation, decision: PolicyDecision) -> dict[str, Any]:
    target = f" → {a.target}" if a.target else ""
    return {"type": "tool_invocation", "id": inv.id, "excerpt": None,
            "detail": f"{a.tool_name} ({a.cls.category}){target}; decision {decision.decision} ({decision.enforcement})"}


def record_tool_findings(
    st: PipelineState, a: ToolAnalysis, inv: ToolInvocation, decision: PolicyDecision, result: EvaluationResult,
    *, completed: bool = False,
) -> None:
    phrase = enforcement_phrase(st, decision.decision, decision.enforcement)
    base = _invocation_evidence(a, inv, decision)
    dest_cls = a.destination.classification if a.destination else None
    dest_ev = ([{"type": "destination", "id": a.destination.id, "excerpt": None,
                 "detail": f"{a.destination.identifier} classified {dest_cls}"}] if a.destination else [])
    common = {"tool_invocation_id": inv.id, "policy_decision_id": decision.id,
              "destination_id": a.destination.id if a.destination else None}

    if a.outbound and (a.secrets_in_arguments or a.session_secret_matches) and dest_cls not in _SAFE:
        where = f"to {a.destination.identifier}" if a.destination else f"through {a.tool_name}"
        attempted = "attempted to send" if decision.decision == Decision.DENY and decision.enforcement == "enforced" \
            else "sent"
        if a.session_secret_matches:
            types = ", ".join(sorted({m["type"] for m in a.session_secret_matches}))
            evidence = [base, *dest_ev] + [
                {"type": "context_item", "id": m["context_item_id"], "excerpt": None,
                 "detail": f"{m['type']} first observed here (fingerprint {m['fingerprint'][:8]})"}
                for m in a.session_secret_matches[:10]
            ]
            raise_finding(
                st, category=F.EXFILTRATION.value, rule_id="CTX-CRED-FLOW-001",
                title=f"Credential read in this session {attempted} {where}"[:400],
                explanation=(
                    f"The arguments of an outbound {a.tool_name} call contain {len(a.session_secret_matches)} "
                    f"secret(s) ({types}) that this session previously read from its context, matched by keyed "
                    f"fingerprint (the secret itself is never stored). The destination is classified "
                    f"{dest_cls or 'as unknown'}. {phrase}"
                ),
                severity=Severity.CRITICAL.value, confidence=0.95, evidence=evidence, **common,
            )
        else:
            types = ", ".join(sorted({s["type"] for s in a.secrets_in_arguments}))
            raise_finding(
                st, category=F.SECRET_EXPOSURE.value, rule_id="CTX-SECRET-OUTBOUND-001",
                title=f"Credential in outbound {a.tool_name} call {where}"[:400],
                explanation=(
                    f"The arguments of an outbound call contain a credential ({types}; redacted before storage). "
                    f"The destination is classified {dest_cls or 'as unknown'}, not trusted or approved. {phrase}"
                ),
                severity=Severity.HIGH.value, confidence=0.85, evidence=[base, *dest_ev], **common,
            )

    if a.destination is not None and dest_cls in _RISKY:
        reasons = " ".join((a.destination_assessment.reasons if a.destination_assessment else [])[:4])
        raise_finding(
            st, category=F.DESTINATION_RISK.value, rule_id="CTX-DEST-001",
            title=f"{a.tool_name} targets a {dest_cls} destination: {a.destination.identifier}"[:400],
            explanation=f"{reasons} {phrase}".strip(),
            severity=_RISKY[dest_cls], confidence=0.8,
            evidence=[base, *dest_ev] + [
                {"type": "destination", "id": a.destination.id, "excerpt": None,
                 "detail": f"check {c.get('check')}: {c.get('result')} — {c.get('detail')}"}
                for c in (a.destination.verification or []) if c.get("result") in ("fail", "warn")
            ][:6],
            **common,
        )

    for hit in a.detection.hits:
        raise_finding(
            st, category=hit.category, rule_id=hit.rule_id,
            title=f"{hit.title}: {a.tool_name}"[:400],
            explanation=f"{hit.explanation} {phrase}",
            severity=hit.severity, confidence=hit.confidence,
            evidence=[{**base, "excerpt": hit.excerpt}, *dest_ev], **common,
        )

    if decision.decision == Decision.DENY and result.matched:
        top = result.matched[0]
        verb = "was denied by" if decision.enforcement == "enforced" else "violated"
        raise_finding(
            st, category=F.POLICY_VIOLATION.value, rule_id=f"policy:{top.policy_id}"[:100],
            title=f"{a.tool_name} {verb} policy '{top.name}'"[:400],
            explanation=f"{top.explanation}. {phrase}" + (" The call was first reported when it completed." if completed else ""),
            severity=top.severity if top.severity in {s.value for s in Severity} else Severity.MEDIUM.value,
            confidence=0.9, evidence=[base, {"type": "policy_decision", "id": decision.id, "excerpt": None,
                                             "detail": decision.explanation[:500]}],
            **common,
        )
