"""Finding helpers for the ingestion pipeline: plain-language remediation, escalation and audit.

All evidence passed in must already be redacted. ``raise_finding`` records (or de-duplicates) the
finding, escalates qualifying ones to incidents and audits newly created critical findings.
"""

from __future__ import annotations

from typing import Any

from app.domain.enums import FindingCategory, Severity
from app.models import SecurityFinding
from app.services.audit import append_audit
from app.services.findings import record_finding
from app.services.incidents import escalate_finding
from app.services.ingestion_state import PipelineState

F = FindingCategory

REMEDIATION: dict[str, str] = {
    F.PROMPT_INJECTION: (
        "Treat this content as data, not instructions. Review the excerpt and the actions the agent took after "
        "reading it (session timeline). If the source is not needed, classify it BLOCKED in the Trust Center."
    ),
    F.INSTRUCTION_OVERRIDE: (
        "The content tries to replace the agent's instructions. Check whether the agent changed course after "
        "reading it, and block or restrict the source if it is not trustworthy."
    ),
    F.CREDENTIAL_ACCESS: (
        "Confirm the agent needed to touch credential material. If not, rotate the credentials it could reach "
        "and add a policy that denies access to these paths for this agent."
    ),
    F.SECRET_EXPOSURE: (
        "A credential appeared in an outbound call. Rotate it, confirm whether the destination should receive "
        "it, and add the destination to the allowlist only if it is expected."
    ),
    F.EXFILTRATION: (
        "Check whether data actually left (the session's tool calls and decisions): if a credential or private data "
        "was sent, treat it as compromised and rotate it now. Then review how it reached the agent's context and "
        "which content or instruction preceded any outbound call."
    ),
    F.UNTRUSTED_SOURCE: (
        "Content from a source that may not instruct the agent contained instructions. If the source is "
        "legitimate, add a trust rule; otherwise keep it classified as data only or block it."
    ),
    F.SUSPICIOUS_TOOL_USE: (
        "Review the tool call arguments and what preceded them. If the action was not intended, deny it with a "
        "policy and investigate the content the agent consumed before it."
    ),
    F.PERMISSION_ESCALATION: (
        "The agent tried to widen its own permissions or persistence. Verify the change was intended and revert "
        "configuration or persistence changes that were not."
    ),
    F.LETHAL_TRIFECTA: (
        "Remove one leg of the trifecta for this agent: restrict access to sensitive data, keep untrusted content "
        "out of its context, or require approval for outbound calls. This is a risk condition, not proof of an attack."
    ),
    F.CROSS_AGENT_CONTAMINATION: (
        "Review what the receiving agent did with content that came from a session with prompt-injection "
        "detections, and treat its outputs as untrusted until reviewed."
    ),
    F.POLICY_VIOLATION: (
        "Review why the agent attempted this action. Where the integration does not enforce decisions, switch to "
        "an enforcing integration (Claude Code hooks, MCP gateway or SDK guard)."
    ),
    F.DESTINATION_RISK: (
        "Verify whether data should go to this destination. Block it with a trust rule if not, or allowlist it "
        "explicitly if it is a legitimate service."
    ),
}


def remediation_for(category: str) -> str | None:
    return REMEDIATION.get(category)


def raise_finding(
    st: PipelineState,
    *,
    category: str,
    rule_id: str,
    title: str,
    explanation: str,
    severity: str,
    confidence: float,
    evidence: list[dict[str, Any]],
    session_id: str | None = None,
    agent_id: str | None = None,
    source_id: str | None = None,
    context_item_id: str | None = None,
    tool_invocation_id: str | None = None,
    policy_decision_id: str | None = None,
    destination_id: str | None = None,
    remediation: str | None = None,
) -> tuple[SecurityFinding, bool]:
    assert st.session is not None and st.agent is not None
    finding, created = record_finding(
        st.db,
        st.ctx.org_id,
        category=category,
        rule_id=rule_id,
        title=st.scrub(title) or title,
        explanation=st.scrub(explanation) or explanation,
        severity=severity,
        confidence=confidence,
        evidence=[_scrub_evidence(st, e) for e in evidence],
        agent_id=agent_id or st.agent.id,
        session_id=session_id or st.session.id,
        source_id=source_id,
        context_item_id=context_item_id,
        tool_invocation_id=tool_invocation_id,
        policy_decision_id=policy_decision_id,
        destination_id=destination_id,
        remediation=remediation if remediation is not None else remediation_for(category),
        is_simulation=st.ctx.is_simulation,
    )
    st.add_ref("finding_ids", finding.id)
    incident = escalate_finding(st.db, finding)
    if incident is not None:
        st.add_ref("incident_ids", incident.id)
    elif finding.incident_id:
        st.add_ref("incident_ids", finding.incident_id)
    if created and finding.severity == Severity.CRITICAL:
        append_audit(
            st.db, st.ctx.org_id, action="finding.critical", actor_type="system",
            target_type="finding", target_id=finding.id,
            details={"category": category, "rule_id": rule_id, "session_id": finding.session_id,
                     "agent_id": finding.agent_id, "event_id": st.event.id},
        )
    return finding, created


def _scrub_evidence(st: PipelineState, item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    for key in ("excerpt", "detail"):
        if isinstance(out.get(key), str):
            out[key] = st.scrub(out[key])
    return out
