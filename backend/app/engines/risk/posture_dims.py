"""The nine posture dimensions (pure). Maximums sum to 100; see ``posture.compute_agent_posture``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.domain.enums import ToolCategory
from app.engines.risk import policy_refs as pr

if TYPE_CHECKING:
    from app.engines.risk.posture import PostureInputs

C = ToolCategory

MAX = {
    "permission_exposure": 15,
    "source_trust": 10,
    "sensitive_data_controls": 15,
    "enforcement_coverage": 10,
    "policy_coverage": 10,
    "approval_controls": 10,
    "detection_coverage": 10,
    "unresolved_findings": 10,
    "trifecta_exposure": 10,
}

HIGH_RISK_CAPS = {C.SHELL, C.CODE_EXECUTION, C.INFRASTRUCTURE}
OUTBOUND_CAPS = {C.EMAIL, C.MESSAGING, C.HTTP, C.BROWSER, C.MCP, C.SEARCH}
COST_HIGH, COST_HIGH_PROD, COST_OUTBOUND, COST_UNDECLARED, MAX_UNDECLARED = 4, 5, 2, 1, 3
FINDING_PENALTY = {"critical": 5, "high": 3, "medium": 1}
NOT_ASSESSED = "Not assessed yet"

_SECRET_FIELDS = ("secrets_in_arguments", "session_secret_matches")
_SENSITIVE_RESOURCE_FIELDS = ("sensitive_resources", "resources")
_DETECTION_FIELDS = ("detection", "context.injection_detected", "context.max_detection_severity")
_TRUST_FIELDS = (
    "context.lowest_trust",
    "context.untrusted_item_count",
    "context.suspicious_source_ids",
    "session.trifecta",
    "session.untrusted_exposure",
    "destination.classification",
)
_GATING = {"DENY", "REQUIRE_APPROVAL"}
_HEALTHY = {"active", "connected", "healthy", "ok", "online"}


@dataclass
class PostureDimension:
    key: str
    label: str
    score: int
    max_score: int
    explanation: str
    evidence: list[dict[str, str]] = field(default_factory=list)
    recommendation: str | None = None


def _ev(kind: str, ident: Any, detail: str) -> dict[str, str]:
    return {"type": kind, "id": str(ident or ""), "detail": detail}


def _policy_ev(p: dict[str, Any], detail: str) -> dict[str, str]:
    return _ev("policy", p.get("id"), f"{p.get('name') or p.get('id')}: {detail}")


def _mode(p: dict[str, Any]) -> str:
    return "enforce" if pr.is_enforced(p) else "monitor"


def permission_exposure(inputs: PostureInputs, caps: list[dict[str, Any]]) -> PostureDimension:
    key, mx = "permission_exposure", MAX["permission_exposure"]
    if not caps:
        return PostureDimension(
            key,
            "Permission exposure",
            mx,
            mx,
            "No tools declared or observed, so the agent has no tool permissions to assess.",
            [],
        )
    prod = str(inputs.agent.get("environment") or "").lower() == "production"
    by_cat: dict[str, list[str]] = {}
    for cap in caps:
        by_cat.setdefault(cap["category"], []).append(cap["name"])
    high = sorted(c for c in by_cat if c in HIGH_RISK_CAPS)
    outbound = sorted(
        c for c in by_cat if c in OUTBOUND_CAPS and any(x["outbound"] for x in caps if x["category"] == c)
    )
    declared = {str(t.get("name")) for t in inputs.declared_tools if t.get("name")}
    undeclared = [c["name"] for c in caps if declared and c["source"] == "observed"]
    cost_high = COST_HIGH_PROD if prod else COST_HIGH
    penalty = (
        cost_high * len(high)
        + COST_OUTBOUND * len(outbound)
        + min(MAX_UNDECLARED, COST_UNDECLARED * len(undeclared))
    )
    evidence = [
        _ev("tool_category", c, f"high-risk capability via {', '.join(sorted(by_cat[c])[:4])} (-{cost_high})")
        for c in high
    ]
    evidence += [
        _ev("tool_category", c, f"outbound channel via {', '.join(sorted(by_cat[c])[:4])} (-{COST_OUTBOUND})")
        for c in outbound
    ]
    evidence += [
        _ev("tool", n, "used but not declared in the agent's configuration") for n in undeclared[:10]
    ]
    score = max(0, mx - penalty)
    parts = []
    if high:
        parts.append(
            f"{len(high)} high-risk capabilit{'y' if len(high) == 1 else 'ies'} ({', '.join(high)}; "
            f"{cost_high} points each{' in production' if prod else ''})"
        )
    if outbound:
        parts.append(
            f"{len(outbound)} outbound channel{'s' if len(outbound) != 1 else ''} ({', '.join(outbound)}; "
            f"{COST_OUTBOUND} each)"
        )
    if undeclared:
        parts.append(
            f"{len(undeclared)} tool(s) used without being declared ({COST_UNDECLARED} each, max "
            f"{MAX_UNDECLARED})"
        )
    explanation = (
        ("The agent can use " + "; ".join(parts) + ".")
        if parts
        else (f"The agent's {len(caps)} tool(s) are low-risk and cannot send data out.")
    )
    rec = None
    if penalty:
        rec = (
            "Remove tools the agent does not need, gate shell/code execution/infrastructure behind approval "
            "policies, and declare every tool so unexpected usage stands out."
        )
    return PostureDimension(key, "Permission exposure", score, mx, explanation, evidence, rec)


def source_trust(inputs: PostureInputs) -> PostureDimension:
    key, mx = "source_trust", MAX["source_trust"]
    evidence = [
        _ev("trust_rules", "count", f"{inputs.trust_rule_count} enabled trust rule(s)"),
        _ev("sources", "untrusted", f"{inputs.untrusted_source_count} untrusted source(s) consumed"),
    ]
    if inputs.trust_rule_count <= 0:
        score = 3
        explanation = (
            "No trust rules are configured, so every source defaults to UNKNOWN and repositories you own "
            "are treated like the open web (3 of 10 points: classification still happens by default)."
        )
        rec = "Add trust rules for first-party repositories, internal documentation and approved MCP servers."
    else:
        score, explanation, rec = mx, f"{inputs.trust_rule_count} trust rule(s) classify sources.", None
    if inputs.untrusted_source_count > 0:
        deduction = 4 if inputs.untrusted_source_count >= 10 else 2
        score = max(0, score - deduction)
        explanation += (
            f" The agent consumed {inputs.untrusted_source_count} source(s) that are not trusted "
            f"(-{deduction}); their content is treated as data, never instructions."
        )
        rec = (
            rec
            or "Review the untrusted sources this agent consumed and add trust rules for the ones you own."
        )
    return PostureDimension(key, "Source trust configuration", score, mx, explanation, evidence, rec)


def sensitive_data_controls(policies: list[dict[str, Any]]) -> PostureDimension:
    key, mx = "sensitive_data_controls", MAX["sensitive_data_controls"]
    cred = [p for p in policies if pr.outcome(p) in _GATING and pr.references_field(p, _SECRET_FIELDS)]
    res = [
        p
        for p in policies
        if pr.outcome(p) in _GATING | {"RESTRICT"} and pr.references_field(p, _SENSITIVE_RESOURCE_FIELDS)
    ]
    cred_enforced = [p for p in cred if pr.is_enforced(p)]
    res_enforced = [p for p in res if pr.is_enforced(p)]
    cred_pts = 10 if cred_enforced else (4 if cred else 0)
    res_pts = 5 if res_enforced else (2 if res else 0)
    evidence = [_policy_ev(p, f"blocks/gates calls carrying credentials ({_mode(p)})") for p in cred]
    evidence += [_policy_ev(p, f"acts on sensitive resources ({_mode(p)})") for p in res]
    explanation = (
        "A credential-exfiltration policy is enforced (10/10)."
        if cred_enforced
        else "A credential-exfiltration policy exists only in monitor mode, so it records but never blocks (4/10)."
        if cred
        else "No enabled policy denies or gates tool calls whose arguments carry credentials (0/10)."
    ) + (
        " Sensitive-resource access is enforced by policy (5/5)."
        if res_enforced
        else " Sensitive-resource policies run in monitor mode only (2/5)."
        if res
        else " No policy acts on sensitive resources such as .env files or keys (0/5)."
    )
    rec = None
    if not cred_enforced:
        rec = "Enable the credential-exfiltration policy (secrets_in_arguments / session_secret_matches) in enforce mode."
    elif not res_enforced:
        rec = "Add an enforce-mode policy that requires approval when sensitive_resources is not empty."
    return PostureDimension(
        key, "Sensitive-data controls", cred_pts + res_pts, mx, explanation, evidence, rec
    )


def enforcement_coverage(integration: dict[str, Any]) -> PostureDimension:
    key, mx, label = "enforcement_coverage", MAX["enforcement_coverage"], "Integration & enforcement coverage"
    kind = integration.get("kind")
    if not kind:
        return PostureDimension(
            key,
            label,
            0,
            mx,
            "No integration is connected for this agent, so ContextOS can "
            "neither observe nor enforce its tool calls.",
            [],
            "Connect the agent through the Claude Code hooks, the MCP gateway or the SDK guard().",
        )
    status = str(integration.get("status") or "unknown").lower()
    healthy = status in _HEALTHY
    enforces = bool(integration.get("supports_enforcement"))
    evidence = [
        _ev(
            "integration",
            kind,
            f"status {status}; "
            f"{'enforces decisions before tools run' if enforces else 'advisory/observed only'}",
        )
    ]
    if enforces:
        score = mx if healthy else 5
        explanation = (
            f"The {kind} integration enforces decisions at a real execution boundary (enforced)."
            if healthy
            else f"The {kind} integration can enforce, but its status is '{status}', so "
            "events may be missing (5/10)."
        )
        rec = None if healthy else f"Restore the {kind} integration; check its API key and connectivity."
    else:
        score = 4 if healthy else 2
        explanation = (
            f"The {kind} integration reports events but cannot block tool calls: decisions are advisory "
            "or observed only, so nothing can be prevented."
        )
        rec = "Use an enforcing integration (Claude Code PreToolUse hook, MCP gateway or SDK guard())."
    return PostureDimension(key, label, score, mx, explanation, evidence, rec)


def _coverage_by_category(
    caps: list[dict[str, Any]], policies: list[dict[str, Any]], outcomes: set[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for p in policies:
        if outcomes is not None and pr.outcome(p) not in outcomes:
            continue
        for cat in pr.covered_categories(p, caps):
            out.setdefault(cat, []).append(p)
    return out


def policy_coverage(caps: list[dict[str, Any]], policies: list[dict[str, Any]]) -> PostureDimension:
    key, mx = "policy_coverage", MAX["policy_coverage"]
    observed = sorted({c["category"] for c in caps if "observed" in c["source"] and c["category"] != C.OTHER})
    basis = "observed"
    if not observed:
        observed = sorted({c["category"] for c in caps if c["category"] != C.OTHER})
        basis = "declared"
    if not observed:
        return PostureDimension(
            key,
            "Policy coverage",
            mx,
            mx,
            f"{NOT_ASSESSED}: no tool categories declared or observed to cover.",
            [],
        )
    cover = _coverage_by_category(caps, policies)
    total, evidence, uncovered = 0.0, [], []
    for cat in observed:
        ps = cover.get(cat, [])
        if any(pr.is_enforced(p) for p in ps):
            total += 1
            evidence.append(
                _ev("tool_category", cat, "covered by " + ", ".join(str(p.get("name")) for p in ps[:3]))
            )
        elif ps:
            total += 0.5
            evidence.append(
                _ev("tool_category", cat, "monitor-only: " + ", ".join(str(p.get("name")) for p in ps[:3]))
            )
        else:
            uncovered.append(cat)
            evidence.append(_ev("tool_category", cat, "no enabled policy targets this category"))
    score = round(mx * total / len(observed))
    explanation = (
        f"{total:g} of {len(observed)} {basis} tool categor{'y' if len(observed) == 1 else 'ies'} are "
        "targeted by an enabled policy (via tool.category, tool.name or tool.risk_level; monitor-only "
        "coverage counts half)."
    )
    rec = (
        f"Add policies for: {', '.join(uncovered)}."
        if uncovered
        else (
            "Switch monitor-only policies to enforce once their decisions look right." if score < mx else None
        )
    )
    return PostureDimension(key, "Policy coverage", score, mx, explanation, evidence, rec)


def approval_controls(
    inputs: PostureInputs, caps: list[dict[str, Any]], policies: list[dict[str, Any]]
) -> PostureDimension:
    key, mx = "approval_controls", MAX["approval_controls"]
    needing = sorted(
        {
            c["category"]
            for c in caps
            if c["category"] in HIGH_RISK_CAPS or (c["category"] in {C.EMAIL, C.MESSAGING} and c["outbound"])
        }
    )
    if not needing:
        return PostureDimension(
            key,
            "Approval controls",
            mx,
            mx,
            "The agent has no high-risk capability that would need human approval.",
            [],
        )
    approvals = [p for p in policies if pr.outcome(p) == "REQUIRE_APPROVAL"]
    has_approvals = max(inputs.approval_policy_count, len(approvals)) > 0
    gated = _coverage_by_category(caps, [p for p in policies if pr.is_enforced(p)], _GATING)
    covered = [c for c in needing if c in gated]
    missing = [c for c in needing if c not in gated]
    if not has_approvals and not covered:
        return PostureDimension(
            key,
            "Approval controls",
            0,
            mx,
            f"No approval policies exist, yet the agent can use "
            f"{', '.join(needing)} without a human in the loop.",
            [_ev("tool_category", c, "no approval or deny policy") for c in needing],
            f"Require approval for {', '.join(needing)} (at least in production).",
        )
    score = (3 if has_approvals else 0) + round(7 * len(covered) / len(needing))
    evidence = [
        _ev("tool_category", c, "gated by " + ", ".join(str(p.get("name")) for p in gated[c][:3]))
        if c in gated
        else _ev("tool_category", c, "no enforce-mode approval or deny policy")
        for c in needing
    ]
    explanation = (
        (
            "Approval policies exist (3 points); "
            if has_approvals
            else "No approval policies exist (0 of 3 points); "
        )
        + f"{len(covered)} of {len(needing)} high-risk capabilities are targeted by an "
        "enforce-mode approval or deny policy (7 points pro rata)."
    )
    rec = None
    if missing:
        rec = f"Require approval for: {', '.join(missing)}."
    elif not has_approvals:
        rec = "Add a REQUIRE_APPROVAL policy so risky calls can proceed with a human decision instead of a hard deny."
    return PostureDimension(key, "Approval controls", score, mx, explanation, evidence, rec)


def detection_coverage(policies: list[dict[str, Any]]) -> PostureDimension:
    key, mx = "detection_coverage", MAX["detection_coverage"]
    det = [
        p
        for p in policies
        if pr.outcome(p) in _GATING | {"RESTRICT"} and pr.references_field(p, _DETECTION_FIELDS)
    ]
    trust = [
        p
        for p in policies
        if pr.outcome(p) in _GATING | {"RESTRICT"} and pr.references_field(p, _TRUST_FIELDS)
    ]
    det_pts = 6 if any(pr.is_enforced(p) for p in det) else (3 if det else 0)
    trust_pts = 4 if any(pr.is_enforced(p) for p in trust) else (2 if trust else 0)
    evidence = [_policy_ev(p, f"acts on detection results ({_mode(p)})") for p in det]
    evidence += [
        _policy_ev(p, f"acts on context/destination trust or trifecta state ({_mode(p)})") for p in trust
    ]
    explanation = (
        "Detection runs on all ingested content and tool calls; this measures whether its results can "
        f"change a decision. Injection/detection-aware policies: {det_pts}/6. Trust- or "
        f"trifecta-aware policies: {trust_pts}/4 (monitor-only earns half)."
    )
    rec = None
    if det_pts < 6:
        rec = "Enforce a policy that gates outbound calls when context.injection_detected is true."
    elif trust_pts < 4:
        rec = "Enforce a policy on session.trifecta or destination.classification for outbound tools."
    return PostureDimension(key, "Detection coverage", det_pts + trust_pts, mx, explanation, evidence, rec)


def unresolved_findings(findings: list[dict[str, Any]]) -> PostureDimension:
    key, mx = "unresolved_findings", MAX["unresolved_findings"]
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    penalty = sum(FINDING_PENALTY.get(sev, 0) * n for sev, n in counts.items())
    score = max(0, mx - penalty)
    evidence = [
        _ev("finding", f.get("id"), f"open {f.get('severity')} {f.get('category') or 'finding'}")
        for f in findings[:10]
    ]
    if not findings:
        return PostureDimension(key, "Unresolved findings", mx, mx, "No open findings for this agent.", [])
    breakdown = ", ".join(
        f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: -FINDING_PENALTY.get(kv[0], 0))
    )
    explanation = (
        f"{len(findings)} open finding(s): {breakdown}. Penalty: critical 5, high 3, medium 1, "
        "low/info 0 points each."
    )
    rec = (
        "Triage open findings, starting with the most severe; resolve or mark false positives."
        if penalty
        else None
    )
    return PostureDimension(key, "Unresolved findings", score, mx, explanation, evidence, rec)


def trifecta_exposure(with_trifecta: int, total: int) -> PostureDimension:
    key, mx = "trifecta_exposure", MAX["trifecta_exposure"]
    if total <= 0:
        return PostureDimension(
            key, "Trifecta exposure", mx, mx, f"{NOT_ASSESSED}: no sessions recorded.", []
        )
    with_trifecta = max(0, min(with_trifecta, total))
    score = round(mx * (1 - with_trifecta / total))
    if with_trifecta:
        score = min(score, mx - 3)
    explanation = (
        f"{with_trifecta} of {total} session(s) had sensitive data access, untrusted content and an "
        "outbound channel at the same time — a risk condition, not proof of an attack."
        + (" Any such session caps this dimension at 7." if with_trifecta else "")
    )
    evidence = [_ev("sessions", "trifecta", f"{with_trifecta}/{total} sessions with all three conditions")]
    rec = (
        (
            "Split tasks that read untrusted content from tasks that touch secrets, or require approval for outbound "
            "calls when session.trifecta is true."
        )
        if with_trifecta
        else None
    )
    return PostureDimension(key, "Trifecta exposure", score, mx, explanation, evidence, rec)
