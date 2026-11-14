"""Deterministic root-cause hypotheses derived from recorded finding categories and evidence.

Nothing here is a conclusion. Each hypothesis carries a confidence *word* computed from how much
recorded evidence supports it:

- ``likely``      — two or more findings of the category, or a high/critical finding with evidence;
- ``possible``    — a single supporting record;
- ``speculative`` — inferred from the task type alone, with no supporting record.

Provenance paths are deliberately not used as support: they are observed relationships, not
proof of causation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.domain.enums import SEVERITY_RANK
from app.workspace.text import inline

CONFIDENCE_WORDS = ("likely", "possible", "speculative")

# category -> (statement, how to test)
_CATEGORY_HYPOTHESES: dict[str, tuple[str, str]] = {
    "prompt_injection": (
        "Content from an untrusted source reaches the agent's instruction channel without being marked as data, "
        "so embedded instructions can steer the agent.",
        "Trace the recorded content from its source to the prompt; check whether a trust label or boundary is "
        "applied before the model sees it, and replay the payload against that path.",
    ),
    "instruction_override": (
        "Retrieved or tool-returned content can override system or developer instructions because instruction "
        "precedence is not enforced where context is assembled.",
        "Find where context is assembled for the model and check whether lower-trust content can appear in a "
        "position or format that the agent treats as instructions.",
    ),
    "credential_access": (
        "The agent's file or tool permissions reach credential stores; path deny-lists or tool scopes are broader "
        "than the task requires.",
        "List the agent's allowed tools and paths and try the recorded access (and traversal or symlink variants) "
        "in a sandbox.",
    ),
    "secret_exposure": (
        "A secret is present in content the agent can read or emit, and redaction is not applied at that boundary.",
        "Identify the channel where the secret appeared (file, log, tool output, response) and check whether "
        "redaction runs before that content is stored or forwarded.",
    ),
    "exfiltration": (
        "An outbound channel is reachable after sensitive data entered the session, and no destination allow-list "
        "or policy blocks the transfer.",
        "Check which policy and destination-trust rules apply to the recorded outbound call and whether the "
        "integration enforces the decision before the call runs.",
    ),
    "untrusted_source": (
        "The source is unclassified or classified as more trusted than it should be, so its content is not "
        "treated with the caution its origin warrants.",
        "Look up the source's trust classification and the trust rules that matched it; test the rule set with "
        "the recorded source identifier.",
    ),
    "suspicious_tool_use": (
        "Tool arguments are not constrained, so the agent can issue dangerous calls (for example destructive "
        "shell flags or unexpected targets) that pass validation.",
        "Compare the recorded tool arguments with the validation and policy rules for that tool.",
    ),
    "dangerous_permissions": (
        "The agent or one of its tools is configured with more privilege than the task needs.",
        "Compare the agent's configured tools, scopes and paths with what the task actually requires.",
    ),
    "lethal_trifecta": (
        "One session combines access to private data, exposure to untrusted content and an outbound channel, and "
        "no policy breaks any of the three legs.",
        "Confirm each leg from the session evidence and check which policies evaluate the combination.",
    ),
    "anomaly": (
        "Behaviour deviates from this agent's recorded baseline, possibly because of a configuration change, a new "
        "tool or manipulated context.",
        "Diff the agent's recent configuration, tools and context sources against an earlier normal session.",
    ),
    "cross_agent_contamination": (
        "Output from one agent is passed to another without its trust label, so untrusted content is laundered "
        "through delegation.",
        "Follow the delegation hand-off and check whether trust labels survive from the producing session to the "
        "consuming one.",
    ),
    "policy_violation": (
        "The action is not stopped at an enforcement boundary: either the integration only observes this tool, or "
        "the policy conditions do not match the recorded input.",
        "Re-evaluate the recorded policy input snapshot against the current policy set and check the integration's "
        "enforcement mode for this tool.",
    ),
    "destination_risk": (
        "Data can be sent to a destination that is unverified or resembles a trusted one, because destination "
        "checks do not cover this host or URL form.",
        "Check the destination's trust record and test lookalike, IP-literal and redirect variants of the URL.",
    ),
    "permission_escalation": (
        "The agent obtained capabilities beyond its configured scope, for example through a delegated agent or a "
        "tool that returns elevated credentials.",
        "Trace where the extra capability first appears in the session and which component granted it.",
    ),
}

# Task-type fallbacks, used only when no finding supports any hypothesis.
_TASK_TYPE_HYPOTHESES: dict[str, list[str]] = {
    "prompt_injection": ["prompt_injection"],
    "data_exposure": ["secret_exposure"],
    "agent_misconfiguration": ["dangerous_permissions"],
}
_TASK_TYPE_GENERIC: dict[str, tuple[str, str]] = {
    "integration_bug": (
        "The integration and the server disagree about the event contract (field names, required fields, version) "
        "or about error and timeout handling.",
        "Capture a real request from the integration and validate it against the contract; replay it against the "
        "server and compare responses.",
    ),
    "performance": (
        "A hot path repeats work: an N+1 query pattern, a missing index, an unbounded loop or a missing cache.",
        "Profile the slow operation with realistic data; record query counts and the slowest call stacks before "
        "changing anything.",
    ),
    "security_vulnerability": (
        "Input crosses a trust boundary without validation before reaching a sensitive operation.",
        "Identify the trust boundary the vulnerable input crosses and check what validation runs there.",
    ),
}


@dataclass(frozen=True)
class Hypothesis:
    statement: str
    confidence: str
    basis: str
    how_to_test: str
    sources: tuple[str, ...]


def _confidence(count: int, max_rank: int, has_evidence: bool) -> str:
    if count >= 2 or (max_rank >= SEVERITY_RANK["high"] and has_evidence):
        return "likely"
    return "possible"


def derive_hypotheses(
    *,
    task: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    policies: Sequence[Mapping[str, Any]],
    previous_attempts: Sequence[Mapping[str, Any]],
    verification_runs: Sequence[Mapping[str, Any]],
) -> list[Hypothesis]:
    """Ordered (most supported first), de-duplicated hypotheses. Deterministic for identical input."""
    groups: dict[str, dict[str, Any]] = {}
    for f in findings:
        category = f.get("category")
        if category not in _CATEGORY_HYPOTHESES:
            continue
        g = groups.setdefault(category, {"count": 0, "rank": 0, "evidence": False, "ids": [], "titles": []})
        g["count"] += 1
        g["rank"] = max(g["rank"], SEVERITY_RANK.get(str(f.get("severity")), 0))
        g["evidence"] = g["evidence"] or bool(f.get("evidence"))
        if f.get("id"):
            g["ids"].append(f"finding:{f['id']}")
        if f.get("title"):
            g["titles"].append(inline(f["title"], 120))

    out: list[Hypothesis] = []
    order = sorted(groups.items(), key=lambda kv: (-kv[1]["count"], -kv[1]["rank"], kv[0]))
    for category, g in order:
        statement, test = _CATEGORY_HYPOTHESES[category]
        named = "; ".join(g["titles"][:3])
        basis = (
            f"{g['count']} recorded finding(s) in category '{category.replace('_', ' ')}'"
            + (f": {named}" if named else "")
            + ("" if g["evidence"] else " (no evidence excerpts attached)")
        )
        out.append(
            Hypothesis(
                statement,
                _confidence(g["count"], g["rank"], g["evidence"]),
                basis + ".",
                test,
                tuple(g["ids"]),
            )
        )

    out.extend(_policy_gap(findings, policies))
    out.extend(_failed_attempts(previous_attempts, verification_runs))

    if not out:
        out.extend(_from_task_type(str(task.get("task_type") or "")))
    return out


def _policy_gap(
    findings: Sequence[Mapping[str, Any]], policies: Sequence[Mapping[str, Any]]
) -> list[Hypothesis]:
    allowed = [p for p in policies if str(p.get("outcome", "")).upper() == "ALLOW"]
    if not allowed or not findings:
        return []
    names = ", ".join(inline(p.get("name") or p.get("id") or "policy", 80) for p in allowed[:3])
    return [
        Hypothesis(
            "Existing policies do not cover the behaviour behind the linked findings: the recorded decisions allowed it.",
            "possible",
            f"Recorded policy outcome ALLOW from: {names}, alongside {len(findings)} linked finding(s).",
            "Re-run the recorded decision input through the policy test endpoint with a candidate rule and confirm it "
            "changes the outcome without blocking legitimate calls.",
            tuple(f"policy:{p['id']}" for p in allowed if p.get("id")),
        )
    ]


def _failed_attempts(
    attempts: Sequence[Mapping[str, Any]], runs: Sequence[Mapping[str, Any]]
) -> list[Hypothesis]:
    failed_runs = [r for r in runs if str(r.get("status")) in ("failed", "error")]
    failed_attempts = [a for a in attempts if str(a.get("status")) in ("failed", "abandoned")]
    if not failed_runs and not failed_attempts:
        return []
    refs = tuple(
        [f"verification_run:{r['id']}" for r in failed_runs if r.get("id")]
        + [f"fix_attempt:{a['id']}" for a in failed_attempts if a.get("id")]
    )
    detail = inline(failed_runs[0].get("summary") or "", 200) if failed_runs else ""
    basis = (
        f"{len(failed_attempts)} failed or abandoned fix attempt(s) and {len(failed_runs)} failed verification "
        f"run(s) are recorded" + (f"; latest failure: {detail}" if detail else "") + "."
    )
    return [
        Hypothesis(
            "An earlier fix addressed a symptom rather than the root cause, or the change does not cover every path "
            "that triggers the issue.",
            "possible" if len(refs) == 1 else "likely",
            basis,
            "Compare what the earlier attempt changed with the paths in the reproduction; run the failed verification "
            "again before changing code.",
            refs,
        )
    ]


def _from_task_type(task_type: str) -> list[Hypothesis]:
    basis = f"Inferred from the task type '{task_type.replace('_', ' ')}' only; no recorded evidence supports it yet."
    out = [
        Hypothesis(_CATEGORY_HYPOTHESES[c][0], "speculative", basis, _CATEGORY_HYPOTHESES[c][1], ())
        for c in _TASK_TYPE_HYPOTHESES.get(task_type, [])
    ]
    if task_type in _TASK_TYPE_GENERIC:
        statement, test = _TASK_TYPE_GENERIC[task_type]
        out.append(Hypothesis(statement, "speculative", basis, test, ()))
    return out
