"""Presentation helpers for the Approval Centre (pure; no database access).

They turn recorded rows into plain language: what the paused call would do, which policy paused
it, the risk recorded when the request was opened and what approving or rejecting actually does
for the integration that asked. Inputs are always the persisted (redacted) values.
"""

from __future__ import annotations

from typing import Any

from app.domain.enums import ApprovalStatus, EnforcementMode, ToolCategory

_MAX_TARGET = 120
_MAX_COMMAND = 80
_INTEGRATION_LABELS = {
    "claude_code": "Claude Code hook",
    "mcp_gateway": "MCP gateway",
    "python_sdk": "Python SDK guard",
}
_LEGS = (
    ("sensitive_access", "Accessed sensitive data"),
    ("untrusted_exposure", "Exposed to untrusted content"),
    ("outbound_channel", "Has an outbound channel"),
)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_RAN_ANYWAY = {"completed", "failed"}


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _arg(arguments: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def describe_action(
    tool_name: str | None,
    category: str | None,
    arguments: dict[str, Any] | None,
    target: str | None,
    *,
    destination: str | None = None,
) -> str:
    """One plain-language phrase for what the agent asked to do, e.g. "send POST to webhook.site".

    Built only from the tool's server-side category and its redacted arguments; never guesses
    beyond them ("use <tool>" when nothing more specific is known).
    """
    args = arguments if isinstance(arguments, dict) else {}
    name = tool_name or "a tool"
    where = _clip(destination or target, _MAX_TARGET) if (destination or target) else None
    on = f" on {where}" if where else ""
    cat = category or ToolCategory.OTHER.value

    if cat == ToolCategory.HTTP:
        method = (_arg(args, "method", "http_method", "verb") or "").upper()
        if not where:
            return f"make an HTTP request with {name}"
        if method and method not in _SAFE_METHODS:
            return f"send {method} to {where}"
        return f"fetch {where}"
    if cat == ToolCategory.BROWSER:
        return f"open {where} in a browser" if where else f"drive a browser with {name}"
    if cat == ToolCategory.EMAIL:
        return f"send an email to {where}" if where else f"send an email with {name}"
    if cat == ToolCategory.MESSAGING:
        return f"post a message to {where}" if where else f"post a message with {name}"
    if cat == ToolCategory.SHELL:
        command = _arg(args, "command", "cmd", "script")
        if destination:
            return f"run a shell command that contacts {where}"
        if command:
            return f"run the shell command `{_clip(command, _MAX_COMMAND)}`"
        return f"run a shell command{on}"
    if cat == ToolCategory.FILE_WRITE:
        return f"write to {where}" if where else f"write files with {name}"
    if cat == ToolCategory.FILE_READ:
        return f"read {where}" if where else f"read files with {name}"
    if cat == ToolCategory.DATABASE:
        return f"run a database query{on}"
    if cat == ToolCategory.CODE_EXECUTION:
        return f"execute code that contacts {where}" if destination else f"execute code with {name}"
    if cat == ToolCategory.INFRASTRUCTURE:
        return f"change infrastructure{on} with {name}"
    if cat == ToolCategory.AGENT_DELEGATION:
        return f"delegate a task to {where}" if where else "delegate a task to another agent"
    if cat == ToolCategory.SEARCH:
        query = _arg(args, "query", "q", "search")
        return f"search for “{_clip(query, _MAX_COMMAND)}”" if query else f"search with {name}"
    if cat == ToolCategory.MCP:
        return f"call the MCP tool {name}{f' (sends to {where})' if destination else on}"
    return f"use {name}{on}"


def matched_policy(raw: Any) -> dict[str, Any]:
    """A ``PolicyDecision.matched_policies`` / ``monitor_matches`` entry, as recorded at decision time."""
    m = raw if isinstance(raw, dict) else {}
    version = m.get("version")
    return {
        "policy_id": str(m.get("policy_id") or ""),
        "name": str(m.get("name") or "Unnamed policy"),
        "version": version if isinstance(version, int) else None,
        "outcome": m.get("outcome"),
        "mode": m.get("mode"),
        "severity": m.get("severity"),
        "explanation": str(m.get("explanation") or ""),
        "description": None,
        "exists": True,
    }


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def risk_summary(raw: dict[str, Any] | None) -> dict[str, Any]:
    """``Approval.risk_summary`` (written by the ingestion pipeline) normalised for the API."""
    r = raw if isinstance(raw, dict) else {}
    destination = r.get("destination") if isinstance(r.get("destination"), dict) else {}
    return {
        "session_score": _int(r.get("session_score")),
        "session_level": r.get("session_level"),
        "trifecta": bool(r.get("trifecta")),
        "session_summary": r.get("session_summary") or None,
        "tool_category": r.get("tool_category"),
        "tool_risk": r.get("tool_risk"),
        "destination_classification": destination.get("classification"),
        "sensitive_resources": [str(x) for x in (r.get("sensitive_resources") or [])][:20],
        "secrets_in_arguments": _int(r.get("secrets_in_arguments")),
        "session_secret_matches": _int(r.get("session_secret_matches")),
        "detections": [str(x) for x in (r.get("detections") or [])],
    }


def session_risk(snapshot: dict[str, Any] | None, risk_state: dict[str, Any] | None, risk_score: int | None) -> dict[str, Any]:
    """Trifecta legs as the policy engine saw them (``input_snapshot.session``) plus the evidence
    currently recorded on the session (``AgentSession.risk_state``; labelled with when it was computed)."""
    snap = snapshot if isinstance(snapshot, dict) else {}
    at_decision = snap.get("session") if isinstance(snap.get("session"), dict) else {}
    state = risk_state if isinstance(risk_state, dict) else {}
    evidence = state.get("trifecta_evidence") if isinstance(state.get("trifecta_evidence"), dict) else {}
    legs = []
    for key, label in _LEGS:
        items = evidence.get(key) if isinstance(evidence.get(key), list) else []
        legs.append({
            "key": key, "label": label, "active_at_decision": bool(at_decision.get(key)),
            "evidence": [{"type": str(e.get("type") or "record"), "id": (str(e["id"]) if e.get("id") else None),
                          "detail": e.get("detail")} for e in items if isinstance(e, dict)][:10],
        })
    context = snap.get("context") if isinstance(snap.get("context"), dict) else {}
    return {
        "score_at_decision": _int(at_decision.get("score")),
        "level_at_decision": at_decision.get("level"),
        "trifecta_at_decision": bool(at_decision.get("trifecta")),
        "legs": legs,
        "current_score": _int(risk_score),
        "current_level": state.get("level"),
        "summary": state.get("summary") or None,
        "evidence_computed_at": state.get("computed_at"),
        "context_at_decision": context,
    }


def enforcement_note(*, status: str, enforcement: str | None, integration: str | None,
                     invocation_status: str | None, ran_before_decision: bool = False) -> str:
    """What approving / rejecting actually does for the integration that asked (honest claims only).

    ``ran_before_decision``: the integration reported the call finished before the request was decided.
    """
    who = _INTEGRATION_LABELS.get(integration or "", f"The {integration} integration" if integration else "The integration")
    if invocation_status in _RAN_ANYWAY and status != ApprovalStatus.APPROVED:
        if status == ApprovalStatus.PENDING:
            return (f"{who} reported this call as {invocation_status} before anyone decided here (for example, "
                    "Claude Code falls back to its own permission prompt when its wait runs out). ContextOS "
                    "recorded that its decision was not honoured; see the related findings. Deciding now still "
                    "records the outcome.")
        return (f"The call was reported as {invocation_status} although this request was {status}. ContextOS "
                "recorded that its decision was not honoured; see the related findings.")
    if enforcement == EnforcementMode.ENFORCED:
        if status == ApprovalStatus.PENDING:
            return (f"{who} paused this call at its execution boundary and is polling ContextOS for the outcome. "
                    "Approve lets it run; Reject makes the integration deny it. Integrations stop waiting after "
                    "their own timeout (for example, Claude Code then falls back to its own permission prompt or "
                    "denies), so a late decision is recorded but the agent may need to retry.")
        if status == ApprovalStatus.APPROVED:
            if ran_before_decision and invocation_status in _RAN_ANYWAY:
                return (f"Approved, but {who} had already reported this call as {invocation_status} before the "
                        "decision, so the approval did not gate it.")
            return f"Approved. {who} receives \"approved\" on its next poll and lets the call run."
        if status == ApprovalStatus.REJECTED:
            return f"Rejected. {who} receives \"rejected\" on its next poll and denies the call."
        if status == ApprovalStatus.EXPIRED:
            return f"Nobody decided before the deadline. {who} treats an expired request as not approved."
        if status == ApprovalStatus.CANCELLED:
            return (f"{who} stopped waiting and withdrew this request (for example, its own timeout ran out), so "
                    "the call was not run on this approval.")
        return f"{who} treats a {status} request as not approved."
    if enforcement == EnforcementMode.ADVISORY:
        return (f"Advisory only. {who} received the approval requirement, but ContextOS cannot confirm that it "
                "waits for the outcome. Your decision is recorded and returned if it polls; the call may already "
                "have run.")
    return "Observed only: this call was reported after the fact, so a decision here cannot prevent it."
