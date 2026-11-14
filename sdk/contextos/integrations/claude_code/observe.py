"""Events for the observation hooks (everything except PreToolUse), including subagent bookkeeping.

Claude Code runs subagents inside the parent's session and, in current versions, usually in the
background: the ``Agent`` tool returns at once with ``{"isAsync": true, "agentId": ...}``, the
subagent's own hooks carry that ``agent_id``, ``SubagentStop`` fires when it finishes, and its result
reaches the parent as a ``<task-notification>`` turn on ``UserPromptSubmit``. To attribute those
later events, the hooks keep a delegation record (see ``state``):

1. PreToolUse(Agent) reports ``agent.delegated`` and stores ``{child_agent, child_session_id}``
   under the ``tool_use_id``.
2. PostToolUse(Agent) of a background launch stores the same record under the ``agentId``; a
   foreground result ends the child session right away.
3. SubagentStop(agent_id) ends the child session.
4. A ``<task-notification>`` naming the ``tool_use_id`` becomes ``agent.message`` from the subagent
   (so its content carries the subagent session's trust), otherwise ``context.ingested`` as tool
   output. It is never reported as a person's prompt.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from contextos.models import AgentRef, EventEnvelope

from . import mapping, state
from .mapping import HookInput

DELEGATIONS = "delegations"


def remember_delegation(h: HookInput, agent: AgentRef) -> None:
    """Called after an ``Agent``/``Task`` PreToolUse was reported as ``agent.delegated``."""
    state.put(
        DELEGATIONS,
        f"tool:{h.session_id}:{h.correlation_id}",
        {"child_agent": mapping.child_agent(agent, h).name, "child_session_id": mapping.child_session_id(h)},
    )


def _delegation_for_tool(h: HookInput, tool_use_id: str) -> dict[str, Any] | None:
    return state.get(DELEGATIONS, f"tool:{h.session_id}:{tool_use_id}")


def _delegation_for_subagent(h: HookInput, agent_id: str, *, remove: bool = False) -> dict[str, Any] | None:
    return state.get(DELEGATIONS, f"agent:{h.session_id}:{agent_id}", remove=remove)


def _child(record: Mapping[str, Any], agent: AgentRef) -> AgentRef:
    return AgentRef(
        name=str(record.get("child_agent") or f"{agent.name}/subagent")[:200],
        framework=mapping.FRAMEWORK,
        environment=agent.environment,
    )


def _tool_events(
    h: HookInput, agent: AgentRef, max_result_chars: int, extra: Mapping[str, Any] | None
) -> list[EventEnvelope]:
    events = [mapping.tool_result(h, agent, max_result_chars=max_result_chars, extra_metadata=extra)]
    if not h.is_delegation:
        return events
    record = _delegation_for_tool(h, h.correlation_id) or {
        "child_agent": mapping.child_agent(agent, h).name,
        "child_session_id": mapping.child_session_id(h),
    }
    launched = h.launched_agent_id
    if h.event == "PostToolUse" and h.runs_in_background:
        if launched:
            state.put(DELEGATIONS, f"agent:{h.session_id}:{launched}", dict(record))
        return events
    reason = "subagent_returned" if h.event == "PostToolUse" else "subagent_failed"
    events.append(
        mapping.child_session_closed(h, _child(record, agent), str(record["child_session_id"]), reason)
    )
    return events


def observation_events(
    h: HookInput, agent: AgentRef, *, max_result_chars: int, extra_metadata: Mapping[str, Any] | None = None
) -> list[EventEnvelope]:
    """Events to report for one observation hook (may read and update delegation records)."""
    if h.event == "SessionStart":
        return [mapping.session_started(h, agent)]
    if h.event == "UserPromptSubmit":
        info = mapping.task_notification(h)
        if info is not None:
            record = _delegation_for_tool(h, info["tool_use_id"]) if info.get("tool_use_id") else None
            return mapping.notification_events(h, agent, info, record)
        event = mapping.prompt_submitted(h, agent)
        return [event] if event else []
    if h.event in ("PostToolUse", "PostToolUseFailure"):
        return _tool_events(h, agent, max_result_chars, extra_metadata)
    if h.event == "SubagentStop":
        agent_id = h.subagent_id
        record = _delegation_for_subagent(h, agent_id, remove=True) if agent_id else None
        if not record or not record.get("child_session_id"):
            return []  # a foreground subagent (already closed) or one of Claude Code's internal agents
        return [
            mapping.child_session_closed(
                h, _child(record, agent), str(record["child_session_id"]), "subagent_stopped"
            )
        ]
    if h.event == "SessionEnd":
        return [mapping.session_ended(h, agent)]
    return []


__all__ = ["DELEGATIONS", "observation_events", "remember_delegation"]
