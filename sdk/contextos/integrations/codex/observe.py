"""Events for the observation hooks (everything except PreToolUse), including sub-agent bookkeeping.

Codex sub-agents run in their own threads under the root session: ``spawn_agent`` returns at once
with ``{"agent_id": <thread id>, "nickname": ...}``, the sub-agent's hooks carry that ``agent_id``
and ``SubagentStop`` fires when it finishes. To attribute those later events the hooks keep a
delegation record (``hookkit.Records("codex")``, ids and names only):

1. PreToolUse(spawn_agent) reports ``agent.delegated`` and stores ``{child_agent, child_session_id}``
   under the ``tool_use_id``.
2. PostToolUse(spawn_agent) stores the same record under the returned ``agent_id``.
3. UserPromptSubmit inside the sub-agent (its task) is reported as ``agent.message`` to it.
4. SubagentStop(agent_id) ends the child session.
"""

from __future__ import annotations

from typing import Any

from contextos.models import AgentRef, EventEnvelope

from . import mapping
from .enforce import DELEGATIONS, RECORDS
from .mapping import HookInput


def _child(record: dict[str, Any], agent: AgentRef) -> AgentRef:
    return AgentRef(name=str(record.get("child_agent") or f"{agent.name}/subagent")[:200],
                    framework=mapping.FRAMEWORK, environment=agent.environment)


def observation_events(h: HookInput, agent: AgentRef, *, max_result_chars: int) -> list[EventEnvelope]:
    """Events to report for one observation hook (may read and update delegation records)."""
    if h.event == "SessionStart":
        return [mapping.session_started(h, agent)]
    if h.event == "UserPromptSubmit":
        record = RECORDS.get(DELEGATIONS, f"agent:{h.session_id}:{h.subagent_id}") if h.subagent_id else None
        event = mapping.prompt_submitted(h, agent, sub_agent=_child(record, agent) if record else None)
        return [event] if event else []
    if h.event == "PostToolUse":
        events = [mapping.tool_result(h, agent, max_result_chars=max_result_chars)]
        if h.is_delegation and (launched := h.launched_agent_id):
            record = RECORDS.get(DELEGATIONS, f"tool:{h.session_id}:{h.correlation_id}") or {
                "child_agent": mapping.child_agent(agent, h).name, "child_session_id": mapping.child_session_id(h)}
            RECORDS.put(DELEGATIONS, f"agent:{h.session_id}:{launched}", dict(record))
        return events
    if h.event == "SubagentStop":
        agent_id = h.subagent_id
        record = RECORDS.get(DELEGATIONS, f"agent:{h.session_id}:{agent_id}", remove=True) if agent_id else None
        if not record or not record.get("child_session_id"):
            return []  # a sub-agent ContextOS did not see being delegated (or already closed)
        return [mapping.child_session_closed(h, _child(record, agent), str(record["child_session_id"]),
                                             "subagent_stopped")]
    if h.event == "SessionEnd":
        return [mapping.session_ended(h, agent)]
    return []


__all__ = ["observation_events"]
