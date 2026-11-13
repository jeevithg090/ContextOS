"""OpenAI Codex hook payloads → ContextOS event envelopes (pure; no I/O).

Verified against the Codex source at tag ``rust-v0.158.0-alpha.2.1`` (``codex-rs/hooks``, the
generated input schemas in ``codex-rs/hooks/schema/generated``) and the Codex CLI 0.158.0-alpha.2.1
binary; see docs/integrations/codex.md.

==================  =====================================================================
Codex hook          ContextOS event(s)
==================  =====================================================================
SessionStart        ``session.started`` (metadata: cwd, source, model, permission mode)
UserPromptSubmit    ``prompt.submitted`` (the prompt text). Inside a sub-agent thread (the payload
                    carries ``agent_id``) the "prompt" is the task its parent sent, so it becomes
                    ``agent.message`` from the parent agent instead
PreToolUse          ``tool.requested`` sent to ``POST /decide``; ``spawn_agent`` also reports
                    ``agent.delegated`` (child agent ``<agent>/<agent_type>``, task = message)
PostToolUse         ``tool.completed`` (result = the text the model reads, size-capped). Codex
                    runs PostToolUse only for calls that produced a successful output: failed calls
                    are never reported by Codex hooks
SubagentStop        ``session.ended`` for the child session of a ``spawn_agent`` delegation
SessionEnd          ``session.ended`` (metadata: reason)
==================  =====================================================================

Payload facts this module relies on (all from the schemas above):
- Every payload has ``session_id`` (shared by the root thread and all its sub-agent threads),
  ``cwd``, ``hook_event_name`` and a nullable ``transcript_path`` (never read here). Turn-scoped
  hooks add ``turn_id``; most add ``model`` and ``permission_mode`` (``default`` or
  ``bypassPermissions`` = approval policy ``never``).
- Inside a sub-agent thread, hooks add ``agent_id`` (the sub-agent's thread id) and ``agent_type``.
- Tool names: shell commands (``exec_command`` and the shell tools) are ``Bash`` with
  ``tool_input = {"command": <string>}``; file edits are ``apply_patch`` with
  ``{"command": <patch text>}``; MCP tools are ``mcp__<server>__<tool>`` with their JSON
  arguments; other function tools (``spawn_agent``, ``view_image``, ``update_plan`` ...) carry their
  JSON arguments (a string when the arguments were not valid JSON).
- ``tool_use_id`` is the model's call id and is the same in PreToolUse and PostToolUse.

Identity: agent = the configured name (default ``codex@<project dir>``), framework
``openai_codex``; session = Codex's ``session_id``; calls made inside a sub-agent stay in that
session with ``subagent_id`` / ``subagent_type`` metadata (as for Claude Code), so session-level
detections see one flow. ``collected_via``: ``openai_codex:<HookEvent>[:<ToolName>]``.

The envelope carries no trust, risk or decision fields; the server computes all of them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from contextos.models import (
    AgentRef,
    DelegationRef,
    EventEnvelope,
    EventType,
    MessageRef,
    ToolRef,
    new_event_id,
)

from .results import bounded_arguments, extract_result

INTEGRATION = "openai_codex"
FRAMEWORK = "openai_codex"
PROVIDER = "openai_codex"
SUPPORTED_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SubagentStop", "SessionEnd")
DELEGATION_TOOLS = frozenset({"spawn_agent"})
MAX_TASK_CHARS = 20_000
MAX_PROMPT_CHARS = 200_000
_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_META_STRING = 1_000


class PayloadError(ValueError):
    """The hook input is not a usable Codex payload (the message never echoes its content)."""


def _sha(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", errors="replace")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _short(value: Any, limit: int = _META_STRING) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    keep = limit - 80
    return text[:keep] + f"\n[TRUNCATED: {len(text) - keep} more characters]"


@dataclass(frozen=True)
class HookInput:
    """A parsed Codex hook payload. ``event`` is the hook the command was registered for."""

    event: str
    data: Mapping[str, Any]

    def _str(self, key: str) -> str | None:
        value = self.data.get(key)
        return value if isinstance(value, str) and value else None

    @property
    def session_id(self) -> str:
        """Codex's session id, or a stable stand-in when it is missing or unusable."""
        raw = self._str("session_id")
        if raw and _ID_RE.match(raw):
            return raw
        basis = raw or self._str("cwd") or "unknown"
        return f"cx_{_sha('session', basis)[:40]}"

    @property
    def tool_name(self) -> str:
        return (self._str("tool_name") or "unknown")[:400]

    @property
    def tool_input(self) -> dict[str, Any]:
        value = self.data.get("tool_input")
        if value is None:
            return {}
        return dict(value) if isinstance(value, Mapping) else {"input": value}

    @property
    def tool_use_id(self) -> str | None:
        value = self._str("tool_use_id")
        return value if value and len(value) <= 200 else None

    @property
    def cwd(self) -> str | None:
        return self._str("cwd")

    @property
    def subagent_id(self) -> str | None:
        """``agent_id`` of the sub-agent thread the hook fired in (``None`` on the root thread)."""
        value = self._str("agent_id")
        return value if value and len(value) <= 200 else None

    @property
    def is_delegation(self) -> bool:
        return self.tool_name in DELEGATION_TOOLS

    @property
    def launched_agent_id(self) -> str | None:
        """``agent_id`` from a ``spawn_agent`` result: the id the sub-agent's own hooks carry."""
        response = self.data.get("tool_response")
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                return None
        if isinstance(response, list):  # content items: [{"type": "input_text", "text": "{...}"}]
            texts = [i.get("text") for i in response if isinstance(i, Mapping) and isinstance(i.get("text"), str)]
            try:
                response = json.loads("".join(texts)) if texts else None
            except json.JSONDecodeError:
                return None
        value = response.get("agent_id") if isinstance(response, Mapping) else None
        return value if isinstance(value, str) and 0 < len(value) <= 200 else None

    @property
    def correlation_id(self) -> str:
        """Pairs PreToolUse with PostToolUse: ``tool_use_id``, else a hash of session + tool + input."""
        if self.tool_use_id:
            return self.tool_use_id
        return f"cx_{_sha(self.session_id, self.tool_name, _canonical(self.tool_input))[:40]}"

    def event_id(self, kind: str) -> str:
        """Deterministic event id when Codex gives a unique handle, so retries deduplicate."""
        handle = self.tool_use_id if kind.startswith(("tool.", "delegation")) else None
        if kind == "prompt":
            handle = self._str("turn_id")
            if handle and self.subagent_id:
                handle = f"{self.subagent_id}:{handle}"
        if handle:
            return f"evt_cx_{_sha(self.session_id, kind, handle)[:40]}"
        return new_event_id()


def parse_payload(raw: bytes, event_name: str) -> HookInput:
    if not raw.strip():
        raise PayloadError("the hook received no input on stdin")
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise PayloadError(f"the hook input is not valid JSON (line {exc.lineno})") from None
    if not isinstance(data, dict):
        raise PayloadError("the hook input must be a JSON object")
    event = event_name.strip() or str(data.get("hook_event_name") or "")
    if not event:
        raise PayloadError("the hook event name is missing")
    return HookInput(event=event, data=data)


def split_tool_name(name: str) -> tuple[str, str, str | None]:
    """``(tool name, provider, server)``. ``mcp__github__create_issue`` → ``create_issue``, ``mcp:github``."""
    if name.startswith("mcp__"):
        server, sep, tool = name[5:].partition("__")
        if sep and server and tool:
            return tool[:200], f"mcp:{server}"[:200], server[:200]
    return name[:200], PROVIDER, None


def tool_ref(h: HookInput) -> ToolRef:
    name, provider, server = split_tool_name(h.tool_name)
    return ToolRef(name=name or "unknown", provider=provider, server=server)


def collected_via(h: HookInput) -> str:
    suffix = f":{h.tool_name}" if h.event in ("PreToolUse", "PostToolUse") else ""
    return f"{INTEGRATION}:{h.event}{suffix}"[:200]


def base_metadata(h: HookInput) -> dict[str, Any]:
    meta: dict[str, Any] = {"hook_event": h.event}
    for key in ("permission_mode", "cwd", "model", "turn_id"):
        if h._str(key):
            meta[key] = _short(h._str(key), 400)
    if h.subagent_id:
        meta["subagent_id"] = h.subagent_id
    if h._str("agent_type"):
        meta["subagent_type"] = _short(h._str("agent_type"), 200)
    if h.tool_name.startswith("mcp__"):
        meta["codex_tool_name"] = h.tool_name
    if h.tool_use_id:
        meta["tool_use_id"] = h.tool_use_id
    return meta


def agent_ref(name: str, environment: str | None = None) -> AgentRef:
    return AgentRef(name=name[:200], framework=FRAMEWORK, environment=(environment or None) and environment[:32])


def child_agent(agent: AgentRef, h: HookInput) -> AgentRef:
    role = str(h.tool_input.get("agent_type") or "default").strip() or "default"
    return AgentRef(name=f"{agent.name}/{role}"[:200], framework=FRAMEWORK, environment=agent.environment)


def child_session_id(h: HookInput) -> str:
    candidate = f"{h.session_id}.agent.{h.correlation_id}"
    return candidate if _ID_RE.match(candidate) else f"cx_sub_{_sha(h.session_id, h.correlation_id)[:40]}"


def _new(h: HookInput, agent: AgentRef, event_type: EventType, kind: str, **fields: Any) -> EventEnvelope:
    fields.setdefault("metadata", base_metadata(h))
    return EventEnvelope(event_id=h.event_id(kind), event_type=event_type, agent=agent, session_id=h.session_id,
                         integration=INTEGRATION, collected_via=collected_via(h), **fields)


# -- builders -------------------------------------------------------------------------------------


def tool_request(h: HookInput, agent: AgentRef) -> EventEnvelope:
    """``tool.requested`` for ``POST /decide``: the FULL tool input, never truncated."""
    return _new(h, agent, EventType.TOOL_REQUESTED, "tool.requested", correlation_id=h.correlation_id,
                tool=tool_ref(h), arguments=h.tool_input)


def _delegated_task(h: HookInput) -> str | None:
    message = h.tool_input.get("message")
    if isinstance(message, str) and message.strip():
        return message
    items = h.tool_input.get("items")
    if isinstance(items, list):  # structured input: keep its text parts
        texts = [i.get("text") for i in items if isinstance(i, Mapping) and isinstance(i.get("text"), str)]
        return "\n".join(texts) if texts else None
    return None


def delegation(h: HookInput, agent: AgentRef) -> EventEnvelope:
    """``agent.delegated`` for a ``spawn_agent`` call: registers the sub-agent and its task."""
    task = _delegated_task(h)
    meta = base_metadata(h)
    for key in ("agent_type", "model", "reasoning_effort", "fork_context"):
        if key in h.tool_input:
            meta[f"delegation_{key}"] = _short(h.tool_input[key], 400)
    return _new(h, agent, EventType.AGENT_DELEGATED, "delegation", correlation_id=h.correlation_id,
                delegation=DelegationRef(child_agent=child_agent(agent, h), child_session_id=child_session_id(h),
                                         task=_truncate(task, MAX_TASK_CHARS) if task is not None else None),
                metadata=meta)


def tool_result(h: HookInput, agent: AgentRef, *, max_result_chars: int) -> EventEnvelope:
    """``tool.completed`` (Codex has no hook for failed calls)."""
    result = extract_result(h.tool_name, h.data.get("tool_response"), max_result_chars)
    return _new(h, agent, EventType.TOOL_COMPLETED, "tool.completed", correlation_id=h.correlation_id,
                tool=tool_ref(h), arguments=bounded_arguments(h.tool_input), result=result,
                metadata=base_metadata(h))


def child_session_closed(h: HookInput, child: AgentRef, child_session: str, reason: str) -> EventEnvelope:
    """``session.ended`` for a delegated sub-agent's child session."""
    meta = {**base_metadata(h), "reason": reason}
    return EventEnvelope(event_type=EventType.SESSION_ENDED, agent=child, session_id=child_session,
                         parent_session_id=h.session_id, integration=INTEGRATION, collected_via=collected_via(h),
                         metadata=meta)


def session_started(h: HookInput, agent: AgentRef) -> EventEnvelope:
    meta = base_metadata(h)
    if h._str("source"):
        meta["source"] = _short(h._str("source"), 100)
    return _new(h, agent, EventType.SESSION_STARTED, "session.started", metadata=meta)


def session_ended(h: HookInput, agent: AgentRef) -> EventEnvelope:
    meta = base_metadata(h)
    if h._str("reason"):
        meta["reason"] = _short(h._str("reason"), 100)
    return _new(h, agent, EventType.SESSION_ENDED, "session.ended", metadata=meta)


def prompt_submitted(h: HookInput, agent: AgentRef, *, sub_agent: AgentRef | None = None) -> EventEnvelope | None:
    """A person's prompt, or — inside a sub-agent thread — the task its parent sent (``agent.message``)."""
    prompt = h.data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    prompt = _truncate(prompt, MAX_PROMPT_CHARS)
    meta = base_metadata(h)
    if h.subagent_id:
        meta["codex_turn"] = "subagent_input"
        message = MessageRef(from_agent=agent.name, from_session_id=h.session_id,
                             to_agent=(sub_agent.name if sub_agent else f"{agent.name}/subagent")[:200],
                             content=prompt)
        return _new(h, agent, EventType.AGENT_MESSAGE, "prompt", message=message, metadata=meta)
    return _new(h, agent, EventType.PROMPT_SUBMITTED, "prompt", content=prompt, metadata=meta)


__all__ = [
    "DELEGATION_TOOLS",
    "FRAMEWORK",
    "INTEGRATION",
    "PROVIDER",
    "SUPPORTED_EVENTS",
    "HookInput",
    "PayloadError",
    "agent_ref",
    "base_metadata",
    "child_agent",
    "child_session_closed",
    "child_session_id",
    "collected_via",
    "delegation",
    "parse_payload",
    "prompt_submitted",
    "session_ended",
    "session_started",
    "split_tool_name",
    "tool_ref",
    "tool_request",
    "tool_result",
]
