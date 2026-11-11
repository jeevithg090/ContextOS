"""Claude Code hook payloads → ContextOS event envelopes (pure; no I/O).

Mapping (verified against the Claude Code hooks reference, see docs/integrations/claude-code.md):

==================  =====================================================================
Hook event          ContextOS event(s)
==================  =====================================================================
SessionStart        ``session.started`` (metadata: cwd, source, model, permission mode)
UserPromptSubmit    ``prompt.submitted`` (the prompt text; the server redacts and classifies).
                    A ``<task-notification>`` (Claude Code delivering a background subagent's
                    or shell's result as a turn) is NOT a human prompt: it becomes
                    ``agent.message`` from the subagent, or ``context.ingested`` (tool output)
PreToolUse          ``tool.requested`` sent to ``POST /decide``; for ``Agent``/``Task`` also
                    ``agent.delegated`` (child agent ``<agent>/<subagent_type>``, task = prompt)
PostToolUse         ``tool.completed`` (result = the text the model reads, size-capped); a
                    foreground ``Agent``/``Task`` result also ends the child session
PostToolUseFailure  ``tool.failed`` (result = the error text)
SubagentStop        ``session.ended`` for the child session of a background subagent
SessionEnd          ``session.ended`` (metadata: reason)
==================  =====================================================================

Identity:
- Agent: the configured name (default ``claude-code@<project dir>``), framework ``claude_code``.
- Session: Claude Code's ``session_id``. Calls made inside a subagent stay in that session (Claude
  Code reports them with the parent's ``session_id``) and carry ``subagent_id`` /
  ``subagent_type`` metadata, so session-level detections (a secret read by a subagent and sent
  out by the main agent) still see one flow.
- Tools: built-ins use provider ``claude_code``; ``mcp__<server>__<tool>`` becomes tool ``<tool>``
  from provider ``mcp:<server>``.
- Correlation: ``tool_use_id`` when present (it is the same in PreToolUse and PostToolUse),
  otherwise a stable hash of session, tool and input.
- ``collected_via``: ``claude_code:<HookEvent>:<ToolName>``.

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
    SourceRef,
    SourceType,
    ToolRef,
    new_event_id,
)

from .results import DELEGATION_TOOLS, bounded_arguments, extract_result

INTEGRATION = "claude_code"
FRAMEWORK = "claude_code"
PROVIDER = "claude_code"
SUPPORTED_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
                    "SubagentStop", "SessionEnd")
MAX_TASK_CHARS = 20_000
MAX_PROMPT_CHARS = 200_000
_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_NOTIFICATION_RE = re.compile(r"^\s*<task-notification>")
_TAG_RES = {tag: re.compile(rf"<{tag}>([^<]{{1,200}})</{tag}>") for tag in ("task-id", "tool-use-id", "status")}
_META_STRING = 1_000


class PayloadError(ValueError):
    """The hook input is not a usable Claude Code payload (message never echoes its content)."""


def _sha(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", errors="replace")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _short(value: Any, limit: int = _META_STRING) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


@dataclass(frozen=True)
class HookInput:
    """A parsed hook payload. ``event`` is the hook the command was registered for."""

    event: str
    data: Mapping[str, Any]

    def _str(self, key: str) -> str | None:
        value = self.data.get(key)
        return value if isinstance(value, str) and value else None

    @property
    def session_id(self) -> str:
        """Claude Code's session id, or a stable stand-in derived from the transcript path / cwd."""
        raw = self._str("session_id")
        if raw and _ID_RE.match(raw):
            return raw
        basis = raw or self._str("transcript_path") or self._str("cwd") or "unknown"
        return f"cc_{_sha('session', basis)[:40]}"

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
    def permission_mode(self) -> str | None:
        return self._str("permission_mode")

    @property
    def is_delegation(self) -> bool:
        return self.tool_name in DELEGATION_TOOLS

    @property
    def runs_in_background(self) -> bool:
        """The delegated subagent keeps running after the tool returns (PostToolUse only knows)."""
        response = self.data.get("tool_response")
        if isinstance(response, Mapping) and (response.get("isAsync") is True or response.get("status") == "async_launched"):
            return True
        return bool(self.tool_input.get("run_in_background"))

    @property
    def launched_agent_id(self) -> str | None:
        """``agentId`` from an ``Agent`` tool response: the ``agent_id`` the subagent's own hooks carry."""
        response = self.data.get("tool_response")
        value = response.get("agentId") if isinstance(response, Mapping) else None
        return value if isinstance(value, str) and 0 < len(value) <= 200 else None

    @property
    def subagent_id(self) -> str | None:
        """``agent_id`` of the subagent the hook fired in (SubagentStop, or calls inside a subagent)."""
        value = self._str("agent_id")
        return value if value and len(value) <= 200 else None

    @property
    def correlation_id(self) -> str:
        """Pairs PreToolUse with PostToolUse: ``tool_use_id``, else a hash of session + tool + input."""
        if self.tool_use_id:
            return self.tool_use_id
        return f"cc_{_sha(self.session_id, self.tool_name, _canonical(self.tool_input))[:40]}"

    def event_id(self, kind: str) -> str:
        """Deterministic event id when Claude Code gives a unique handle, so retries deduplicate."""
        handle = self.tool_use_id if kind.startswith(("tool.", "delegation")) else None
        if kind == "prompt":
            handle = self._str("prompt_id")
        if handle:
            return f"evt_cc_{_sha(self.session_id, kind, handle)[:40]}"
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
    suffix = f":{h.tool_name}" if h.event in ("PreToolUse", "PostToolUse", "PostToolUseFailure") else ""
    return f"{INTEGRATION}:{h.event}{suffix}"[:200]


def base_metadata(h: HookInput) -> dict[str, Any]:
    meta: dict[str, Any] = {"hook_event": h.event}
    for key in ("permission_mode", "cwd"):
        if h._str(key):
            meta[key] = _short(h._str(key))
    # Present when the hook fires inside a subagent (common input fields).
    if h._str("agent_id"):
        meta["subagent_id"] = _short(h._str("agent_id"), 200)
    if h._str("agent_type"):
        meta["subagent_type"] = _short(h._str("agent_type"), 200)
    if h.tool_name.startswith("mcp__"):
        meta["claude_tool_name"] = h.tool_name
    if h.tool_use_id:
        meta["tool_use_id"] = h.tool_use_id
    return meta


def agent_ref(name: str, environment: str | None = None) -> AgentRef:
    return AgentRef(name=name[:200], framework=FRAMEWORK, environment=(environment or None) and environment[:32])


def child_agent(agent: AgentRef, h: HookInput) -> AgentRef:
    subagent = str(h.tool_input.get("subagent_type") or "general-purpose").strip() or "general-purpose"
    return AgentRef(name=f"{agent.name}/{subagent}"[:200], framework=FRAMEWORK, environment=agent.environment)


def child_session_id(h: HookInput) -> str:
    candidate = f"{h.session_id}.agent.{h.correlation_id}"
    return candidate if _ID_RE.match(candidate) else f"cc_sub_{_sha(h.session_id, h.correlation_id)[:40]}"


def _new(h: HookInput, agent: AgentRef, event_type: EventType, kind: str, **fields: Any) -> EventEnvelope:
    fields.setdefault("metadata", base_metadata(h))
    return EventEnvelope(event_id=h.event_id(kind), event_type=event_type, agent=agent, session_id=h.session_id,
                         integration=INTEGRATION, collected_via=collected_via(h), **fields)


# -- builders -------------------------------------------------------------------------------------


def tool_request(h: HookInput, agent: AgentRef) -> EventEnvelope:
    """``tool.requested`` for ``POST /decide``: the FULL tool input, never truncated."""
    return _new(h, agent, EventType.TOOL_REQUESTED, "tool.requested", correlation_id=h.correlation_id,
                tool=tool_ref(h), arguments=h.tool_input)


def delegation(h: HookInput, agent: AgentRef) -> EventEnvelope:
    """``agent.delegated`` for an ``Agent``/``Task`` call: registers the subagent and its task."""
    task = h.tool_input.get("prompt")
    text = str(task) if task is not None else None
    if text is not None and len(text) > MAX_TASK_CHARS:
        keep = MAX_TASK_CHARS - 60
        text = text[:keep] + f"\n[TRUNCATED: {len(text) - keep} more characters]"
    meta = base_metadata(h)
    for key in ("description", "subagent_type", "model", "run_in_background"):
        if key in h.tool_input:
            meta[f"delegation_{key}"] = _short(h.tool_input[key], 400)
    return _new(h, agent, EventType.AGENT_DELEGATED, "delegation", correlation_id=h.correlation_id,
                delegation=DelegationRef(child_agent=child_agent(agent, h), child_session_id=child_session_id(h),
                                         task=text),
                metadata=meta)


def tool_result(h: HookInput, agent: AgentRef, *, max_result_chars: int,
                extra_metadata: Mapping[str, Any] | None = None) -> EventEnvelope:
    failed = h.event == "PostToolUseFailure"
    meta = base_metadata(h)
    if isinstance(h.data.get("duration_ms"), (int, float)) and not isinstance(h.data.get("duration_ms"), bool):
        meta["duration_ms"] = h.data["duration_ms"]
    if failed and isinstance(h.data.get("is_interrupt"), bool):
        meta["is_interrupt"] = h.data["is_interrupt"]
    meta.update(extra_metadata or {})
    if failed:
        error = h.data.get("error")
        result: Any = extract_result(h.tool_name, error if error is not None else "Tool reported a failure",
                                     max_result_chars)
    else:
        result = extract_result(h.tool_name, h.data.get("tool_response"), max_result_chars)
    return _new(h, agent, EventType.TOOL_FAILED if failed else EventType.TOOL_COMPLETED,
                "tool.failed" if failed else "tool.completed", correlation_id=h.correlation_id, tool=tool_ref(h),
                arguments=bounded_arguments(h.tool_input), result=result, is_error=failed, metadata=meta)


def child_session_closed(h: HookInput, child: AgentRef, child_session: str, reason: str) -> EventEnvelope:
    """``session.ended`` for a delegated subagent's child session."""
    meta = {**base_metadata(h), "reason": reason}
    return EventEnvelope(event_id=h.event_id("delegation.ended") if h.tool_use_id else new_event_id(),
                         event_type=EventType.SESSION_ENDED, agent=child, session_id=child_session,
                         parent_session_id=h.session_id, integration=INTEGRATION, collected_via=collected_via(h),
                         metadata=meta)


def session_started(h: HookInput, agent: AgentRef) -> EventEnvelope:
    meta = base_metadata(h)
    for key in ("source", "model", "agent_type", "session_title"):
        if h._str(key):
            meta[key] = _short(h._str(key), 400)
    meta.pop("subagent_type", None)  # on SessionStart, agent_type is the --agent the session runs as
    return _new(h, agent, EventType.SESSION_STARTED, "session.started", metadata=meta)


def session_ended(h: HookInput, agent: AgentRef) -> EventEnvelope:
    meta = base_metadata(h)
    if h._str("reason"):
        meta["reason"] = _short(h._str("reason"), 100)
    return _new(h, agent, EventType.SESSION_ENDED, "session.ended", metadata=meta)


def prompt_submitted(h: HookInput, agent: AgentRef) -> EventEnvelope | None:
    prompt = h.data.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    if len(prompt) > MAX_PROMPT_CHARS:
        prompt = prompt[:MAX_PROMPT_CHARS - 80] + f"\n[TRUNCATED: {len(prompt) - MAX_PROMPT_CHARS + 80} more characters]"
    meta = base_metadata(h)
    if h._str("prompt_id"):
        meta["prompt_id"] = _short(h._str("prompt_id"), 200)
    return _new(h, agent, EventType.PROMPT_SUBMITTED, "prompt", content=prompt, metadata=meta)


def task_notification(h: HookInput) -> dict[str, str] | None:
    """``{"task_id", "tool_use_id", "status"}`` when the prompt is a Claude Code task notification."""
    prompt = h.data.get("prompt")
    if not isinstance(prompt, str) or not _NOTIFICATION_RE.match(prompt):
        return None
    found = {tag.replace("-", "_"): m.group(1).strip() for tag, rx in _TAG_RES.items() if (m := rx.search(prompt))}
    return found


def notification_events(h: HookInput, agent: AgentRef, info: Mapping[str, str],
                        delegation_record: Mapping[str, Any] | None) -> list[EventEnvelope]:
    """A ``<task-notification>`` turn: the result of background work, not something a person typed."""
    prompt = str(h.data.get("prompt") or "")
    if len(prompt) > MAX_PROMPT_CHARS:
        prompt = prompt[:MAX_PROMPT_CHARS - 80] + f"\n[TRUNCATED: {len(prompt) - MAX_PROMPT_CHARS + 80} more characters]"
    meta = {**base_metadata(h), "claude_code_turn": "task_notification",
            **{f"notification_{k}": _short(v, 200) for k, v in info.items()}}
    if delegation_record and delegation_record.get("child_session_id"):
        message = MessageRef(from_agent=str(delegation_record.get("child_agent") or f"{agent.name}/subagent")[:200],
                             from_session_id=str(delegation_record["child_session_id"]), to_agent=agent.name,
                             content=prompt)
        return [_new(h, agent, EventType.AGENT_MESSAGE, "prompt", message=message, metadata=meta)]
    source = SourceRef(type=SourceType.TOOL_OUTPUT, identifier="claude_code:task-notification",
                       display_name="Claude Code background task result",
                       metadata={k: _short(v, 200) for k, v in info.items()})
    return [_new(h, agent, EventType.CONTEXT_INGESTED, "prompt", source=source, content=prompt, metadata=meta)]


__all__ = [
    "FRAMEWORK",
    "INTEGRATION",
    "PROVIDER",
    "SUPPORTED_EVENTS",
    "HookInput",
    "PayloadError",
    "agent_ref",
    "child_agent",
    "child_session_closed",
    "child_session_id",
    "collected_via",
    "delegation",
    "notification_events",
    "parse_payload",
    "prompt_submitted",
    "session_ended",
    "session_started",
    "split_tool_name",
    "task_notification",
    "tool_ref",
    "tool_request",
    "tool_result",
]
