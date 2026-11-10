"""Typed event contract (schema version 1.0).

This is what integrations send. It deliberately has NO fields for trust, risk or policy outcomes:
those are always computed server-side. ``extra="forbid"`` rejects attempts to smuggle them in.
The organisation is derived from the API key, never from the payload.

Server-side enrichment (organisation, resolved ids, trust/risk metadata, policy decision) is
recorded on ``IngestedEvent.refs`` and the domain tables, and exposed via ``ProcessedEventOut``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import EventType, SourceType, ToolCategory

SCHEMA_VERSION = "1.0"
_ID_PATTERN = r"^[A-Za-z0-9_.:\-]{1,128}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=200_000)


class AgentRef(_Strict):
    """Identifies the reporting agent. Auto-registers the agent on first sight (by name)."""

    name: str = Field(min_length=1, max_length=200)
    framework: str = Field(default="custom", max_length=64)
    version: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, max_length=32)


class SourceRef(_Strict):
    type: SourceType
    identifier: str = Field(min_length=1, max_length=2048)  # URL, file path, repo path, server name...
    display_name: str | None = Field(default=None, max_length=400)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolRef(_Strict):
    name: str = Field(min_length=1, max_length=200)
    provider: str = Field(default="unknown", max_length=200)
    server: str | None = Field(default=None, max_length=200)  # MCP server name
    # A hint only; ContextOS classifies the tool itself and records the hint for comparison.
    category_hint: ToolCategory | None = None
    description: str | None = Field(default=None, max_length=4000)


class DestinationRef(_Strict):
    kind: Literal["domain", "ip", "email", "service", "agent", "unknown"] = "unknown"
    identifier: str = Field(min_length=1, max_length=1024)


class DelegationRef(_Strict):
    child_agent: AgentRef
    child_session_id: str = Field(pattern=_ID_PATTERN)
    task: str | None = Field(default=None, max_length=20_000)


class MessageRef(_Strict):
    from_agent: str = Field(max_length=200)  # agent name
    from_session_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    to_agent: str | None = Field(default=None, max_length=200)
    content: str


class EventEnvelope(_Strict):
    event_id: str = Field(pattern=_ID_PATTERN, description="Client-generated idempotency key")
    event_type: EventType
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    timestamp: datetime = Field(description="Client-observed time (display only; server time is authoritative)")
    agent: AgentRef
    session_id: str = Field(pattern=_ID_PATTERN, description="Integration's session id")
    parent_session_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    correlation_id: str | None = Field(default=None, max_length=200, description="Pairs tool.requested/tool.completed")
    integration: str | None = Field(default=None, max_length=64, description="e.g. claude_code, mcp_gateway, python_sdk")
    collected_via: str | None = Field(default=None, max_length=200, description="Hook / callback that observed this")

    source: SourceRef | None = None
    tool: ToolRef | None = None
    destination: DestinationRef | None = None

    content: str | None = Field(default=None, description="Context text to inspect (redacted before persistence)")
    content_type: str = Field(default="text/plain", max_length=64)
    arguments: dict[str, Any] | None = None
    result: str | dict[str, Any] | list[Any] | None = None
    is_error: bool = False
    delegation: DelegationRef | None = None
    message: MessageRef | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_shape(self) -> EventEnvelope:
        t = self.event_type
        if t == EventType.CONTEXT_INGESTED and (self.source is None or self.content is None):
            raise ValueError("context.ingested requires 'source' and 'content'")
        if t == EventType.PROMPT_SUBMITTED and self.content is None:
            raise ValueError("prompt.submitted requires 'content'")
        if t in (EventType.TOOL_REQUESTED, EventType.TOOL_COMPLETED, EventType.TOOL_FAILED) and self.tool is None:
            raise ValueError(f"{t} requires 'tool'")
        if t == EventType.AGENT_DELEGATED and self.delegation is None:
            raise ValueError("agent.delegated requires 'delegation'")
        if t == EventType.AGENT_MESSAGE and self.message is None:
            raise ValueError("agent.message requires 'message'")
        if t == EventType.MCP_SERVER_CONNECTED and self.source is None:
            raise ValueError("mcp.server_connected requires 'source' (type mcp_server)")
        return self


class EventBatch(_Strict):
    events: list[EventEnvelope] = Field(min_length=1, max_length=500)


class EventResult(BaseModel):
    event_id: str
    status: Literal["accepted", "duplicate", "rejected"]
    ingested_event_id: str | None = None
    error: str | None = None
    refs: dict[str, Any] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    """Returned synchronously by ``POST /api/v1/decide`` for ``tool.requested`` events."""

    decision: str  # Decision
    enforcement: str  # EnforcementMode the server assumes for this integration
    reason: str
    policy_decision_id: str
    tool_invocation_id: str
    approval_id: str | None = None
    approval_status: str | None = None
    matched_policies: list[dict[str, Any]] = Field(default_factory=list)
    restrictions: dict[str, Any] = Field(default_factory=dict)
    risk: dict[str, Any] = Field(default_factory=dict)
