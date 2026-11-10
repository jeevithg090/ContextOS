"""Client-side mirror of the ContextOS event contract (schema version 1.0).

Field names, types and validation rules are identical to the server's
``backend/app/events/envelope.py`` so an envelope that validates here validates there. The SDK
never imports server code; this module is the copy integrations build against.

The envelope has NO fields for trust, risk or decisions: the server computes all of them, and
``extra="forbid"`` rejects attempts to send them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION: Literal["1.0"] = "1.0"
_ID_PATTERN = r"^[A-Za-z0-9_.:\-]{1,128}$"
MAX_CONTENT_CHARS = 200_000  # server rejects longer strings in typed fields


class EventType(StrEnum):
    SESSION_STARTED = "session.started"
    SESSION_ENDED = "session.ended"
    PROMPT_SUBMITTED = "prompt.submitted"
    CONTEXT_INGESTED = "context.ingested"
    TOOL_REQUESTED = "tool.requested"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    AGENT_DELEGATED = "agent.delegated"
    AGENT_MESSAGE = "agent.message"
    MCP_SERVER_CONNECTED = "mcp.server_connected"


class SourceType(StrEnum):
    WEB = "web"
    REPOSITORY = "repository"
    FILE = "file"
    DOCUMENT = "document"
    EMAIL = "email"
    API = "api"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    BROWSER = "browser"
    DATABASE = "database"
    USER_UPLOAD = "user_upload"
    USER_PROMPT = "user_prompt"
    TOOL_OUTPUT = "tool_output"
    AGENT_OUTPUT = "agent_output"
    SYSTEM = "system"
    OTHER = "other"


class ToolCategory(StrEnum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL = "shell"
    HTTP = "http"
    BROWSER = "browser"
    EMAIL = "email"
    MESSAGING = "messaging"
    DATABASE = "database"
    CODE_EXECUTION = "code_execution"
    INFRASTRUCTURE = "infrastructure"
    AGENT_DELEGATION = "agent_delegation"
    SEARCH = "search"
    MCP = "mcp"
    OTHER = "other"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RESTRICT = "RESTRICT"
    AUDIT = "AUDIT"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def new_event_id() -> str:
    """Client-generated idempotency key: retries with the same id are recognised as duplicates."""
    return _new_id("evt")


def new_session_id() -> str:
    return _new_id("ses")


def new_correlation_id() -> str:
    return _new_id("cor")


def utcnow() -> datetime:
    return datetime.now(UTC)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=MAX_CONTENT_CHARS)


class AgentRef(_Strict):
    """Identifies the reporting agent. The server auto-registers the agent on first sight (by name)."""

    name: str = Field(min_length=1, max_length=200)
    framework: str = Field(default="custom", max_length=64)
    version: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, max_length=32)


class SourceRef(_Strict):
    type: SourceType
    identifier: str = Field(min_length=1, max_length=2048)
    display_name: str | None = Field(default=None, max_length=400)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolRef(_Strict):
    name: str = Field(min_length=1, max_length=200)
    provider: str = Field(default="unknown", max_length=200)
    server: str | None = Field(default=None, max_length=200)
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
    from_agent: str = Field(max_length=200)
    from_session_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    to_agent: str | None = Field(default=None, max_length=200)
    content: str


class EventEnvelope(_Strict):
    event_id: str = Field(default_factory=new_event_id, pattern=_ID_PATTERN)
    event_type: EventType
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    timestamp: datetime = Field(default_factory=utcnow)
    agent: AgentRef
    session_id: str = Field(pattern=_ID_PATTERN)
    parent_session_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    correlation_id: str | None = Field(default=None, max_length=200)
    integration: str | None = Field(default=None, max_length=64)
    collected_via: str | None = Field(default=None, max_length=200)

    source: SourceRef | None = None
    tool: ToolRef | None = None
    destination: DestinationRef | None = None

    content: str | None = None
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

    def to_wire(self) -> dict[str, Any]:
        """JSON-safe dict for the HTTP body (``None`` fields omitted; the server applies defaults)."""
        return self.model_dump(mode="json", exclude_none=True)


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


__all__ = [
    "MAX_CONTENT_CHARS",
    "SCHEMA_VERSION",
    "AgentRef",
    "ApprovalStatus",
    "Decision",
    "DecisionResponse",
    "DelegationRef",
    "DestinationRef",
    "EventBatch",
    "EventEnvelope",
    "EventResult",
    "EventType",
    "MessageRef",
    "SourceRef",
    "SourceType",
    "ToolCategory",
    "ToolRef",
    "new_correlation_id",
    "new_event_id",
    "new_session_id",
    "utcnow",
]
