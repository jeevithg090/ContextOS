"""Tools, tool invocations and outbound destinations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class Tool(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "tools"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "name"),)

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(
        String(200), default="unknown"
    )  # "claude_code", "mcp:<server>", ...
    server: Mapped[str | None] = mapped_column(String(200), default=None)  # MCP server name when applicable
    category: Mapped[str] = mapped_column(String(32), default="other")  # server-classified ToolCategory
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    description: Mapped[str | None] = mapped_column(Text, default=None)
    tool_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict)  # e.g. MCP input schema
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    invocation_count: Mapped[int] = mapped_column(Integer, default=0)


class Destination(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "destinations"
    __table_args__ = (UniqueConstraint("organization_id", "kind", "identifier"),)

    id: Mapped[str] = id_column()
    kind: Mapped[str] = mapped_column(String(32))  # domain|ip|email|service|agent|unknown
    identifier: Mapped[str] = mapped_column(String(1024))  # normalised host / address
    display_name: Mapped[str | None] = mapped_column(String(400), default=None)
    classification: Mapped[str] = mapped_column(String(16), default="UNKNOWN")  # TrustLevel
    trust_rule_id: Mapped[str | None] = mapped_column(String(40), default=None)
    # Checks actually performed: [{"check": str, "result": "pass"|"fail"|"warn"|"unknown", "detail": str}]
    verification: Mapped[list[Any]] = mapped_column(default=list)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    transfer_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    sensitive_transfer_count: Mapped[int] = mapped_column(Integer, default=0)


class ToolInvocation(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "tool_invocations"
    __table_args__ = (
        Index("ix_tool_inv_org_session", "organization_id", "session_id"),
        Index("ix_tool_inv_correlation", "organization_id", "session_id", "correlation_id"),
        Index("ix_tool_inv_org_requested", "organization_id", "requested_at"),  # retention, time-range scans
    )

    id: Mapped[str] = id_column()
    agent_id: Mapped[str] = mapped_column(String(40), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str] = mapped_column(String(40), ForeignKey("agent_sessions.id", ondelete="CASCADE"))
    tool_id: Mapped[str] = mapped_column(String(40), ForeignKey("tools.id", ondelete="CASCADE"), index=True)
    request_event_id: Mapped[str | None] = mapped_column(String(40), default=None)
    result_event_id: Mapped[str | None] = mapped_column(String(40), default=None)
    correlation_id: Mapped[str | None] = mapped_column(
        String(200), default=None
    )  # e.g. Claude Code tool_use_id
    # requested -> allowed|denied|pending_approval|approved|rejected|restricted -> completed|failed
    status: Mapped[str] = mapped_column(String(32), default="requested")
    decision: Mapped[str | None] = mapped_column(String(32), default=None)  # Decision
    enforcement: Mapped[str] = mapped_column(String(16), default="observed")  # EnforcementMode
    policy_decision_id: Mapped[str | None] = mapped_column(String(40), default=None)
    approval_id: Mapped[str | None] = mapped_column(String(40), default=None)
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(default=dict)
    argument_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    resources: Mapped[list[Any]] = mapped_column(
        default=list
    )  # [{"kind": "file"|"url"|..., "id": str, "sensitive": bool, "reason": str|None}]
    destination_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    sensitive_data_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    secret_fingerprints: Mapped[list[Any]] = mapped_column(default=list)
    # Secret fingerprints in the arguments that were previously observed in this session's context
    # (strong evidence of a credential flowing from context into an outbound call).
    matched_session_fingerprints: Mapped[list[Any]] = mapped_column(default=list)
    requested_at: Mapped[datetime] = mapped_column(default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    result_summary: Mapped[str | None] = mapped_column(Text, default=None)  # redacted
    result_context_item_id: Mapped[str | None] = mapped_column(String(40), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)
