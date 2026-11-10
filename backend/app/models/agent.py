"""Agents, agent sessions and inter-agent relationships."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class Agent(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    framework: Mapped[str] = mapped_column(String(64), default="custom")  # claude_code, mcp, langgraph, ...
    owner: Mapped[str | None] = mapped_column(String(200), default=None)  # team or person responsible
    environment: Mapped[str] = mapped_column(String(32), default="development")  # development|staging|production
    labels: Mapped[list[Any]] = mapped_column(default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")  # active|inactive|quarantined
    version: Mapped[str | None] = mapped_column(String(64), default=None)
    # Declared configuration: {"tools": [{"name", "category"}], "permissions": [...], "mcp_servers": [...]}
    declared_capabilities: Mapped[dict[str, Any]] = mapped_column(default=dict)
    integration_id: Mapped[str | None] = mapped_column(
        String(40), ForeignKey("integrations.id", ondelete="SET NULL"), default=None
    )
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(default=None)
    # Cached, recomputed by the risk engine; explanation lives in posture endpoints.
    risk_score: Mapped[int] = mapped_column(Integer, default=0)


class AgentSession(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "agent_sessions"
    __table_args__ = (UniqueConstraint("organization_id", "agent_id", "external_session_id"),)

    id: Mapped[str] = id_column()
    agent_id: Mapped[str] = mapped_column(String(40), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    external_session_id: Mapped[str] = mapped_column(String(200))  # id assigned by the integration
    parent_session_id: Mapped[str | None] = mapped_column(
        String(40), ForeignKey("agent_sessions.id", ondelete="SET NULL"), default=None, index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="active")  # active|ended
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(default=None)
    last_event_at: Mapped[datetime | None] = mapped_column(default=None)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    # Observable session metadata reported by the integration (cwd, model, permission mode...).
    session_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Risk engine output: {"score", "level", "trifecta": {...evidence...}, "factors": [...]}
    risk_state: Mapped[dict[str, Any]] = mapped_column(default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)
    simulation_run_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)


class AgentRelationship(TimestampMixin, OrgScopedMixin, Base):
    """Observed delegation / communication between agents."""

    __tablename__ = "agent_relationships"
    __table_args__ = (UniqueConstraint("organization_id", "parent_agent_id", "child_agent_id", "relationship_type"),)

    id: Mapped[str] = id_column()
    parent_agent_id: Mapped[str] = mapped_column(String(40), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    child_agent_id: Mapped[str] = mapped_column(String(40), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), default="delegates_to")  # delegates_to|messages
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    last_parent_session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    last_child_session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    # True when the child's lowest observed context trust is below the parent's (trust boundary crossed).
    crosses_trust_boundary: Mapped[bool] = mapped_column(Boolean, default=False)
