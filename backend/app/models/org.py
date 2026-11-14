"""Tenancy and identity: organisations, users, memberships, API keys, auth sessions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    # Org-level configuration: {"retention_days": int, "fail_mode": "closed"|"open",
    # "default_decision": "ALLOW"|"AUDIT", "approval_timeout_s": int, ...}
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Monotonic per-org counters (incremented inside the owning transaction).
    audit_seq: Mapped[int] = mapped_column(Integer, default=0)
    event_seq: Mapped[int] = mapped_column(Integer, default=0)
    task_seq: Mapped[int] = mapped_column(Integer, default=0)
    incident_seq: Mapped[int] = mapped_column(Integer, default=0)  # INC-<n> numbers (migration 0002)
    audit_head_hash: Mapped[str | None] = mapped_column(String(64), default=None)


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = id_column()
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(default=None)


class Membership(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    id: Mapped[str] = id_column()
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(32))  # domain.enums.Role


class ApiKey(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(32))  # first characters, safe to display
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[list[Any]] = mapped_column(default=list)  # subset of API_KEY_SCOPES
    # When set, events authenticated by this key can only be attributed to this agent
    # (prevents one compromised integration from forging another agent's telemetry).
    agent_id: Mapped[str | None] = mapped_column(
        String(40), ForeignKey("agents.id", ondelete="SET NULL"), default=None
    )
    created_by_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class AuthSession(Base):
    """Browser login session. Only the token hash is stored."""

    __tablename__ = "auth_sessions"

    id: Mapped[str] = id_column()
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime] = mapped_column()
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
    user_agent: Mapped[str | None] = mapped_column(String(400), default=None)
