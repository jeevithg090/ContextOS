"""Event log, audit chain, integrations, simulations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class IngestedEvent(OrgScopedMixin, Base):
    """Append-only log of every accepted event (redacted). The basis for replay and idempotency."""

    __tablename__ = "ingested_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "client_event_id"),
        Index("ix_events_org_session_seq", "organization_id", "session_id", "sequence"),
    )

    id: Mapped[str] = id_column()
    client_event_id: Mapped[str] = mapped_column(String(128))  # envelope.event_id (idempotency key)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    schema_version: Mapped[str] = mapped_column(String(8), default="1.0")
    sequence: Mapped[int] = mapped_column(Integer)  # server-assigned, per-org monotonic ordering
    agent_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    correlation_id: Mapped[str | None] = mapped_column(String(200), default=None)
    integration: Mapped[str | None] = mapped_column(String(64), default=None)
    occurred_at: Mapped[datetime] = mapped_column()  # client-reported (untrusted, kept for display)
    received_at: Mapped[datetime] = mapped_column(default=utcnow)  # server time (authoritative)
    payload_redacted: Mapped[dict[str, Any]] = mapped_column(default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64))
    # References produced while processing: {"context_item_id", "tool_invocation_id", "policy_decision_id",
    # "finding_ids": [...], "source_id", "destination_id", "approval_id"}
    refs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    processing_status: Mapped[str] = mapped_column(String(16), default="processed")  # processed|error
    processing_error: Mapped[str | None] = mapped_column(Text, default=None)
    api_key_id: Mapped[str | None] = mapped_column(String(40), default=None)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(OrgScopedMixin, Base):
    """Append-only, keyed hash-chained audit trail. See docs/SECURITY_MODEL.md for the threat model."""

    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("organization_id", "seq"),)

    id: Mapped[str] = id_column()
    seq: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(default=utcnow)
    actor_type: Mapped[str] = mapped_column(String(16))  # user|api_key|system
    actor_id: Mapped[str | None] = mapped_column(String(40), default=None)
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "policy.updated", "tool.denied"
    target_type: Mapped[str | None] = mapped_column(String(48), default=None)
    target_id: Mapped[str | None] = mapped_column(String(40), default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)  # redacted
    prev_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    hash: Mapped[str] = mapped_column(String(64))


class Integration(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "kind", "name"),)

    id: Mapped[str] = id_column()
    kind: Mapped[str] = mapped_column(String(48))  # claude_code|mcp_gateway|python_sdk|...
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="never_seen")  # connected|stale|never_seen|error
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    last_event_at: Mapped[datetime | None] = mapped_column(default=None)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    decision_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, default=None)


class SimulationRun(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "simulation_runs"

    id: Mapped[str] = id_column()
    scenario_id: Mapped[str] = mapped_column(String(100), index=True)
    scenario_name: Mapped[str] = mapped_column(String(200))
    suite_run_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)  # regression suite grouping
    agent_id: Mapped[str | None] = mapped_column(String(40), default=None)
    session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    agent_version: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|completed|failed
    passed: Mapped[bool | None] = mapped_column(Boolean, default=None)
    # Snapshot of the policies/trust rules in effect: [{"policy_id","version","enabled","mode"}]
    policy_snapshot: Mapped[list[Any]] = mapped_column(default=list)
    # [{"step", "expectation", "expected", "actual", "passed", "evidence_ids": [...]}]
    results: Mapped[list[Any]] = mapped_column(default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    triggered_by_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
