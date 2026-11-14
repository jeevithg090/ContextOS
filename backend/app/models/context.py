"""Context sources, context items (receipts) and provenance edges.

A ``ProvenanceEdge`` records an OBSERVED relationship between two entities (e.g. "this context item
entered this session"). It does not assert that the content causally determined a model decision.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class ContextSource(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "context_sources"
    __table_args__ = (UniqueConstraint("organization_id", "source_type", "identifier"),)

    id: Mapped[str] = id_column()
    source_type: Mapped[str] = mapped_column(String(32))  # domain.enums.SourceType
    identifier: Mapped[str] = mapped_column(String(2048))  # canonical URL / path / server name
    display_name: Mapped[str | None] = mapped_column(String(400), default=None)
    domain: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    owner: Mapped[str | None] = mapped_column(String(200), default=None)
    trust_level: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    trust_capabilities: Mapped[list[Any]] = mapped_column(default=list)
    trust_reasons: Mapped[list[Any]] = mapped_column(default=list)  # human-readable explanation lines
    trust_rule_id: Mapped[str | None] = mapped_column(String(40), default=None)
    # True when a human set the classification explicitly (overrides heuristics, not evidence flags).
    manually_classified: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    max_finding_severity: Mapped[str | None] = mapped_column(String(16), default=None)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # True while every observation of this source came from simulated (Simulation Lab) traffic.
    # Ingestion sets it on creation from the event's simulation flag and clears it the first time
    # real traffic observes the same source; it never flips back to True.
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class ContextItem(OrgScopedMixin, Base):
    """One observed piece of context delivered to an agent. Doubles as the Context Receipt."""

    __tablename__ = "context_items"
    __table_args__ = (
        Index("ix_context_items_org_session", "organization_id", "session_id"),
        Index(
            "ix_context_items_org_received", "organization_id", "received_at"
        ),  # retention, time-range scans
    )

    id: Mapped[str] = id_column()
    source_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("context_sources.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str] = mapped_column(String(40), ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str] = mapped_column(String(40), ForeignKey("agent_sessions.id", ondelete="CASCADE"))
    event_id: Mapped[str] = mapped_column(String(40), index=True)  # ingested_events.id
    collected_via: Mapped[str] = mapped_column(String(200))  # e.g. "claude_code:PostToolUse:WebFetch"
    collected_at: Mapped[datetime] = mapped_column()  # client-observed timestamp
    received_at: Mapped[datetime] = mapped_column(default=utcnow)  # server timestamp (authoritative)
    content_type: Mapped[str] = mapped_column(String(64), default="text/plain")
    content_hash: Mapped[str | None] = mapped_column(
        String(64), default=None, index=True
    )  # sha256 of raw content
    content_length: Mapped[int] = mapped_column(Integer, default=0)
    redacted_preview: Mapped[str | None] = mapped_column(
        Text, default=None
    )  # redacted + truncated; never raw
    sensitivity: Mapped[str] = mapped_column(String(16), default="internal")
    contains_secrets: Mapped[bool] = mapped_column(Boolean, default=False)
    secret_fingerprints: Mapped[list[Any]] = mapped_column(default=list)  # [{"type", "fingerprint"}]
    trust_level: Mapped[str] = mapped_column(String(16), default="UNKNOWN")  # trust at ingest time
    trust_capabilities: Mapped[list[Any]] = mapped_column(default=list)
    # {"score": float, "max_severity": str|None, "rule_ids": [...], "hit_count": int}
    detection_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    tool_invocation_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    origin_agent_id: Mapped[str | None] = mapped_column(
        String(40), default=None
    )  # for agent outputs/messages
    origin_session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    receipt_signature: Mapped[str | None] = mapped_column(
        String(64), default=None
    )  # HMAC over receipt fields
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)
    item_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict)


class ProvenanceEdge(OrgScopedMixin, Base):
    __tablename__ = "provenance_edges"
    __table_args__ = (
        Index("ix_prov_src", "organization_id", "src_type", "src_id"),
        Index("ix_prov_dst", "organization_id", "dst_type", "dst_id"),
        Index("ix_prov_org_observed", "organization_id", "observed_at"),  # retention
    )

    id: Mapped[str] = id_column()
    src_type: Mapped[str] = mapped_column(String(32))  # domain.enums.ProvenanceNodeType
    src_id: Mapped[str] = mapped_column(String(2048))
    dst_type: Mapped[str] = mapped_column(String(32))
    dst_id: Mapped[str] = mapped_column(String(2048))
    relation: Mapped[str] = mapped_column(String(64))  # domain.enums.ProvenanceRelation
    session_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    event_id: Mapped[str | None] = mapped_column(String(40), default=None)
    observed_at: Mapped[datetime] = mapped_column(default=utcnow)
    # "observed" = directly recorded; "inferred" = derived by ContextOS (e.g. secret fingerprint match).
    confidence: Mapped[str] = mapped_column(String(16), default="observed")
    edge_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict)
