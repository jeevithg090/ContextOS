"""Trust rules, policies, decisions, approvals, findings, incidents."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class TrustRule(TimestampMixin, OrgScopedMixin, Base):
    """Configurable trust classification for sources and/or destinations."""

    __tablename__ = "trust_rules"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    applies_to: Mapped[str] = mapped_column(String(16), default="source")  # source|destination|both
    source_type: Mapped[str | None] = mapped_column(String(32), default=None)  # None = any type
    match_field: Mapped[str] = mapped_column(String(16), default="identifier")  # identifier|domain
    pattern: Mapped[str] = mapped_column(String(1024))  # glob, e.g. "github.com/acme/*" or "*.acme.com"
    trust_level: Mapped[str] = mapped_column(String(16))
    capabilities: Mapped[list[Any]] = mapped_column(default=list)  # TrustCapability values
    priority: Mapped[int] = mapped_column(Integer, default=100)  # higher wins
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)


class SecurityPolicy(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "security_policies"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mode: Mapped[str] = mapped_column(String(16), default="enforce")  # PolicyMode
    priority: Mapped[int] = mapped_column(Integer, default=100)
    outcome: Mapped[str] = mapped_column(String(32))  # Decision
    conditions: Mapped[dict[str, Any]] = mapped_column(default=dict)  # policy DSL, see engines/policy
    restrictions: Mapped[dict[str, Any]] = mapped_column(default=dict)  # for RESTRICT outcomes
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list[Any]] = mapped_column(default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    builtin_key: Mapped[str | None] = mapped_column(String(100), default=None)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)


class PolicyDecision(OrgScopedMixin, Base):
    """Immutable record of one policy evaluation, including the exact (redacted) input used.

    ``input_snapshot`` makes counterfactual replay honest: alternative policies are evaluated
    against what was actually recorded, never against reconstructed data.
    """

    __tablename__ = "policy_decisions"
    __table_args__ = (
        Index("ix_policy_decisions_org_session", "organization_id", "session_id"),
        Index(
            "ix_policy_decisions_org_evaluated", "organization_id", "evaluated_at"
        ),  # retention, time ranges
    )

    id: Mapped[str] = id_column()
    agent_id: Mapped[str] = mapped_column(String(40), index=True)
    session_id: Mapped[str] = mapped_column(String(40))
    tool_invocation_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    event_id: Mapped[str | None] = mapped_column(String(40), default=None)
    decision: Mapped[str] = mapped_column(String(32))  # Decision returned to the integration
    enforcement: Mapped[str] = mapped_column(String(16), default="observed")  # EnforcementMode
    matched_policies: Mapped[list[Any]] = mapped_column(
        default=list
    )  # [{"policy_id","name","version","outcome","mode","explanation"}]
    monitor_matches: Mapped[list[Any]] = mapped_column(default=list)  # monitor-mode matches (recorded only)
    explanation: Mapped[str] = mapped_column(Text, default="")
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(default=utcnow)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)


class Approval(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "approvals"

    id: Mapped[str] = id_column()
    policy_decision_id: Mapped[str] = mapped_column(String(40), index=True)
    tool_invocation_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    agent_id: Mapped[str] = mapped_column(String(40), index=True)
    session_id: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # ApprovalStatus
    summary: Mapped[str] = mapped_column(Text, default="")
    risk_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    requested_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    decided_at: Mapped[datetime | None] = mapped_column(default=None)
    decided_by_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    decision_note: Mapped[str | None] = mapped_column(Text, default=None)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)


class SecurityFinding(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "security_findings"
    __table_args__ = (Index("ix_findings_org_fingerprint", "organization_id", "fingerprint"),)

    id: Mapped[str] = id_column()
    agent_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    session_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    category: Mapped[str] = mapped_column(String(48))  # FindingCategory
    rule_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(400))
    explanation: Mapped[str] = mapped_column(Text)  # why this was raised, in plain language
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0..1
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # FindingStatus
    # [{"type": "context_item"|"tool_invocation"|"policy_decision"|"event"|"source"|"destination",
    #   "id": str, "excerpt": str|None (redacted), "detail": str|None}]
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    source_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    context_item_id: Mapped[str | None] = mapped_column(String(40), default=None)
    tool_invocation_id: Mapped[str | None] = mapped_column(String(40), default=None)
    policy_decision_id: Mapped[str | None] = mapped_column(String(40), default=None)
    destination_id: Mapped[str | None] = mapped_column(String(40), default=None)
    incident_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))  # dedupe key
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    remediation: Mapped[str | None] = mapped_column(Text, default=None)
    resolved_by_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    resolution_note: Mapped[str | None] = mapped_column(Text, default=None)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)


class Incident(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "incidents"

    id: Mapped[str] = id_column()
    number: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(400))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # IncidentStatus
    assignee_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    primary_agent_id: Mapped[str | None] = mapped_column(String(40), default=None)
    primary_session_id: Mapped[str | None] = mapped_column(String(40), default=None)
    opened_at: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by: Mapped[str] = mapped_column(String(40), default="system")  # "system" or user id
    resolution: Mapped[str | None] = mapped_column(Text, default=None)
    tags: Mapped[list[Any]] = mapped_column(default=list)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=False)


class IncidentActivity(OrgScopedMixin, Base):
    __tablename__ = "incident_activities"

    id: Mapped[str] = id_column()
    incident_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    actor: Mapped[str] = mapped_column(String(40))  # user id or "system"
    kind: Mapped[str] = mapped_column(
        String(32)
    )  # note|status_change|finding_linked|assigned|exported|created
    body: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
