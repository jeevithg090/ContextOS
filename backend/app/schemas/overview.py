"""Overview (security command centre) schemas.

Mirrored by ``frontend/src/features/overview/types.ts``. Every number is computed by the server from
persisted rows of the caller's organisation (``app.services.overview_service``); nothing here is a
target, an estimate or a placeholder. Rows produced by the Simulation Lab carry ``is_simulation``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

OverviewWindow = Literal["24h", "7d", "30d"]


class NavCountsOut(BaseModel):
    """Sidebar badges: real (non-simulated) work waiting for someone."""

    pending_approvals: int
    open_incidents: int
    open_findings: int


# ----------------------------------------------------------------------------- posture


class EnforcementCoverageOut(BaseModel):
    """How the window's policy decisions reached the agent: ``enforced`` at an execution boundary that
    honours them, ``advisory`` (returned, may be ignored) or ``observed`` (reported after the fact)."""

    total: int
    enforced: int
    advisory: int
    observed: int
    share: float | None  # enforced / total; None when there were no decisions


class PostureOut(BaseModel):
    agents_total: int
    agents_active: int  # agents that reported an event in the window
    sessions_active: int  # sessions still open that had activity in the window
    trifecta_sessions: int  # sessions with activity in the window whose risk state has all three trifecta legs
    sources_by_trust: dict[str, int]  # current classification of every known source
    open_findings_by_severity: dict[str, int]  # open + acknowledged, all time
    open_findings_total: int
    pending_approvals: int  # still waiting for a human and not past their deadline
    open_incidents: int  # open, investigating or contained
    decisions_by_outcome: dict[str, int]  # window
    decisions_total: int
    enforcement_coverage: EnforcementCoverageOut
    blocked_actions: int  # DENY decisions returned at an enforcing boundary in the window


# ----------------------------------------------------------------------------- series


class EventPointOut(BaseModel):
    t: datetime
    live: int
    simulated: int


class SeverityPointOut(BaseModel):
    t: datetime
    critical: int
    high: int
    medium: int
    low: int
    info: int


class DecisionPointOut(BaseModel):
    t: datetime
    ALLOW: int
    DENY: int
    REQUIRE_APPROVAL: int
    RESTRICT: int
    AUDIT: int


class SeriesOut(BaseModel):
    bucket: Literal["hour", "day"]
    events: list[EventPointOut]
    findings_by_severity: list[SeverityPointOut]  # by first detection; false positives excluded
    decisions_by_outcome: list[DecisionPointOut]


# ----------------------------------------------------------------------------- lists


class AgentRefOut(BaseModel):
    id: str
    name: str | None


class RiskyAgentOut(BaseModel):
    id: str
    name: str
    environment: str
    framework: str
    status: str
    risk_score: int
    risk_level: str
    reason: str | None  # label of the largest risk factor in the agent's riskiest open session
    reason_detail: str | None  # that factor's plain-language explanation (redacted)
    session_id: str | None  # the session the score comes from
    trifecta: bool
    open_findings: int
    last_seen_at: datetime | None
    is_simulation: bool


class FindingItemOut(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    status: str
    rule_id: str
    agent: AgentRefOut | None
    session_id: str | None
    incident_id: str | None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulation: bool


class ApprovalItemOut(BaseModel):
    id: str
    summary: str
    agent: AgentRefOut
    session_id: str
    tool_name: str | None
    requested_at: datetime
    expires_at: datetime | None
    seconds_remaining: int | None
    is_simulation: bool


class IncidentItemOut(BaseModel):
    id: str
    number: int
    title: str
    severity: str
    status: str
    opened_at: datetime
    primary_agent: AgentRefOut | None
    is_simulation: bool


class AttentionOut(BaseModel):
    pending_approvals: list[ApprovalItemOut]  # oldest first (closest to timing out)
    critical_findings: list[FindingItemOut]  # open critical, then high
    open_incidents: list[IncidentItemOut]  # most severe, then newest


class ToolRefOut(BaseModel):
    name: str | None
    category: str | None
    server: str | None


class BlockedActionOut(BaseModel):
    invocation_id: str
    session_id: str
    agent: AgentRefOut
    tool: ToolRefOut
    action: str  # plain-language description built from the redacted arguments
    decision: str
    enforcement: str
    status: str
    outcome: str  # what actually happened, worded honestly for the enforcement mode
    reason: str | None  # policy explanation (redacted, truncated)
    policy_decision_id: str | None
    approval_id: str | None
    at: datetime
    is_simulation: bool


class IntegrationHealthOut(BaseModel):
    id: str
    kind: str
    name: str
    status: Literal["connected", "stale", "never_seen", "error"]
    status_reason: str
    last_event_at: datetime | None
    event_count: int
    decision_count: int
    enforcement_capable: bool
    enforcement_note: str
    last_error: str | None


class ActivityOut(BaseModel):
    id: str
    seq: int
    occurred_at: datetime
    actor_type: str
    actor_id: str | None
    actor_label: str
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]  # redacted, bounded


class OnboardingOut(BaseModel):
    has_agents: bool  # a real (non-simulated) agent has reported
    has_api_key: bool  # an active API key exists
    has_events: bool  # a real event has been ingested
    has_simulations: bool  # a Simulation Lab run exists


class SimulatedShareOut(BaseModel):
    """Simulation Lab rows in the window (counted whether or not they are included above)."""

    events: int
    findings: int
    decisions: int


class OverviewOut(BaseModel):
    window: OverviewWindow
    bucket: Literal["hour", "day"]
    since: datetime
    until: datetime
    generated_at: datetime
    include_simulated: bool
    posture: PostureOut
    series: SeriesOut
    top_risky_agents: list[RiskyAgentOut]
    recent_findings: list[FindingItemOut]
    attention: AttentionOut
    recent_blocked_or_paused: list[BlockedActionOut]
    integrations: list[IntegrationHealthOut]
    recent_activity: list[ActivityOut]
    onboarding: OnboardingOut
    simulated: SimulatedShareOut
