"""Agent-session schemas: lists, detail (risk state with lethal-trifecta evidence) and timelines.

Mirrored by ``frontend/src/features/agents/types.ts``. All values are server-computed from
persisted rows; nothing here is accepted from integrations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import Page

TRIFECTA_NOTE = (
    "The lethal trifecta is a risk condition: sensitive data access, untrusted content and an outbound "
    "channel in the same session. It makes exfiltration through prompt injection possible; it is not proof "
    "that an attack happened."
)


class AgentRefOut(BaseModel):
    id: str
    name: str
    framework: str
    environment: str
    status: str
    is_simulation: bool = False


class FindingBriefOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    session_id: str | None
    last_seen_at: datetime
    occurrence_count: int
    is_simulation: bool


class SessionSummaryOut(BaseModel):
    id: str
    agent: AgentRefOut
    external_session_id: str
    parent_session_id: str | None
    status: str
    started_at: datetime
    ended_at: datetime | None
    last_event_at: datetime | None
    event_count: int
    risk_score: int
    risk_level: str
    trifecta: bool
    sensitive_access: bool
    untrusted_exposure: bool
    outbound_channel: bool
    open_findings: int = Field(description="Findings in this session that are open or acknowledged")
    child_count: int = 0
    is_simulation: bool
    simulation_run_id: str | None


class RiskEvidenceOut(BaseModel):
    type: str  # context_item | tool_invocation | finding | session | tool (declared capability)
    id: str
    detail: str
    label: str | None = None  # resolved display name (source, tool, finding title, agent)
    trust_level: str | None = None  # for context items: trust recorded at ingest
    session_id: str | None = None  # session the referenced record belongs to


class TrifectaConditionOut(BaseModel):
    key: str  # sensitive_access | untrusted_exposure | outbound_channel
    label: str
    description: str
    active: bool
    evidence: list[RiskEvidenceOut] = Field(default_factory=list)


class RiskFactorOut(BaseModel):
    key: str
    label: str
    weight: int
    explanation: str
    evidence: list[RiskEvidenceOut] = Field(default_factory=list)


class SessionRiskOut(BaseModel):
    score: int
    level: str
    summary: str
    trifecta: bool
    conditions: list[TrifectaConditionOut]
    factors: list[RiskFactorOut]
    computed_at: str | None
    note: str = TRIFECTA_NOTE


class SessionRefOut(BaseModel):
    id: str
    external_session_id: str
    agent: AgentRefOut
    status: str
    started_at: datetime
    risk_score: int
    risk_level: str
    trifecta: bool


class SessionCountsOut(BaseModel):
    timeline_entries: int
    context_items: int
    untrusted_context_items: int
    tool_invocations: int
    decisions: dict[str, int]
    enforcement: dict[str, int]
    findings_open: int
    findings_total: int
    approvals_pending: int
    processing_errors: int


class SessionDetailOut(SessionSummaryOut):
    metadata: dict[str, Any]
    risk: SessionRiskOut
    parent: SessionRefOut | None
    children: list[SessionRefOut]
    counts: SessionCountsOut
    findings: list[FindingBriefOut]


class TimelineRefsOut(BaseModel):
    context_item_id: str | None = None
    tool_invocation_id: str | None = None
    policy_decision_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    approval_id: str | None = None
    child_session_id: str | None = None
    source_id: str | None = None
    destination_id: str | None = None


class TimelineToolOut(BaseModel):
    name: str
    category: str
    status: str | None = None


class TimelineEntryOut(BaseModel):
    id: str  # ingested event id
    sequence: int
    received_at: datetime  # server time (authoritative)
    occurred_at: datetime  # client-reported time (display only)
    event_type: str
    title: str
    summary: str | None = None
    trust_level: str | None = None
    decision: str | None = None
    enforcement: str | None = None
    severity: str | None = None
    processing_status: str
    from_other_session: bool = Field(
        default=False,
        description="Recorded in another session (e.g. the parent's delegation that created this session's task)",
    )
    tool: TimelineToolOut | None = None
    refs: TimelineRefsOut


class TimelinePage(Page[TimelineEntryOut]):
    focus_event_ids: list[str] = Field(
        default_factory=list, description="Entries of the requested tool invocation (request and result)"
    )
