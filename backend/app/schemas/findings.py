"""Security Intelligence schemas: findings list, statistics, detail (resolved evidence + related
records) and triage requests.

Mirrored by ``frontend/src/features/intelligence/types.ts``. Every value is computed by the server
from persisted rows; nothing here is accepted from integrations. Evidence excerpts were redacted
before they were stored.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.domain.enums import FindingStatus

PROVENANCE_NOTE = (
    "These links are relationships ContextOS observed and recorded (this content entered this session, this "
    "session made this call). They show what happened in sequence, not that one step caused the next."
)

# ----------------------------------------------------------------------------- references


class AgentRefOut(BaseModel):
    id: str
    name: str


class SessionRefOut(BaseModel):
    id: str
    external_session_id: str


class SourceRefOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None
    trust_level: str


class IncidentRefOut(BaseModel):
    id: str
    number: int
    title: str
    status: str
    severity: str


class UserRefOut(BaseModel):
    id: str
    name: str


# ----------------------------------------------------------------------------- list


class FindingSummaryOut(BaseModel):
    id: str
    title: str
    category: str
    rule_id: str
    severity: str
    confidence: float = Field(description="0..1 — how sure the detector is that this is a real problem")
    status: str
    agent: AgentRefOut | None
    session: SessionRefOut | None
    source: SourceRefOut | None
    incident: IncidentRefOut | None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulation: bool


# ----------------------------------------------------------------------------- stats


class SeverityCountsOut(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class CategoryCountOut(BaseModel):
    category: str
    count: int


class TrendPointOut(BaseModel):
    t: datetime = Field(description="Start of the bucket (UTC)")
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class TopSourceOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None
    trust_level: str
    count: int = Field(
        description="Findings first seen in the window for this source, excluding false positives"
    )
    max_severity: str | None


class AgentFacetOut(BaseModel):
    id: str
    name: str
    count: int


class MttrOut(BaseModel):
    mean_seconds: float | None = Field(description="Mean time from first detection to resolution")
    median_seconds: float | None
    resolved_count: int = Field(description="Findings resolved in the window that the figures are based on")


class OpenBacklogOut(BaseModel):
    """Current state, independent of the window: findings still open or acknowledged."""

    total: int
    needs_triage: int = Field(description="Open findings nobody has acknowledged yet")
    acknowledged: int
    by_severity: SeverityCountsOut
    by_category: list[CategoryCountOut]
    oldest_first_seen_at: datetime | None


class PeriodStatsOut(BaseModel):
    """Findings first detected inside the window."""

    total: int
    by_severity: SeverityCountsOut
    by_category: list[CategoryCountOut]
    by_status: dict[str, int]
    trend: list[TrendPointOut] = Field(
        description="New findings per bucket by severity, excluding false positives"
    )
    top_sources: list[TopSourceOut]
    mttr: MttrOut


class FindingStatsOut(BaseModel):
    window: str
    bucket: Literal["hour", "day"]
    since: datetime
    until: datetime
    include_simulated: bool
    simulated_open: int = Field(
        description="Open simulated findings not counted because simulations are hidden"
    )
    open: OpenBacklogOut
    period: PeriodStatsOut
    agents: list[AgentFacetOut] = Field(description="Agents with findings (any time), for filtering")
    categories: list[CategoryCountOut] = Field(
        description="Categories with findings (any time), for filtering"
    )


# ----------------------------------------------------------------------------- detail


class EvidenceOut(BaseModel):
    type: str
    id: str | None
    label: str | None = Field(description="Display name of the referenced record, when it still exists")
    session_id: str | None = Field(description="Session the referenced record belongs to (for linking)")
    excerpt: str | None = Field(description="Redacted excerpt recorded at detection time")
    detail: str | None
    found: bool = Field(description="False when the referenced record no longer exists in this organisation")


class RelatedAgentOut(BaseModel):
    id: str
    name: str
    framework: str
    environment: str
    status: str


class RelatedSessionOut(BaseModel):
    id: str
    external_session_id: str
    status: str
    started_at: datetime
    risk_score: int
    risk_level: str
    trifecta: bool


class RelatedSourceOut(SourceRefOut):
    finding_count: int = Field(
        description="Detections recorded against this source that are not marked false positive "
        "(the trust engine's evidence; findings derived from other findings are not counted twice)"
    )
    max_finding_severity: str | None
    manually_classified: bool


class RetrievalRefOut(BaseModel):
    id: str
    tool_name: str


class RelatedContextItemOut(BaseModel):
    id: str
    collected_via: str
    received_at: datetime
    trust_level: str = Field(description="Trust of the source when the item was received")
    sensitivity: str
    contains_secrets: bool
    content_length: int
    retrieved_by: RetrievalRefOut | None = Field(
        description="The tool call whose result delivered this content"
    )


class RelatedInvocationOut(BaseModel):
    id: str
    session_id: str
    tool_name: str
    tool_category: str
    status: str
    decision: str | None
    enforcement: str
    requested_at: datetime


class MatchedPolicyOut(BaseModel):
    policy_id: str | None
    name: str
    outcome: str | None
    mode: str | None


class RelatedDecisionOut(BaseModel):
    id: str
    session_id: str
    decision: str
    enforcement: str
    explanation: str
    evaluated_at: datetime
    matched_policies: list[MatchedPolicyOut]


class RelatedDestinationOut(BaseModel):
    id: str
    kind: str
    identifier: str
    classification: str


class RelatedTaskOut(BaseModel):
    id: str
    key: str
    title: str
    priority: str
    column: str | None
    done: bool
    archived: bool


class FindingRelatedOut(BaseModel):
    agent: RelatedAgentOut | None
    session: RelatedSessionOut | None
    source: RelatedSourceOut | None
    context_item: RelatedContextItemOut | None
    tool_invocation: RelatedInvocationOut | None
    decision: RelatedDecisionOut | None
    destination: RelatedDestinationOut | None
    incident: IncidentRefOut | None
    tasks: list[RelatedTaskOut]


class IncidentCandidateOut(IncidentRefOut):
    reason: str = Field(description="Why this incident is suggested (same session, same agent, recent)")


class HistoryEntryOut(BaseModel):
    action: str
    from_status: str | None
    to_status: str | None
    actor: str
    note: str | None
    occurred_at: datetime


class FindingDetailOut(FindingSummaryOut):
    explanation: str
    remediation: str | None
    resolution_note: str | None
    resolved_by: UserRefOut | None
    evidence: list[EvidenceOut]
    related: FindingRelatedOut
    history: list[HistoryEntryOut]
    allowed_transitions: list[str]
    incident_candidates: list[IncidentCandidateOut]
    provenance_note: str = PROVENANCE_NOTE


# ----------------------------------------------------------------------------- triage


class FindingUpdateIn(BaseModel):
    status: FindingStatus | None = None
    resolution_note: str | None = Field(default=None, max_length=4000)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _something(self) -> FindingUpdateIn:
        if self.status is None and self.resolution_note is None:
            raise ValueError("Provide a status, a resolution note, or both")
        return self


class FindingIncidentIn(BaseModel):
    incident_id: str | None = Field(
        default=None, max_length=40, description="Attach to this incident; omit to open a new one"
    )
    title: str | None = Field(
        default=None, max_length=400, description="Title for a new incident (defaults to the finding's)"
    )

    model_config = {"extra": "forbid"}


class FindingIncidentOut(BaseModel):
    created: bool = Field(description="True when a new incident was opened")
    incident: IncidentRefOut
    finding: FindingSummaryOut
