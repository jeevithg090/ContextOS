"""Incident schemas: list, investigator detail, workflow requests and the investigation timeline.

Mirrored by ``frontend/src/features/incidents/types.ts``. Everything is computed by the server from
persisted rows; free text was redacted before it was stored and is re-redacted on the way out.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import IncidentStatus, Severity

TimelineEntryType = Literal["event", "finding", "policy_decision", "approval", "activity"]

# ----------------------------------------------------------------------------- references


class AgentRefOut(BaseModel):
    id: str
    name: str


class SessionRefOut(BaseModel):
    id: str
    external_session_id: str


class UserRefOut(BaseModel):
    id: str
    name: str


class ActorOut(BaseModel):
    type: Literal["user", "system"]
    id: str | None
    name: str


# ----------------------------------------------------------------------------- list


class IncidentSummaryOut(BaseModel):
    id: str
    number: int
    key: str = Field(description="Display key, e.g. INC-12")
    title: str
    severity: str
    status: str
    assignee: UserRefOut | None
    primary_agent: AgentRefOut | None
    primary_session: SessionRefOut | None
    finding_count: int
    open_finding_count: int = Field(description="Linked findings still open or acknowledged")
    max_finding_severity: str | None
    opened_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    created_by: ActorOut
    is_simulation: bool


# ----------------------------------------------------------------------------- detail


class IncidentFindingOut(BaseModel):
    id: str
    title: str
    category: str
    rule_id: str
    severity: str
    status: str
    confidence: float
    explanation: str
    agent: AgentRefOut | None
    session: SessionRefOut | None
    source_id: str | None
    context_item_id: str | None
    tool_invocation_id: str | None
    policy_decision_id: str | None
    destination_id: str | None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class InvolvedAgentOut(BaseModel):
    id: str
    name: str
    framework: str
    environment: str
    status: str
    finding_count: int
    is_primary: bool


class InvolvedSessionOut(BaseModel):
    id: str
    external_session_id: str
    agent_id: str
    agent_name: str
    status: str
    started_at: datetime
    ended_at: datetime | None
    event_count: int
    risk_score: int
    risk_level: str
    trifecta: bool
    finding_count: int
    is_primary: bool


class InvolvedSourceOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None
    trust_level: str = Field(description="The source's current trust classification")
    trust_reasons: list[str | None]
    finding_count: int


class InvolvedDestinationOut(BaseModel):
    id: str
    kind: str
    identifier: str
    display_name: str | None
    classification: str
    transfer_count: int
    blocked_count: int
    finding_count: int


class InvolvedOut(BaseModel):
    agents: list[InvolvedAgentOut]
    sessions: list[InvolvedSessionOut]
    sources: list[InvolvedSourceOut]
    destinations: list[InvolvedDestinationOut]
    note: str


class ActivityOut(BaseModel):
    id: str
    kind: str
    actor: ActorOut
    body: str
    details: dict[str, Any]
    created_at: datetime


class LinkedTaskOut(BaseModel):
    id: str
    key: str
    title: str
    priority: str
    column: str | None
    done: bool
    archived: bool
    related_finding_id: str | None
    parent_task_id: str | None


class IncidentDetailOut(IncidentSummaryOut):
    summary: str
    resolution: str | None
    tags: list[Any]
    allowed_transitions: list[str]
    findings: list[IncidentFindingOut]
    involved: InvolvedOut
    activity: list[ActivityOut]
    tasks: list[LinkedTaskOut]


# ----------------------------------------------------------------------------- requests


class IncidentCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=400)
    summary: str = Field(default="", max_length=8000)
    severity: Severity
    finding_ids: list[str] = Field(default_factory=list, max_length=200)


class IncidentUpdateIn(BaseModel):
    """Send only the fields to change. ``assignee_user_id: null`` unassigns."""

    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus | None = None
    severity: Severity | None = None
    assignee_user_id: str | None = Field(default=None, max_length=40)
    resolution: str | None = Field(default=None, max_length=8000)

    @model_validator(mode="after")
    def _something(self) -> IncidentUpdateIn:
        if not self.model_fields_set:
            raise ValueError("Provide at least one of status, severity, assignee_user_id or resolution")
        for name in ("status", "severity"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=8000)


class LinkFindingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_ids: list[str] = Field(min_length=1, max_length=200)


class LinkFindingsOut(BaseModel):
    linked: list[str] = Field(description="Findings attached by this request")
    already_linked: list[str] = Field(description="Findings that were already part of this incident")
    incident: IncidentDetailOut


# ----------------------------------------------------------------------------- timeline


class TimelineRefsOut(BaseModel):
    event_id: str | None
    session_id: str | None
    context_item_id: str | None
    tool_invocation_id: str | None
    policy_decision_id: str | None
    approval_id: str | None
    source_id: str | None
    destination_id: str | None
    finding_id: str | None
    finding_ids: list[str]


class TimelineEntryOut(BaseModel):
    id: str = Field(description="'<type>:<record id>' (approvals add ':requested' / ':decided')")
    type: TimelineEntryType
    occurred_at: datetime = Field(description="ContextOS server time")
    title: str
    summary: str | None
    severity: str | None
    status: str | None
    decision: str | None
    enforcement: str | None
    trust_level: str | None
    event_type: str | None
    sequence: int | None
    session_id: str | None
    agent_id: str | None
    actor: ActorOut | None
    tool_name: str | None
    from_other_session: bool
    refs: TimelineRefsOut


class IncidentTimelineOut(BaseModel):
    incident_id: str
    items: list[TimelineEntryOut]
    total: int = Field(description="Entries matching the type filter (before the limit)")
    truncated: bool
    counts: dict[str, int] = Field(description="Entries per type, ignoring the type filter")
    session_ids: list[str] = Field(description="Sessions whose events are included")
    recorded_event_count: int
    note: str
