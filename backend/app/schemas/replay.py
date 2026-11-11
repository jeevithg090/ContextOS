"""Replay Lab schemas: recorded session replay and counterfactual policy evaluation.

Mirrored by ``frontend/src/features/replay/types.ts``. Replay steps are recorded facts (redacted);
``risk_after`` is recomputed from recorded events and labelled as such. Counterfactual results are
simulations evaluated against each recorded ``PolicyDecision.input_snapshot`` — never history.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.policies import DecisionName, ModeName, PolicyDraft
from app.schemas.sessions import AgentRefOut, TimelineRefsOut, TimelineToolOut

RISK_BASIS = "recomputed from recorded events"
SIMULATION_LABEL = "SIMULATION — hypothetical outcomes evaluated against recorded inputs, not historical fact"
COUNTERFACTUAL_BASIS = "recorded PolicyDecision.input_snapshot"
CAVEATS = (
    "Steps after a hypothetically denied action might not have occurred; their recorded inputs are evaluated as observed.",
    "Events with no recorded policy decision cannot be evaluated.",
)
MAX_POLICY_IDS = 500
MAX_DRAFTS = 20

DefaultDecisionName = Literal["ALLOW", "AUDIT", "REQUIRE_APPROVAL", "DENY"]


# ----------------------------------------------------------------------------- session replay


class ReplaySessionMetaOut(BaseModel):
    id: str
    external_session_id: str
    agent: AgentRefOut
    parent_session_id: str | None
    status: str
    started_at: datetime
    ended_at: datetime | None
    last_event_at: datetime | None
    event_count: int
    risk_score: int = Field(description="The session's current (live) risk score, not a replayed value")
    risk_level: str
    trifecta: bool
    is_simulation: bool


class StepOutcomeOut(BaseModel):
    """What ContextOS recorded for a decision step."""

    policy_decision_id: str
    decision: str
    enforcement: str
    explanation: str
    matched_policies: list[str] = Field(default_factory=list, description="Enforce-mode policies that matched")
    approval_id: str | None = None
    approval_status: str | None = None


class StepFindingOut(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    status: str = Field(description="Current triage status (may have changed since the step)")


class RiskFactorBriefOut(BaseModel):
    key: str
    label: str
    weight: int


class StepRiskOut(BaseModel):
    score: int
    level: str
    delta: int = Field(description="Change from the previous step's recomputed score")
    trifecta: bool
    sensitive_access: bool
    untrusted_exposure: bool
    outbound_channel: bool
    summary: str
    factors: list[RiskFactorBriefOut]
    basis: str = RISK_BASIS


class RecordedRiskOut(BaseModel):
    """Session risk the pipeline recorded when it evaluated this decision (before the call ran)."""

    score: int
    level: str
    trifecta: bool


class ReplayStepOut(BaseModel):
    index: int = Field(description="0-based position in the whole recorded sequence")
    sequence: int = Field(description="Server-assigned event sequence (authoritative ordering)")
    event_id: str
    event_type: str
    received_at: datetime
    occurred_at: datetime = Field(description="Client-reported time (display only)")
    title: str
    summary: str | None
    processing_status: str
    from_other_session: bool
    trust_level: str | None
    tool: TimelineToolOut | None
    refs: TimelineRefsOut
    outcome: StepOutcomeOut | None
    findings: list[StepFindingOut]
    risk_after: StepRiskOut
    recorded_risk: RecordedRiskOut | None


class ReplayOut(BaseModel):
    session: ReplaySessionMetaOut
    basis: str
    risk_basis: str = RISK_BASIS
    risk_note: str
    total_steps: int
    decision_steps: int
    offset: int
    limit: int
    truncated: bool = Field(description="True when steps exist beyond this window")
    focus_index: int | None = Field(default=None, description="Step of the requested decision_id, if found")
    steps: list[ReplayStepOut]


# ----------------------------------------------------------------------------- counterfactual


class PolicyOverrideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: DecisionName | None = None
    mode: ModeName | None = None
    enabled: bool | None = None


class PolicySetIn(BaseModel):
    """The hypothetical policy set. ``base`` "current" starts from every saved policy (as configured
    now); "none" starts empty so only ``add_policies`` are evaluated."""

    model_config = ConfigDict(extra="forbid")

    base: Literal["current", "none"] = "current"
    disable_policy_ids: list[str] = Field(default_factory=list, max_length=MAX_POLICY_IDS)
    overrides: dict[str, PolicyOverrideIn] = Field(default_factory=dict, max_length=MAX_POLICY_IDS)
    add_policies: list[PolicyDraft] = Field(default_factory=list, max_length=MAX_DRAFTS)


class CounterfactualIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=40)
    policy_set: PolicySetIn = Field(default_factory=PolicySetIn)
    default_decision: DefaultDecisionName | None = Field(
        default=None, description="Outcome when no policy matches; the organisation's setting when omitted"
    )


class EvaluatedPolicyOut(BaseModel):
    id: str
    name: str
    version: int
    outcome: str
    mode: str
    enabled: bool
    priority: int
    source: Literal["saved", "draft"]
    changes: list[str] = Field(default_factory=list, description="What this simulation changed, in plain words")


class PolicySetOut(BaseModel):
    base: str
    default_decision: str
    policies: list[EvaluatedPolicyOut]
    warnings: list[str] = Field(default_factory=list)


class HypotheticalMatchOut(BaseModel):
    policy_id: str
    name: str
    version: int
    outcome: str
    mode: str
    severity: str
    explanation: str
    draft: bool = False


class PolicyChangeOut(BaseModel):
    policy_id: str
    name: str
    change: Literal["removed", "disabled", "monitor", "no_longer_matches", "outcome_changed", "newly_matches"]
    detail: str


class EvidenceFieldOut(BaseModel):
    field: str = Field(description="Field path referenced by a matching condition")
    present: bool
    value: Any = Field(default=None, description="Value in the recorded (redacted) input snapshot")
    policies: list[str] = Field(default_factory=list, description="Matching policies whose conditions use this field")


class CounterfactualToolOut(BaseModel):
    name: str | None = None
    category: str | None = None


class CounterfactualStepOut(BaseModel):
    decision_id: str
    invocation_id: str | None
    event_id: str | None
    sequence: int | None
    step_index: int | None = Field(description="Position of the decision's event in the replay steps")
    evaluated_at: datetime
    tool: CounterfactualToolOut
    is_simulation: bool = Field(description="The recorded decision came from Simulation Lab traffic")
    original_decision: str
    original_enforcement: str
    original_matches: list[str]
    original_explanation: str
    hypothetical_decision: str
    changed: bool
    hypothetical_matches: list[HypotheticalMatchOut]
    hypothetical_monitor_matches: list[HypotheticalMatchOut]
    hypothetical_restrictions: dict[str, Any]
    evaluation_errors: list[dict[str, str]]
    current_decision: str = Field(description="Outcome under today's saved policies, without hypothetical changes")
    drifted: bool = Field(description="Today's saved policies already give a different outcome than recorded")
    policy_changes: list[PolicyChangeOut]
    explanation: str
    evidence: list[EvidenceFieldOut]
    after_hypothetical_block: bool = Field(
        description="An earlier step was hypothetically denied or paused, so this step might not have occurred"
    )


class CounterfactualSummaryOut(BaseModel):
    evaluated: int
    changed: int
    would_deny: int
    would_pause: int = Field(description="Hypothetically REQUIRE_APPROVAL")
    would_allow: int = Field(description="Hypothetically ALLOW or AUDIT")
    would_restrict: int
    drifted: int
    transitions: dict[str, int] = Field(default_factory=dict, description='"ORIGINAL→HYPOTHETICAL" counts')


class NotEvaluableOut(BaseModel):
    event_id: str | None
    sequence: int | None
    event_type: str
    reason: str
    policy_decision_id: str | None = None


class CounterfactualOut(BaseModel):
    simulation: Literal[True] = True
    label: str = SIMULATION_LABEL
    basis: str = COUNTERFACTUAL_BASIS
    session_id: str
    policy_set: PolicySetOut
    steps: list[CounterfactualStepOut]
    summary: CounterfactualSummaryOut
    caveats: list[str] = Field(default_factory=lambda: list(CAVEATS))
    not_evaluable_count: int
    not_evaluable: list[NotEvaluableOut]
    truncated: bool = False
