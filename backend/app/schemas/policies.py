"""Policy Studio schemas: policies, match statistics, validation and dry-run tests.

Policy semantics live in ``app.engines.policy`` (condition DSL, precedence, RESTRICT merging).
These models only describe the HTTP contract mirrored by ``frontend/src/features/policies/types.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.common import ORM

DecisionName = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT"]  # == domain.enums.Decision
ModeName = Literal["enforce", "monitor"]  # == domain.enums.PolicyMode
SeverityName = Literal["critical", "high", "medium", "low", "info"]  # == domain.enums.Severity

NAME_MAX = 200
DESCRIPTION_MAX = 4000
PRIORITY_RANGE = (0, 100_000)
MAX_TAGS = 20
TAG_MAX = 48

SIMULATION_LABEL = "Simulation — not a historical outcome"


def _clean_name(value: str | None) -> str | None:
    return None if value is None else " ".join(value.split())


def _clean_tags(tags: list[str] | None) -> list[str] | None:
    if tags is None:
        return None
    out: list[str] = []
    for tag in tags:
        t = tag.strip().lower()
        if not t:
            continue
        if len(t) > TAG_MAX:
            raise ValueError(f"tags must be at most {TAG_MAX} characters")
        if t not in out:
            out.append(t)
    if len(out) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags")
    return out


# ----------------------------------------------------------------------------- read models


class PolicyMatchStats(BaseModel):
    """How often the policy matched recorded decisions, computed from ``PolicyDecision`` rows."""

    window_days: int
    matched: int = Field(description="Real (non-simulated) decisions where it matched in enforce mode")
    monitor_matched: int = Field(
        description="Real decisions where it matched in monitor mode (recorded only)"
    )
    simulated: int = Field(description="Simulation Lab decisions where it matched (either mode)")
    last_matched_at: datetime | None = None
    daily: list[int] = Field(description="Real matches (both modes) per UTC day, oldest first")


class PolicyOut(BaseModel):
    model_config = ORM

    id: str
    name: str
    description: str | None
    enabled: bool
    mode: str
    priority: int
    outcome: str
    conditions: dict[str, Any]
    restrictions: dict[str, Any]
    severity: str
    tags: list[str]
    version: int
    is_builtin: bool
    builtin_key: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    explanation: str = Field(description="The conditions in plain English")
    stats: PolicyMatchStats | None = None


# ----------------------------------------------------------------------------- write models


class _PolicyFields(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("name", check_fields=False)
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        cleaned = _clean_name(value)
        if cleaned is not None and not cleaned:
            raise ValueError("name must not be blank")
        return cleaned

    @field_validator("description", check_fields=False)
    @classmethod
    def _description(cls, value: str | None) -> str | None:
        return (value.strip() or None) if value is not None else None

    @field_validator("tags", check_fields=False)
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value)


class PolicyCreate(_PolicyFields):
    name: str = Field(min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    outcome: DecisionName
    mode: ModeName = "enforce"
    enabled: bool = True
    priority: int = Field(default=100, ge=PRIORITY_RANGE[0], le=PRIORITY_RANGE[1])
    severity: SeverityName = "medium"
    conditions: dict[str, Any]
    restrictions: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PolicyPatch(_PolicyFields):
    """Partial update. Omitted fields are unchanged; unknown fields are rejected."""

    name: str | None = Field(default=None, min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    outcome: DecisionName | None = None
    mode: ModeName | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=PRIORITY_RANGE[0], le=PRIORITY_RANGE[1])
    severity: SeverityName | None = None
    conditions: dict[str, Any] | None = None
    restrictions: dict[str, Any] | None = None
    tags: list[str] | None = None


# ----------------------------------------------------------------------------- validation


class ValidateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conditions: Any
    outcome: DecisionName | None = None
    restrictions: Any = None


class ValidateOut(BaseModel):
    valid: bool
    errors: list[str]
    explanation: str | None = Field(description="Plain-English reading of the conditions (null when invalid)")


# ----------------------------------------------------------------------------- dry-run tests


class PolicyDraft(_PolicyFields):
    """An unsaved policy to evaluate. ``id`` refers to the saved policy it would replace, if any."""

    id: str | None = None
    name: str = Field(default="Draft policy", min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    outcome: DecisionName
    mode: ModeName = "enforce"
    enabled: bool = True
    priority: int = Field(default=100, ge=PRIORITY_RANGE[0], le=PRIORITY_RANGE[1])
    severity: SeverityName = "medium"
    conditions: dict[str, Any]
    restrictions: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PolicyTestIn(BaseModel):
    """Dry-run evaluation. Nothing is persisted, audited or returned to an integration.

    Policies: a ``policy`` draft and/or saved ``policy_ids``; ``with_org_policies`` adds every
    enabled policy of the organisation (a draft with an ``id`` replaces its saved version).
    Input: exactly one of ``input`` (an EvaluationInput object) or ``policy_decision_id`` (the
    recorded, redacted ``input_snapshot`` of that decision).
    """

    model_config = ConfigDict(extra="forbid")

    policy: PolicyDraft | None = None
    policy_ids: list[str] = Field(default_factory=list, max_length=200)
    with_org_policies: bool = False
    input: dict[str, Any] | None = None
    policy_decision_id: str | None = None

    @model_validator(mode="after")
    def _check(self) -> PolicyTestIn:
        if (self.input is None) == (self.policy_decision_id is None):
            raise ValueError("provide exactly one of 'input' or 'policy_decision_id'")
        if self.policy is None and not self.policy_ids and not self.with_org_policies:
            raise ValueError("provide a draft 'policy', 'policy_ids' or 'with_org_policies'")
        return self


class PolicyMatchOut(BaseModel):
    policy_id: str
    name: str
    version: int
    outcome: str
    mode: str
    severity: str
    explanation: str


class EvaluationErrorOut(BaseModel):
    policy_id: str
    name: str
    error: str


class EvaluatedPolicyOut(BaseModel):
    id: str
    name: str
    version: int
    outcome: str
    mode: str
    draft: bool = Field(description="True for the unsaved draft from the request")
    forced_enabled: bool = Field(
        description="Disabled policy evaluated as if enabled because it was targeted"
    )


class RecordedDecisionOut(BaseModel):
    """What ContextOS actually decided when the input was recorded (for comparison)."""

    id: str
    session_id: str
    agent_id: str
    decision: str
    enforcement: str
    evaluated_at: datetime
    explanation: str
    matched_policy_names: list[str]
    is_simulation: bool


class PolicyTestOut(BaseModel):
    simulation: Literal[True] = True
    label: str = SIMULATION_LABEL
    decision: str
    matched: list[PolicyMatchOut]
    monitor_matches: list[PolicyMatchOut]
    explanation: str
    restrictions: dict[str, Any]
    deciding_policy_id: str | None
    evaluation_errors: list[EvaluationErrorOut]
    default_decision: str
    evaluated_policies: list[EvaluatedPolicyOut]
    source: Literal["input", "policy_decision"]
    recorded: RecordedDecisionOut | None = None
    evaluated_input: dict[str, Any] = Field(description="The (redacted) input that was evaluated")
    warnings: list[str] = Field(default_factory=list)


# ----------------------------------------------------------------------------- recorded decisions


class DecisionSummaryOut(BaseModel):
    """A recorded policy decision, summarised for pickers and per-policy history."""

    id: str
    session_id: str
    agent_id: str
    agent_name: str | None
    tool_name: str | None
    tool_category: str | None
    decision: str
    enforcement: str
    evaluated_at: datetime
    explanation: str
    is_simulation: bool


class PolicyDecisionMatchOut(DecisionSummaryOut):
    """A recorded decision in which a given policy matched."""

    match_mode: str = Field(description="enforce (influenced the decision) or monitor (recorded only)")
    matched_outcome: str
    matched_version: int | None
    match_explanation: str
