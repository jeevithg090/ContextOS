"""Trust Centre schemas: trust rules, source and destination classification, dry-run assessments.

Trust semantics live in ``app.engines.trust`` (glob matching, precedence, evidence downgrades,
destination checks). These models only describe the HTTP contract mirrored by
``frontend/src/features/trust/types.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

TrustLevelName = Literal["TRUSTED", "APPROVED", "EXTERNAL", "UNKNOWN", "SUSPICIOUS", "BLOCKED"]
AppliesToName = Literal["source", "destination", "both"]
ScopeName = Literal["source", "destination"]
MatchFieldName = Literal["identifier", "domain"]
CapabilityName = Literal["read", "instruct", "execute", "credential_access", "send"]
DestinationKindName = Literal["domain", "ip", "email", "service", "agent", "unknown"]
SourceTypeName = Literal[
    "web", "repository", "file", "document", "email", "api", "mcp_server", "mcp_tool", "browser", "database",
    "user_upload", "user_prompt", "tool_output", "agent_output", "system", "other",
]  # == domain.enums.SourceType
CheckResultName = Literal["pass", "warn", "fail", "unknown"]

NAME_MAX = 200
DESCRIPTION_MAX = 2000
NOTE_MAX = 1000
PATTERN_MAX = 1024
PRIORITY_MAX = 100_000

_STRICT = ConfigDict(extra="forbid")


def _clean_name(value: str | None) -> str | None:
    if value is None:
        return None
    name = " ".join(value.split())
    if not name:
        raise ValueError("must not be blank")
    return name


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _required_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        raise ValueError("must not be blank")
    return text


# ----------------------------------------------------------------------------- shared read models


class ReassessSummaryOut(BaseModel):
    """What a bulk re-assessment after a rule change touched (bounded to ``limit`` rows per kind)."""

    sources_checked: int
    sources_changed: int
    destinations_checked: int
    destinations_changed: int
    truncated: bool = Field(description="True when more rows existed than were re-assessed")
    limit: int


class RuleRefOut(BaseModel):
    """A trust rule as it took part in an assessment (``id`` is None for an unsaved draft)."""

    id: str | None
    name: str
    pattern: str
    match_field: str
    applies_to: str
    source_type: str | None
    trust_level: str
    priority: int
    is_draft: bool = False


class CheckOut(BaseModel):
    check: str
    result: str
    detail: str


class AssessmentOut(BaseModel):
    scope: ScopeName
    level: str
    capabilities: list[str]
    reasons: list[str]
    canonical_identifier: str
    domain: str | None = None
    kind: str | None = Field(default=None, description="Destinations: the resolved destination kind")
    matched_rule: RuleRefOut | None = None
    matching_rules: list[RuleRefOut] = Field(
        default_factory=list, description="Every enabled rule that matches, in precedence order (the first decides)"
    )
    checks: list[CheckOut] = Field(default_factory=list, description="Destinations: checks actually performed")
    not_verified: list[str] = Field(default_factory=list, description="Destinations: what was NOT verified")


class ExistingRecordOut(BaseModel):
    """The stored source/destination the tested identifier corresponds to, if any."""

    type: ScopeName
    id: str
    current_level: str
    manually_classified: bool = False
    finding_count: int = 0
    observation_count: int = 0
    transfer_count: int = 0
    with_history: AssessmentOut = Field(
        description="What re-assessing this record now would produce, including its recorded history"
    )


# ----------------------------------------------------------------------------- rules


class TrustRuleOut(BaseModel):
    id: str
    name: str
    description: str | None
    applies_to: str
    source_type: str | None
    match_field: str
    pattern: str
    trust_level: str
    capabilities: list[str]
    priority: int
    enabled: bool
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    is_default: bool = Field(description="One of the default rules installed for new organisations")
    is_override: bool = Field(description="An exact-match destination rule created by classifying a destination")
    classified_sources: int = Field(description="Sources currently classified by this rule")
    classified_destinations: int = Field(description="Destinations currently classified by this rule")
    reassessment: ReassessSummaryOut | None = Field(
        default=None, description="Set on create/update responses: the re-assessment the change triggered"
    )


class TrustRuleCreate(BaseModel):
    model_config = _STRICT

    name: str = Field(min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    applies_to: AppliesToName = "source"
    source_type: SourceTypeName | None = None
    match_field: MatchFieldName = "identifier"
    pattern: str = Field(min_length=1, max_length=PATTERN_MAX)
    trust_level: TrustLevelName
    capabilities: list[CapabilityName] | None = Field(
        default=None, description="Omit to use the level's defaults (e.g. TRUSTED sources: read, instruct, execute)"
    )
    priority: int = Field(default=100, ge=0, le=PRIORITY_MAX)
    enabled: bool = True

    _name = field_validator("name")(lambda v: _clean_name(v))
    _description = field_validator("description")(lambda v: _clean_text(v))
    _pattern = field_validator("pattern")(lambda v: _required_text(v))


class TrustRulePatch(BaseModel):
    model_config = _STRICT

    name: str | None = Field(default=None, min_length=1, max_length=NAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    applies_to: AppliesToName | None = None
    source_type: SourceTypeName | None = None
    match_field: MatchFieldName | None = None
    pattern: str | None = Field(default=None, min_length=1, max_length=PATTERN_MAX)
    trust_level: TrustLevelName | None = None
    capabilities: list[CapabilityName] | None = None
    priority: int | None = Field(default=None, ge=0, le=PRIORITY_MAX)
    enabled: bool | None = None

    _name = field_validator("name")(lambda v: _clean_name(v))
    _description = field_validator("description")(lambda v: _clean_text(v))
    _pattern = field_validator("pattern")(lambda v: _required_text(v))


class RuleDeleteOut(BaseModel):
    id: str
    reassessment: ReassessSummaryOut


class RuleTestIn(BaseModel):
    """Dry run: classify an identifier with the saved rules (optionally plus an unsaved draft)."""

    model_config = _STRICT

    applies_to: ScopeName = "source"
    source_type: SourceTypeName = Field(default="web", description="Sources: the type of source to classify")
    kind: DestinationKindName = Field(default="unknown", description="Destinations: kind as an integration reports it")
    identifier: str = Field(min_length=1, max_length=2048)
    draft: TrustRuleCreate | None = Field(default=None, description="Evaluate as if this rule were saved")
    replace_rule_id: str | None = Field(
        default=None, max_length=40, description="When editing a saved rule, leave its saved version out of the test"
    )


class RuleTestOut(BaseModel):
    assessment: AssessmentOut = Field(description="Rules only: no recorded history is taken into account")
    draft_errors: list[str] = Field(default_factory=list, description="Why the draft could not be saved as it is")
    draft_matches: bool | None = Field(default=None, description="Whether the draft's pattern matches at all")
    draft_decides: bool | None = Field(default=None, description="Whether the draft is the deciding rule")
    existing: ExistingRecordOut | None = None
    dry_run: bool = True


# ----------------------------------------------------------------------------- sources


class TrustSourceOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None
    domain: str | None
    trust_level: str
    trust_capabilities: list[str]
    trust_rule_id: str | None
    trust_rule_name: str | None
    manually_classified: bool
    observation_count: int
    finding_count: int = Field(description="Findings recorded for this source that are not marked false positive")
    max_finding_severity: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulation: bool = False  # only Simulation Lab traffic has observed this source


class HistoryEntryOut(BaseModel):
    """One trust change taken from the tamper-evident audit trail."""

    id: str
    at: datetime
    action: str
    summary: str
    from_level: str | None
    to_level: str | None
    actor_type: str
    actor_id: str | None
    actor_label: str
    note: str | None = None


class FindingRefOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    session_id: str | None
    occurrence_count: int
    last_seen_at: datetime
    is_simulation: bool


class SourceItemOut(BaseModel):
    id: str
    session_id: str
    agent_id: str
    agent_name: str | None
    collected_via: str
    received_at: datetime
    trust_level: str = Field(description="Trust the item had when it was ingested")
    max_severity: str | None = Field(description="Highest detection severity in the item, if any")
    is_simulation: bool


class EvidenceDowngradeOut(BaseModel):
    level_without_evidence: str
    level: str
    finding_count: int
    max_severity: str | None
    explanation: str


class ManualClassificationOut(BaseModel):
    at: datetime
    actor_label: str
    level: str | None
    capabilities: list[str]
    note: str | None


class TrustSourceDetailOut(TrustSourceOut):
    trust_reasons: list[str]
    matched_rule: RuleRefOut | None
    evidence_downgrade: EvidenceDowngradeOut | None
    manual_classification: ManualClassificationOut | None
    history: list[HistoryEntryOut]
    findings: list[FindingRefOut]
    findings_total: int
    recent_items: list[SourceItemOut]


class SourceClassifyIn(BaseModel):
    model_config = _STRICT

    trust_level: TrustLevelName
    capabilities: list[CapabilityName] | None = Field(default=None, description="Omit to use the level's defaults")
    note: str = Field(min_length=1, max_length=NOTE_MAX, description="Why; recorded in the audit trail")

    _note = field_validator("note")(lambda v: _required_text(v))


# ----------------------------------------------------------------------------- destinations


class VerificationSummaryOut(BaseModel):
    passed: int
    warned: int
    failed: int
    unknown: int


class TrustDestinationOut(BaseModel):
    id: str
    kind: str
    identifier: str
    display_name: str | None
    classification: str
    trust_rule_id: str | None
    trust_rule_name: str | None
    override_rule_id: str | None = Field(description="Exact-match rule that pins this destination's classification")
    transfer_count: int
    blocked_count: int = Field(description="Calls DENIED at an enforcing integration")
    sensitive_transfer_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    verification: VerificationSummaryOut
    is_simulation: bool = False  # every recorded call to this destination was simulated


class DestinationInvocationOut(BaseModel):
    id: str
    session_id: str
    agent_id: str
    agent_name: str | None
    tool_name: str | None
    status: str
    decision: str | None
    enforcement: str
    policy_decision_id: str | None
    decision_explanation: str | None
    requested_at: datetime
    sensitive_data_detected: bool
    is_simulation: bool


class TrustDestinationDetailOut(TrustDestinationOut):
    checks: list[CheckOut]
    assessment: AssessmentOut = Field(description="The destination re-assessed now with the current rules")
    stale: bool = Field(description="The stored classification differs from what the current rules produce")
    invocations: list[DestinationInvocationOut]
    invocations_total: int
    decision_counts: dict[str, int]
    enforcement_counts: dict[str, int]
    findings: list[FindingRefOut]


class DestinationClassifyIn(BaseModel):
    model_config = _STRICT

    classification: TrustLevelName
    note: str = Field(min_length=1, max_length=NOTE_MAX, description="Why; recorded on the rule and in the audit trail")

    _note = field_validator("note")(lambda v: _required_text(v))


class DestinationVerifyIn(BaseModel):
    model_config = _STRICT

    kind: DestinationKindName = "unknown"
    identifier: str = Field(min_length=1, max_length=1024)


class DestinationVerifyOut(BaseModel):
    assessment: AssessmentOut
    existing: ExistingRecordOut | None = None
    dry_run: bool = True


# ----------------------------------------------------------------------------- summary


class LevelDistributionOut(BaseModel):
    total: int
    by_level: dict[str, int]


class SourceSummaryOut(LevelDistributionOut):
    manual: int
    with_findings: int
    can_instruct: int = Field(description="Sources whose content may currently give the agent instructions")


class DestinationSummaryOut(LevelDistributionOut):
    with_blocked_calls: int
    with_sensitive_transfers: int


class RuleSummaryOut(BaseModel):
    total: int
    enabled: int
    source: int
    destination: int


class DowngradeOut(BaseModel):
    target_type: ScopeName
    target_id: str
    label: str
    from_level: str
    to_level: str
    at: datetime
    actor_label: str
    summary: str
    is_simulation: bool = Field(False, description="Only Simulation Lab traffic observed this record")


class TrustSummaryOut(BaseModel):
    sources: SourceSummaryOut
    destinations: DestinationSummaryOut
    rules: RuleSummaryOut
    sources_with_findings: list[TrustSourceOut]
    recently_downgraded: list[DowngradeOut]
    downgrade_window_days: int
