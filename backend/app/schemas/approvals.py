"""API schemas for the Approval Centre (``/api/v1/approvals``).

Everything here is built from persisted rows: the ``Approval``, its ``ToolInvocation`` (redacted
arguments, resources), the ``PolicyDecision`` that paused the call (explanation, matched policies,
recorded input snapshot) and the session's recorded risk state. Nothing is reconstructed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ApprovalDecideIn(BaseModel):
    approve: bool = Field(description="true = let the paused call run; false = reject it")
    note: str | None = Field(
        default=None,
        max_length=2000,
        description="Why you decided this way. Secrets are redacted before storage.",
    )


class UserRefOut(BaseModel):
    id: str
    name: str | None = None
    email: str | None = None


class AgentRefOut(BaseModel):
    id: str
    name: str | None = None
    environment: str | None = None


class SessionRefOut(BaseModel):
    id: str
    external_session_id: str | None = None
    status: str | None = None


class ToolRefOut(BaseModel):
    name: str | None = None
    category: str | None = None
    provider: str | None = None
    server: str | None = None
    risk_level: str | None = None


class ResourceOut(BaseModel):
    kind: str
    id: str
    sensitive: bool = False
    reason: str | None = None


class DestinationRefOut(BaseModel):
    id: str
    kind: str
    identifier: str
    classification: str  # current classification
    classification_at_decision: str | None = None  # what the policy engine saw


class TargetOut(BaseModel):
    primary: str | None = None  # destination host, file, command... what the call acts on
    destination: DestinationRefOut | None = None
    resources: list[ResourceOut] = Field(default_factory=list)  # first few; the detail has all
    resource_count: int = 0
    sensitive_resource_count: int = 0


class MatchedPolicyOut(BaseModel):
    policy_id: str
    name: str
    version: int | None = None
    outcome: str | None = None
    mode: str | None = None
    severity: str | None = None
    explanation: str = ""  # which conditions matched, with the observed values
    description: str | None = None  # the policy's current description (detail only)
    exists: bool = True  # False when the policy was deleted after this decision


class PolicyDecisionRefOut(BaseModel):
    id: str
    decision: str
    enforcement: str
    explanation: str
    evaluated_at: datetime | None = None
    deciding_policy: MatchedPolicyOut | None = None
    matched_policies: list[MatchedPolicyOut] = Field(default_factory=list)


class RiskSummaryOut(BaseModel):
    """Risk recorded when the approval was opened (``Approval.risk_summary``)."""

    session_score: int = 0
    session_level: str | None = None
    trifecta: bool = False
    session_summary: str | None = None
    tool_category: str | None = None
    tool_risk: str | None = None
    destination_classification: str | None = None
    sensitive_resources: list[str] = Field(default_factory=list)
    secrets_in_arguments: int = 0
    session_secret_matches: int = 0
    detections: list[str] = Field(default_factory=list)


class ApprovalOut(BaseModel):
    id: str
    status: str
    summary: str
    action: str  # plain language: "send POST to hooks.webhook.site"
    agent: AgentRefOut
    session: SessionRefOut
    tool: ToolRefOut
    tool_invocation_id: str | None = None
    tool_invocation_status: str | None = None
    target: TargetOut
    policy_decision: PolicyDecisionRefOut | None = None
    risk: RiskSummaryOut
    requires_confirmation: bool = False
    confirmation_reasons: list[str] = Field(default_factory=list)
    requested_at: datetime
    expires_at: datetime | None = None
    seconds_remaining: int | None = None  # pending only; computed by the server
    decided_at: datetime | None = None
    decided_by: UserRefOut | None = None
    decision_note: str | None = None
    is_simulation: bool = False


class DestinationCheckOut(BaseModel):
    check: str
    result: str  # pass | fail | warn | unknown
    detail: str | None = None


class DestinationDetailOut(DestinationRefOut):
    display_name: str | None = None
    checks: list[DestinationCheckOut] = Field(default_factory=list)
    transfer_count: int = 0
    blocked_count: int = 0
    sensitive_transfer_count: int = 0
    first_seen_at: datetime | None = None


class SecretRefOut(BaseModel):
    type: str
    context_item_id: str | None = None  # where the same secret was seen in this session's context


class SecretsOut(BaseModel):
    in_arguments: list[SecretRefOut] = Field(default_factory=list)
    from_session_context: list[SecretRefOut] = Field(default_factory=list)


class DetectionOut(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    max_severity: str | None = None
    categories: list[str] = Field(default_factory=list)


class EvidenceOut(BaseModel):
    type: str
    id: str | None = None
    detail: str | None = None


class TrifectaLegOut(BaseModel):
    key: str  # sensitive_access | untrusted_exposure | outbound_channel
    label: str
    active_at_decision: bool
    evidence: list[EvidenceOut] = Field(default_factory=list)


class SessionRiskOut(BaseModel):
    score_at_decision: int = 0
    level_at_decision: str | None = None
    trifecta_at_decision: bool = False
    legs: list[TrifectaLegOut] = Field(default_factory=list)
    current_score: int = 0
    current_level: str | None = None
    summary: str | None = None
    evidence_computed_at: str | None = None
    # Context summary the policy engine saw: lowest trust, untrusted item count, injection...
    context_at_decision: dict[str, Any] = Field(default_factory=dict)


class ContextItemRefOut(BaseModel):
    id: str
    source_id: str
    source_identifier: str | None = None
    source_display_name: str | None = None
    source_type: str | None = None
    source_trust_level: str | None = None  # current
    trust_level: str  # at ingest time
    collected_via: str
    received_at: datetime
    sensitivity: str
    contains_secrets: bool = False
    detection_max_severity: str | None = None
    detection_hit_count: int = 0
    preview: str | None = None  # redacted, truncated
    tool_invocation_id: str | None = None


class FindingRefOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    last_seen_at: datetime
    linked_to_this_call: bool = False


class ActivityOut(BaseModel):
    id: str
    seq: int
    occurred_at: datetime
    action: str
    actor_type: str
    actor_id: str | None = None
    actor_name: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ApprovalDetailOut(ApprovalOut):
    arguments: dict[str, Any] = Field(default_factory=dict)  # redacted at ingestion
    argument_hash: str | None = None
    resources: list[ResourceOut] = Field(default_factory=list)
    destination: DestinationDetailOut | None = None
    secrets: SecretsOut = Field(default_factory=SecretsOut)
    detection: DetectionOut = Field(default_factory=DetectionOut)
    monitor_matches: list[MatchedPolicyOut] = Field(default_factory=list)
    session_risk: SessionRiskOut = Field(default_factory=SessionRiskOut)
    recent_context: list[ContextItemRefOut] = Field(default_factory=list)
    context_total: int = 0  # context items in the session up to the request
    related_findings: list[FindingRefOut] = Field(default_factory=list)
    enforcement_note: str = ""  # what approving / rejecting actually does for this integration
    activity: list[ActivityOut] = Field(default_factory=list)
