"""API schemas for the Context Explorer: context items, context sources and Context Receipts.

Everything here is built from persisted, already-redacted rows. Raw context content is never stored,
so it can never be returned; secret fingerprints are reported only as a count per secret type.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceRefOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None = None
    domain: str | None = None
    trust_level: str  # the source's CURRENT classification (may differ from an item's trust at ingest)


class AgentRefOut(BaseModel):
    id: str
    name: str | None = None


class SessionRefOut(BaseModel):
    id: str
    external_session_id: str | None = None
    status: str | None = None


class DetectionCountsOut(BaseModel):
    score: float = 0.0
    max_severity: str | None = None
    hit_count: int = 0
    rule_ids: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)


class ContextItemSummaryOut(BaseModel):
    id: str
    source: SourceRefOut
    trust_level: str  # trust at ingest (what the receipt attests to)
    trust_capabilities: list[str] = Field(default_factory=list)
    sensitivity: str
    contains_secrets: bool
    detection: DetectionCountsOut
    finding_count: int = 0
    agent: AgentRefOut
    session: SessionRefOut
    collected_via: str
    collected_at: datetime
    received_at: datetime
    content_type: str
    content_length: int
    tool_invocation_id: str | None = None
    is_simulation: bool = False


class DetectionHitOut(BaseModel):
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: float
    technique: str = "plain"
    explanation: str
    explanation_source: Literal["finding", "category"]  # where the explanation text came from
    excerpt: str | None = None  # redacted excerpt recorded on the finding's evidence
    finding_id: str | None = None


class DetectionDetailOut(DetectionCountsOut):
    classifier_score: float | None = None
    hits: list[DetectionHitOut] = Field(default_factory=list)
    findings_suppressed_reason: str | None = None  # e.g. operator prompts record hits without findings


class SecretTypeCountOut(BaseModel):
    type: str
    count: int


class FindingRefOut(BaseModel):
    id: str
    title: str
    category: str
    rule_id: str
    severity: str
    status: str
    confidence: float
    last_seen_at: datetime
    incident_id: str | None = None


class ProvenanceEndpointOut(BaseModel):
    type: str
    id: str


class ProvenanceEdgeOut(BaseModel):
    id: str
    relation: str
    src: ProvenanceEndpointOut
    dst: ProvenanceEndpointOut
    confidence: str  # "observed" | "inferred"
    observed_at: datetime


class ToolInvocationRefOut(BaseModel):
    id: str
    tool_name: str | None = None
    tool_provider: str | None = None
    tool_category: str | None = None
    status: str
    decision: str | None = None
    enforcement: str
    requested_at: datetime
    completed_at: datetime | None = None


class ContextItemDetailOut(ContextItemSummaryOut):
    event_id: str
    content_hash: str | None = None
    redacted_preview: str | None = None
    preview_stored: bool  # False when the organisation disabled previews or the content was empty
    preview_truncated: bool
    secret_fingerprint_count: int
    secret_types: list[SecretTypeCountOut] = Field(default_factory=list)
    detection: DetectionDetailOut  # richer than the summary counts
    findings: list[FindingRefOut] = Field(default_factory=list)
    tool_invocation: ToolInvocationRefOut | None = None
    origin_agent: AgentRefOut | None = None  # for agent output / inter-agent messages
    origin_session_id: str | None = None
    item_metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceEdgeOut] = Field(default_factory=list)
    provenance_note: str
    has_receipt_signature: bool


class SubsequentEventOut(BaseModel):
    id: str
    sequence: int
    event_type: str
    summary: str
    occurred_at: datetime  # client-reported
    received_at: datetime  # server time (authoritative)
    processing_status: str
    tool_name: str | None = None
    decision: str | None = None
    enforcement: str | None = None
    tool_invocation_id: str | None = None
    policy_decision_id: str | None = None
    context_item_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)


class ReceiptRelatedOut(BaseModel):
    source: SourceRefOut
    agent: AgentRefOut
    session: SessionRefOut
    tool_invocation: ToolInvocationRefOut | None = None
    findings: list[FindingRefOut] = Field(default_factory=list)
    subsequent_events: list[SubsequentEventOut] = Field(default_factory=list)
    more_subsequent_events: bool = False
    subsequent_events_note: str


class ReceiptVerificationOut(BaseModel):
    status: Literal["valid", "invalid", "missing"]
    algorithm: str
    purpose: str
    explanation: str


class ReceiptTimestampsOut(BaseModel):
    collected_at: datetime  # client-reported, untrusted
    received_at: datetime  # server clock, authoritative
    skew_seconds: float  # received_at - collected_at
    explanation: str


class ReceiptStatementOut(BaseModel):
    summary: str
    proves: list[str]
    does_not_prove: list[str]


class ContextReceiptOut(BaseModel):
    receipt: dict[str, Any]
    signature: str | None = None
    signature_valid: bool
    verification: ReceiptVerificationOut
    timestamps: ReceiptTimestampsOut
    statement: ReceiptStatementOut
    related: ReceiptRelatedOut
    is_simulation: bool = False
    generated_at: datetime


class FacetCountOut(BaseModel):
    value: str
    count: int


class ContextFacetsOut(BaseModel):
    """Counts for the current item filters. Each facet ignores its own filter so the chips can
    show the full distribution and still narrow the list when selected."""

    total: int
    by_trust_level: list[FacetCountOut]
    by_sensitivity: list[FacetCountOut]
    by_source_type: list[FacetCountOut]
    with_detections: int
    with_secrets: int
    simulated_total: int  # simulated items that match the filters (shown when they are hidden)


class ContextSourceSummaryOut(BaseModel):
    id: str
    source_type: str
    identifier: str
    display_name: str | None = None
    domain: str | None = None
    owner: str | None = None
    trust_level: str
    trust_capabilities: list[str] = Field(default_factory=list)
    manually_classified: bool = False
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int = 0
    item_count: int = 0
    agent_count: int = 0
    session_count: int = 0
    finding_count: int = 0
    open_finding_count: int = 0
    max_finding_severity: str | None = None
    items_with_detections: int = 0


class TrustRuleRefOut(BaseModel):
    id: str
    name: str
    pattern: str
    trust_level: str
    enabled: bool


class SourceConsumerOut(BaseModel):
    agent: AgentRefOut
    item_count: int
    session_count: int
    last_received_at: datetime


class ContextSourceDetailOut(ContextSourceSummaryOut):
    trust_reasons: list[str] = Field(default_factory=list)
    trust_rule: TrustRuleRefOut | None = None
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    recent_items: list[ContextItemSummaryOut] = Field(default_factory=list)
    findings: list[FindingRefOut] = Field(default_factory=list)
    consumers: list[SourceConsumerOut] = Field(default_factory=list)
