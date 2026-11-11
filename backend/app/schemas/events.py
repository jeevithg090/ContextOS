"""API schemas for event ingestion, decisions, the event log, content scanning and approval polling.

The integration contract itself (``EventEnvelope``, ``EventBatch``, ``EventResult``,
``DecisionResponse``) lives in ``app.events.envelope`` and is re-exported here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import SourceType
from app.events.envelope import DecisionResponse, EventBatch, EventEnvelope, EventResult
from app.schemas.common import ORM

__all__ = [
    "ApprovalCancelIn",
    "ApprovalPollOut",
    "DecisionResponse",
    "EventBatch",
    "EventBatchOut",
    "EventEnvelope",
    "EventResult",
    "IngestedEventDetailOut",
    "IngestedEventOut",
    "ScanDetectionOut",
    "ScanHitOut",
    "ScanIn",
    "ScanOut",
    "ScanSecretOut",
]


class EventBatchOut(BaseModel):
    """One result per submitted event, in order. ``rejected`` events were not stored."""

    results: list[EventResult]


class IngestedEventOut(BaseModel):
    """An entry of the append-only event log (redacted; server-assigned ``sequence`` orders it)."""

    model_config = ORM

    id: str
    client_event_id: str
    event_type: str
    schema_version: str
    sequence: int
    agent_id: str | None = None
    agent_name: str | None = None
    session_id: str | None = None
    external_session_id: str | None = None
    correlation_id: str | None = None
    integration: str | None = None
    occurred_at: datetime = Field(description="Client-reported time (untrusted, display only)")
    received_at: datetime = Field(description="Server time (authoritative)")
    refs: dict[str, Any] = Field(default_factory=dict)
    processing_status: str = Field(description="processed | error")
    processing_error: str | None = None
    api_key_id: str | None = None
    is_simulation: bool = False


class IngestedEventDetailOut(IngestedEventOut):
    payload_redacted: dict[str, Any] = Field(
        default_factory=dict,
        description="The event as stored: secrets redacted, context text reduced to sha256/length/preview",
    )
    payload_hash: str


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=200_000)
    source_type: SourceType | None = None
    content_type: str | None = Field(default=None, max_length=64)


class ScanHitOut(BaseModel):
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: float
    explanation: str
    excerpt: str | None = Field(default=None, description="Redacted excerpt around the match")
    technique: str


class ScanDetectionOut(BaseModel):
    score: float
    max_severity: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    hit_count: int = 0
    classifier_score: float | None = None
    hits: list[ScanHitOut] = Field(default_factory=list)


class ScanSecretOut(BaseModel):
    """Where a secret is in the submitted content. The value (and its fingerprint) is never returned."""

    type: str
    start: int = Field(description="Offset of the first character in the submitted content")
    end: int = Field(description="Offset one past the last character")
    confidence: float


class ScanOut(BaseModel):
    """Detection over submitted content. Nothing is persisted."""

    detection: ScanDetectionOut
    hits: list[ScanHitOut] = Field(default_factory=list, description="Same as detection.hits")
    secrets: list[ScanSecretOut] = Field(default_factory=list)
    sensitivity: str
    content_length: int
    content_sha256: str
    redacted_preview: str


class ApprovalPollOut(BaseModel):
    """Polled by integrations holding a tool call while a person decides."""

    approval_id: str
    status: str
    decided_at: datetime | None = None
    decision_note: str | None = None
    expires_at: datetime | None = None


class ApprovalCancelIn(BaseModel):
    """An integration that stopped waiting for a reviewer (timeout, user abort) withdraws the request."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500, description="Why the integration stopped waiting")
