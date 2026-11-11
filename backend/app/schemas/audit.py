"""API schemas for the audit log and its hash-chain verification."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

ActorTypeLiteral = Literal["user", "api_key", "system"]


class AuditEventOut(BaseModel):
    id: str
    seq: int
    occurred_at: datetime
    actor_type: str
    actor_id: str | None
    # Resolved display name of the actor (user name, API key name) when it still exists.
    actor_label: str | None
    # Secondary actor detail: a user's email (only shown to signed-in users) or an API key prefix.
    actor_detail: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    prev_hash: str | None
    hash: str


class AuditThreatModelOut(BaseModel):
    detects: list[str]
    does_not_protect_against: list[str]
    anchoring: str


class AuditVerifyOut(BaseModel):
    valid: bool
    checked: int
    head_seq: int
    head_hash: str | None
    first_invalid_seq: int | None
    first_invalid_entry_id: str | None
    reason: str | None
    # Plain-language interpretation of ``reason``: what kind of tampering it indicates.
    reason_explained: str | None
    summary: str
    verified_at: datetime
    threat_model: AuditThreatModelOut
