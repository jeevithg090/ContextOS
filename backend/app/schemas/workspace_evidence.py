"""Engineering Workspace evidence: attachments, code links, fix attempts and verification runs.

Honesty rules encoded here and enforced by the services:
- A fix attempt in ``claimed_complete`` is an agent's or engineer's *claim*. It never verifies or
  resolves the task; only a passed verification run does.
- ``simulation`` verification runs are produced by running a real Simulation Lab scenario; their
  status is taken from the run, never from the client.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.workspace import (
    AgentToolName,
    AttachmentKindName,
    FixStatusName,
    LinkKindName,
    Strict,
    UserRefOut,
    VerificationKindName,
    VerificationRunStatusName,
)

ATTACHMENT_MAX_BYTES = 100 * 1024


class AttachmentCreate(Strict):
    name: str = Field(min_length=1, max_length=400)
    kind: AttachmentKindName = "note"
    url: str | None = Field(default=None, max_length=2048)
    # Byte-size cap (100 KB) is enforced by the service so the error is a clear 413.
    content: str | None = None


class AttachmentOut(BaseModel):
    id: str
    task_id: str
    name: str
    kind: str
    url: str | None
    content: str | None = Field(description="Redacted text content")
    size: int = Field(description="Stored (redacted) content size in bytes")
    created_by: UserRefOut | None
    created_at: datetime


class LinkCreate(Strict):
    kind: LinkKindName
    url: str | None = Field(default=None, max_length=2048)
    title: str | None = Field(default=None, max_length=400)
    ref: str | None = Field(
        default=None, max_length=300, description="Branch name, commit SHA or environment"
    )
    state: str | None = Field(default=None, max_length=32, description="PR: open|draft|merged|closed")


class LinkItemOut(BaseModel):
    index: int
    kind: str
    url: str | None
    title: str | None
    ref: str | None
    state: str | None
    added_at: str | None
    added_by: str | None


class FixAttemptCreate(Strict):
    agent_tool: AgentToolName = "claude_code"
    generated_prompt_id: str | None = None
    status: FixStatusName = "planned"
    branch: str | None = Field(default=None, max_length=300)
    commit_sha: str | None = Field(default=None, max_length=64)
    pr_url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=20_000)


class FixAttemptPatch(Strict):
    status: FixStatusName | None = None
    branch: str | None = Field(default=None, max_length=300)
    commit_sha: str | None = Field(default=None, max_length=64)
    pr_url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=20_000)


class FixAttemptOut(BaseModel):
    id: str
    task_id: str
    generated_prompt_id: str | None
    agent_tool: str
    status: str
    branch: str | None
    commit_sha: str | None
    pr_url: str | None
    notes: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_by: UserRefOut | None
    created_at: datetime
    updated_at: datetime
    is_claim_only: bool = Field(description="True for claimed_complete: a claim, not verification")


class VerificationCreate(Strict):
    kind: VerificationKindName
    status: VerificationRunStatusName | None = Field(
        default=None, description="Required except for kind=simulation (taken from the referenced run)"
    )
    summary: str = Field(default="", max_length=20_000)
    command: str | None = Field(default=None, max_length=4000)
    evidence_url: str | None = Field(default=None, max_length=2048)
    evidence: dict[str, Any] = Field(default_factory=dict)
    fix_attempt_id: str | None = None
    simulation_run_id: str | None = None


class VerifyWithSimulationIn(Strict):
    scenario_id: str = Field(min_length=1, max_length=100)
    fix_attempt_id: str | None = None


class VerificationOut(BaseModel):
    id: str
    task_id: str
    fix_attempt_id: str | None
    kind: str
    status: str
    summary: str
    command: str | None
    evidence_url: str | None
    evidence: dict[str, Any]
    simulation_run_id: str | None
    created_by: UserRefOut | None
    created_at: datetime
    task_verification_status: str = Field(description="The task's verification status after this run")
