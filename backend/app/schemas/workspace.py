"""Engineering Workspace: shared vocabulary and small read models.

The HTTP contract for boards lives in ``schemas/workspace_boards.py``, tasks in
``schemas/workspace_tasks.py`` and fix/verification evidence in ``schemas/workspace_evidence.py``.
All of it is mirrored by ``frontend/src/features/workspace/types.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

# == domain.enums.TaskType
TaskTypeName = Literal[
    "security_vulnerability", "prompt_injection", "agent_misconfiguration", "data_exposure", "integration_bug",
    "backend", "frontend", "performance", "feature", "tech_debt", "task",
]
PriorityName = Literal["urgent", "high", "medium", "low", "none"]  # == domain.enums.TaskPriority
SeverityName = Literal["critical", "high", "medium", "low", "info"]  # == domain.enums.Severity
VerificationStatusName = Literal["unverified", "pending", "passed", "failed"]  # == domain.enums.VerificationStatus
# == app.workspace.templates.STATUS_KEYS
StatusKeyName = Literal["backlog", "todo", "investigating", "ready", "in_progress", "review", "testing", "verified", "done"]
AutomationTriggerName = Literal["pr_linked", "verification_passed", "verification_failed", "fix_attempt_started"]
RefTypeName = Literal[
    "finding", "incident", "event", "session", "agent", "tool_invocation", "policy_decision", "context_item",
    "source", "approval", "destination",
]
DependencyKindName = Literal["blocks", "relates_to"]
AssigneeRoleName = Literal["assignee", "reviewer"]
LinkKindName = Literal["branch", "commit", "pull_request", "deployment"]
AttachmentKindName = Literal["link", "log", "stack_trace", "note"]
FixStatusName = Literal["planned", "in_progress", "claimed_complete", "verified", "failed", "abandoned"]
AgentToolName = Literal["claude_code", "codex", "cursor", "copilot", "human", "other"]
VerificationKindName = Literal["test_run", "code_review", "manual", "deployment", "simulation", "replay"]
VerificationRunStatusName = Literal["passed", "failed", "error", "pending"]

TITLE_MAX = 400
TEXT_MAX = 20_000


class Strict(BaseModel):
    """Base for request bodies: unknown fields are rejected rather than silently ignored."""

    model_config = ConfigDict(extra="forbid")


class UserRefOut(BaseModel):
    id: str
    name: str
    email: str


class LabelOut(BaseModel):
    id: str
    name: str
    color: str


class LabelWithUsageOut(LabelOut):
    task_count: int
    created_at: datetime


class AssigneeOut(BaseModel):
    user_id: str
    name: str
    email: str
    role: AssigneeRoleName


class LabelCreate(Strict):
    name: str
    color: str = "slate"
