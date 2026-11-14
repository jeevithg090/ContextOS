"""Engineering Workspace tasks: create/update/move, comments, dependencies, assignees, references.

Free-text fields are redacted with ``app.engines.redaction`` before they are stored, so a pasted
token in a description or comment never reaches the database in raw form.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.workspace import (
    TEXT_MAX,
    TITLE_MAX,
    AssigneeRoleName,
    DependencyKindName,
    PriorityName,
    RefTypeName,
    SeverityName,
    Strict,
    TaskTypeName,
    UserRefOut,
)
from app.schemas.workspace_boards import ColumnOut, TaskCardOut
from app.schemas.workspace_evidence import AttachmentOut, FixAttemptOut, LinkItemOut, VerificationOut


class AcceptanceCriterion(Strict):
    text: str = Field(min_length=1, max_length=1000)
    done: bool = False


class _TaskFields(Strict):
    description: str | None = Field(default=None, max_length=TEXT_MAX)
    task_type: TaskTypeName | None = None
    priority: PriorityName | None = None
    severity: SeverityName | None = None
    due_date: datetime | None = None
    parent_task_id: str | None = None
    related_agent_id: str | None = None
    related_incident_id: str | None = None
    related_finding_id: str | None = None
    related_files: list[str] | None = Field(default=None, max_length=200)
    reproduction_steps: str | None = Field(default=None, max_length=TEXT_MAX)
    expected_behaviour: str | None = Field(default=None, max_length=TEXT_MAX)
    actual_behaviour: str | None = Field(default=None, max_length=TEXT_MAX)
    acceptance_criteria: list[AcceptanceCriterion] | None = Field(default=None, max_length=50)
    label_ids: list[str] | None = Field(default=None, max_length=50)


class TaskCreate(_TaskFields):
    title: str = Field(min_length=1, max_length=TITLE_MAX)
    board_id: str | None = Field(default=None, description="Default: the organisation's default board")
    column_id: str | None = Field(default=None, description="Default: the board's first column")
    assignee_ids: list[str] | None = Field(default=None, max_length=20)
    override_wip: bool = False


class TaskPatch(_TaskFields):
    title: str | None = Field(default=None, min_length=1, max_length=TITLE_MAX)
    resolution: str | None = Field(default=None, max_length=TEXT_MAX)
    archived: bool | None = Field(default=None, description="false restores an archived task")


class TaskMove(Strict):
    column_id: str
    position: int | None = Field(
        default=None, ge=0, description="Index within the target column; default end"
    )
    override_wip: bool = False


class FromFindingIn(Strict):
    finding_id: str
    board_id: str | None = None


class FromIncidentIn(Strict):
    incident_id: str
    board_id: str | None = None
    mode: str = Field(default="per_finding", pattern="^(per_finding|parent_with_subtasks)$")


class CommentCreate(Strict):
    body: str = Field(min_length=1, max_length=TEXT_MAX)


class CommentPatch(Strict):
    body: str = Field(min_length=1, max_length=TEXT_MAX)


class DependencyCreate(Strict):
    depends_on_task_id: str
    kind: DependencyKindName = "blocks"


class AssigneeIn(Strict):
    user_id: str
    role: AssigneeRoleName = "assignee"


class AssigneesPut(Strict):
    assignees: list[AssigneeIn] = Field(max_length=20)


class RefCreate(Strict):
    ref_type: RefTypeName
    ref_id: str = Field(min_length=1, max_length=40)
    note: str | None = Field(default=None, max_length=2000)


class CommentOut(BaseModel):
    id: str
    task_id: str
    author: UserRefOut | None
    body: str
    created_at: datetime
    edited_at: datetime | None


class TaskBriefOut(BaseModel):
    id: str
    key: str
    title: str
    status_key: str
    is_done: bool
    archived: bool


class DependencyOut(BaseModel):
    id: str
    task_id: str
    depends_on_task_id: str
    kind: str
    created_at: datetime
    task: TaskBriefOut = Field(description="The task on the other side of the dependency")


class RefOut(BaseModel):
    id: str
    task_id: str
    ref_type: str
    ref_id: str
    note: str | None
    label: str = Field(description="Human-readable name of the referenced record (redacted)")
    detail: str | None = Field(description="Short status line, e.g. severity and status")
    exists: bool = Field(description="False when the referenced record has since been deleted")
    created_at: datetime


class ActivityOut(BaseModel):
    id: str
    kind: str
    actor: UserRefOut | None = Field(description="null = system / automation")
    from_value: str | None
    to_value: str | None
    details: dict[str, Any]
    created_at: datetime


class TaskDetailOut(TaskCardOut):
    board_name: str
    column: ColumnOut
    description: str
    reporter: UserRefOut | None
    related_files: list[str]
    reproduction_steps: str
    expected_behaviour: str
    actual_behaviour: str
    acceptance_criteria: list[dict[str, Any]]
    resolution: str | None
    verified_at: datetime | None
    reopened_count: int
    parent: TaskBriefOut | None
    subtasks: list[TaskBriefOut]
    blocked_by: list[DependencyOut] = Field(description="Tasks this task depends on")
    blocking: list[DependencyOut] = Field(description="Tasks that depend on this task")
    comments: list[CommentOut]
    refs: list[RefOut]
    attachments: list[AttachmentOut]
    links: dict[str, list[LinkItemOut]]
    fix_attempts: list[FixAttemptOut]
    verification_runs: list[VerificationOut]
    activity: list[ActivityOut]
    generated_prompt_ids: list[str]


class FromFindingOut(BaseModel):
    created: bool = Field(description="False when an open task for this finding already existed")
    task: TaskDetailOut


class IncidentTaskOut(BaseModel):
    finding_id: str | None
    created: bool
    task: TaskCardOut


class FromIncidentOut(BaseModel):
    incident_id: str
    mode: str
    parent_task_id: str | None
    created_count: int
    existing_count: int
    tasks: list[IncidentTaskOut]
