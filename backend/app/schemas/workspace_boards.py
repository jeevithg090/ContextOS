"""Engineering Workspace boards and columns (HTTP contract).

Column layouts are validated by ``app.workspace.templates.validate_columns`` in the service layer
(plain-language errors in a 422 ``details.errors`` list); these models only check shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.workspace import (
    AssigneeOut,
    AutomationTriggerName,
    LabelOut,
    StatusKeyName,
    Strict,
    TaskTypeName,
)

BoardTemplateName = Literal[
    "software_development", "security_remediation", "incident_response", "bug_tracking", "feature_development",
    "technical_debt", "research_experiments",
]
SwimlaneName = Literal["none", "priority", "assignee"]
CARD_FIELDS = ("key", "type", "priority", "severity", "labels", "assignees", "due_date", "subtasks", "verification", "finding")


class BoardTemplateOut(BaseModel):
    key: str
    name: str
    description: str
    columns: list[str]
    requires_verification: bool


class AutomationRule(Strict):
    """When ``trigger`` happens to a task sitting in this column, move it to ``move_to_column_id``."""

    trigger: AutomationTriggerName
    move_to_column_id: str


class BoardConfig(Strict):
    card_fields: list[str] | None = None
    swimlanes: SwimlaneName | None = None
    default_task_type: TaskTypeName | None = None


class ColumnOut(BaseModel):
    id: str
    board_id: str
    name: str
    description: str | None
    color: str
    position: int
    wip_limit: int | None
    status_key: str
    is_done_column: bool
    requires_verification: bool
    automation: list[dict[str, Any]]
    task_count: int = Field(description="Non-archived tasks currently in the column")
    wip_exceeded: bool = Field(description="True when a WIP limit is set and the column holds more tasks than it")


class TaskCardOut(BaseModel):
    """Compact task representation used on board columns and in task lists."""

    id: str
    key: str
    number: int
    board_id: str
    column_id: str
    column_name: str
    status_key: str
    is_done: bool
    position: float
    title: str
    task_type: str
    priority: str
    severity: str | None
    labels: list[LabelOut]
    assignees: list[AssigneeOut]
    due_date: datetime | None
    is_overdue: bool
    parent_task_id: str | None
    subtasks_total: int
    subtasks_done: int
    blocked_by_open: int = Field(description="Open tasks this task depends on ('blocks' dependencies)")
    verification_status: str
    related_finding_id: str | None
    related_incident_id: str | None
    related_agent_id: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    archived_at: datetime | None


class ColumnWithTasksOut(ColumnOut):
    tasks: list[TaskCardOut]


class BoardSummaryOut(BaseModel):
    id: str
    name: str
    description: str | None
    template: str
    is_default: bool
    config: dict[str, Any]
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    column_count: int
    task_count: int
    open_task_count: int = Field(description="Tasks not in a done column")


class BoardDetailOut(BoardSummaryOut):
    columns: list[ColumnWithTasksOut]


class BoardCreate(Strict):
    name: str = Field(min_length=1, max_length=200)
    template: BoardTemplateName = "software_development"
    description: str | None = Field(default=None, max_length=4000)


class BoardPatch(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    is_default: bool | None = None
    config: BoardConfig | None = None
    archived: bool | None = Field(default=None, description="false restores an archived board")


class BoardDuplicate(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=200)


class ColumnCreate(Strict):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    color: str = "slate"
    wip_limit: int | None = Field(default=None, ge=1, le=10_000)
    status_key: StatusKeyName = "todo"
    requires_verification: bool = False
    is_done_column: bool = False
    automation: list[AutomationRule] = Field(default_factory=list, max_length=20)
    position: int | None = Field(default=None, ge=0, description="Insert index; default is the end")


class ColumnPatch(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    color: str | None = None
    wip_limit: int | None = Field(default=None, ge=1, le=10_000)
    status_key: StatusKeyName | None = None
    requires_verification: bool | None = None
    is_done_column: bool | None = None
    automation: list[AutomationRule] | None = Field(default=None, max_length=20)


class ColumnReorder(Strict):
    column_ids: list[str] = Field(min_length=1, max_length=100)


class ColumnDeleteOut(BaseModel):
    deleted_column_id: str
    moved_task_count: int
    moved_to_column_id: str | None
    removed_automation_rules: int = Field(description="Rules in other columns that targeted the deleted column")


__all__ = [
    "CARD_FIELDS", "AutomationRule", "BoardConfig", "BoardCreate", "BoardDetailOut", "BoardDuplicate", "BoardPatch",
    "BoardSummaryOut", "BoardTemplateName", "BoardTemplateOut", "ColumnCreate", "ColumnDeleteOut", "ColumnOut",
    "ColumnPatch", "ColumnReorder", "ColumnWithTasksOut", "SwimlaneName", "TaskCardOut",
]
