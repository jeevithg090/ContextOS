"""Engineering analytics and the security-remediation pipeline (HTTP contract).

Every number is computed from persisted rows (tasks, board columns, verification runs, findings);
nothing is estimated. Ratios carry their numerator and denominator so the UI can show what was
counted. Mirrored by ``frontend/src/features/workspace/analytics/types.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.workspace_boards import TaskCardOut

# no_task: nothing tracks the finding | task_open: a linked task is not in a done column |
# task_done_unverified: linked tasks are done, none has passed verification | verified: a done linked
# task has passed verification evidence.
RemediationStateName = Literal["no_task", "task_open", "task_done_unverified", "verified"]
SeriesGranularityName = Literal["day", "week"]


class CountOut(BaseModel):
    key: str
    count: int


class RatioOut(BaseModel):
    numerator: int
    denominator: int
    rate: float | None = Field(description="numerator / denominator (0..1); null when the denominator is 0")


class FindingBacklogOut(BaseModel):
    total: int = Field(description="Open or acknowledged findings whose remediation is not done (no_task + task_open)")
    no_task: int = Field(description="Open findings that no task tracks")
    task_open: int = Field(description="Open findings whose linked task is not in a done column yet")
    open_findings: int = Field(description="All open or acknowledged findings, whatever their remediation state")


class ReopenedOut(BaseModel):
    reopen_events: int = Field(description="Sum of reopened_count over current (non-archived) tasks")
    tasks_reopened: int = Field(description="Tasks that were reopened at least once")


class SeriesPointOut(BaseModel):
    start: datetime = Field(description="Bucket start (UTC midnight; weeks start on Monday)")
    created: int
    completed: int


class CycleBucketOut(BaseModel):
    key: str
    label: str
    min_hours: float
    max_hours: float | None
    count: int


class CriticalItemOut(BaseModel):
    kind: Literal["finding", "task"]
    id: str
    title: str
    severity: str
    since: datetime = Field(description="first_seen_at for findings, created_at for tasks")
    state: RemediationStateName
    is_simulation: bool
    agent_id: str | None
    agent_name: str | None
    task: TaskCardOut | None = Field(description="The open task tracking the item (the task itself for kind=task)")


class OutstandingCriticalOut(BaseModel):
    total: int = Field(description="Distinct items: critical findings without a done task plus other open critical tasks")
    findings: int
    tasks: int = Field(description="Open tasks with severity critical (some may track a listed finding)")
    items: list[CriticalItemOut] = Field(description="Oldest first, at most 50")


class EngineeringAnalyticsOut(BaseModel):
    generated_at: datetime
    window_days: int
    window_start: datetime
    board_id: str | None = Field(description="Task metrics are limited to this board; finding metrics never are")
    include_simulations: bool
    open_tasks: int
    overdue: int = Field(description="Open tasks whose due date has passed")
    by_priority: list[CountOut] = Field(description="Open tasks per priority (every priority, canonical order)")
    by_type: list[CountOut] = Field(description="Open tasks per task type (types with at least one task)")
    by_status_key: list[CountOut] = Field(description="Open tasks per column status key (canonical order)")
    completed_in_window: int = Field(description="Tasks completed in the window that are still done")
    avg_resolution_hours: float | None = Field(description="Mean of completed_at - created_at over completed_in_window")
    median_resolution_hours: float | None
    p90_resolution_hours: float | None
    findings_awaiting_remediation: FindingBacklogOut
    remediation_completion_rate: RatioOut = Field(
        description="Findings with a linked task in a done column / findings with at least one linked task"
    )
    reopened_issues: ReopenedOut
    failed_verification_runs: RatioOut = Field(description="Failed runs / all verification runs recorded in the window")
    outstanding_critical: OutstandingCriticalOut
    series_granularity: SeriesGranularityName
    created_vs_completed: list[SeriesPointOut]
    throughput: list[SeriesPointOut] = Field(description="Tasks created and completed per week in the window")
    cycle_time: list[CycleBucketOut] = Field(description="Distribution of resolution time over completed_in_window")


class RemediationCountsOut(BaseModel):
    no_task: int
    task_open: int
    task_done_unverified: int
    verified: int


class RemediationFindingOut(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: float
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulation: bool
    agent_id: str | None
    agent_name: str | None
    session_id: str | None
    incident_id: str | None
    state: RemediationStateName
    state_reason: str = Field(description="Plain-language explanation of the remediation state")
    linked_task_count: int
    task: TaskCardOut | None = Field(description="Open task, else the most recently completed (verified first)")


class RemediationPageOut(BaseModel):
    items: list[RemediationFindingOut]
    total: int
    limit: int
    offset: int
    counts: RemediationCountsOut = Field(description="Findings per state for the same filters, ignoring the state filter")
