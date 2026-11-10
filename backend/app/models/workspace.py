"""Engineering Workspace: boards, tasks and AI fix-context artefacts.

Tasks reference security records (findings, incidents, events...) through ``TaskContextReference``
rows rather than copying sensitive event data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.database.base import Base, OrgScopedMixin, TimestampMixin, id_column


class Board(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "boards"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    template: Mapped[str] = mapped_column(String(48), default="software_development")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # BoardConfiguration: {"card_fields": [...], "swimlanes": "none"|"priority"|"assignee",
    #   "default_task_type": str, "key_prefix": "CTX"}
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    archived_at: Mapped[datetime | None] = mapped_column(default=None)


class BoardColumn(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "board_columns"

    id: Mapped[str] = id_column()
    board_id: Mapped[str] = mapped_column(String(40), ForeignKey("boards.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    color: Mapped[str] = mapped_column(String(16), default="slate")  # token name or #hex
    position: Mapped[int] = mapped_column(Integer, default=0)
    wip_limit: Mapped[int | None] = mapped_column(Integer, default=None)
    # Semantic category used for analytics and workflow rules:
    # backlog|todo|investigating|ready|in_progress|review|testing|verified|done
    status_key: Mapped[str] = mapped_column(String(32), default="todo")
    is_done_column: Mapped[bool] = mapped_column(Boolean, default=False)
    # Moving a task INTO this column requires a passed VerificationRun.
    requires_verification: Mapped[bool] = mapped_column(Boolean, default=False)
    # Automatic transitions: [{"trigger": "pr_linked"|"verification_passed"|"verification_failed"|"fix_attempt_started",
    #   "move_to_column_id": str}]
    automation: Mapped[list[Any]] = mapped_column(default=list)


class TaskLabel(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "task_labels"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(64))
    color: Mapped[str] = mapped_column(String(16), default="slate")


class Task(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("organization_id", "number"),
        Index("ix_tasks_board_column", "board_id", "column_id"),
    )

    id: Mapped[str] = id_column()
    number: Mapped[int] = mapped_column(Integer)  # per-org sequence → key "CTX-<number>"
    board_id: Mapped[str] = mapped_column(String(40), ForeignKey("boards.id", ondelete="CASCADE"))
    column_id: Mapped[str] = mapped_column(String(40), ForeignKey("board_columns.id", ondelete="RESTRICT"))
    position: Mapped[float] = mapped_column(Float, default=0.0)  # ordering within a column
    title: Mapped[str] = mapped_column(String(400))
    description: Mapped[str] = mapped_column(Text, default="")
    task_type: Mapped[str] = mapped_column(String(48), default="task")  # TaskType
    priority: Mapped[str] = mapped_column(String(16), default="medium")  # TaskPriority
    severity: Mapped[str | None] = mapped_column(String(16), default=None)  # Severity for security work
    reporter_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    due_date: Mapped[datetime | None] = mapped_column(default=None)
    parent_task_id: Mapped[str | None] = mapped_column(
        String(40), ForeignKey("tasks.id", ondelete="SET NULL"), default=None, index=True
    )
    related_agent_id: Mapped[str | None] = mapped_column(String(40), default=None)
    related_incident_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    related_finding_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    related_files: Mapped[list[Any]] = mapped_column(default=list)  # repo-relative paths
    links: Mapped[dict[str, Any]] = mapped_column(default=dict)  # {"branches": [], "commits": [], "pull_requests": [{"url","title","state"}], "deployments": []}
    reproduction_steps: Mapped[str] = mapped_column(Text, default="")
    expected_behaviour: Mapped[str] = mapped_column(Text, default="")
    actual_behaviour: Mapped[str] = mapped_column(Text, default="")
    acceptance_criteria: Mapped[list[Any]] = mapped_column(default=list)  # [{"text": str, "done": bool}]
    resolution: Mapped[str | None] = mapped_column(Text, default=None)
    verification_status: Mapped[str] = mapped_column(String(16), default="unverified")  # VerificationStatus
    verified_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    archived_at: Mapped[datetime | None] = mapped_column(default=None)


class TaskLabelLink(OrgScopedMixin, Base):
    __tablename__ = "task_label_links"
    __table_args__ = (UniqueConstraint("task_id", "label_id"),)

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    label_id: Mapped[str] = mapped_column(String(40), ForeignKey("task_labels.id", ondelete="CASCADE"))


class TaskAssignment(OrgScopedMixin, Base):
    __tablename__ = "task_assignments"
    __table_args__ = (UniqueConstraint("task_id", "user_id"),)

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="assignee")  # assignee|reviewer
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TaskComment(OrgScopedMixin, Base):
    __tablename__ = "task_comments"

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    author_user_id: Mapped[str | None] = mapped_column(String(40), default=None)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    edited_at: Mapped[datetime | None] = mapped_column(default=None)


class TaskDependency(OrgScopedMixin, Base):
    __tablename__ = "task_dependencies"
    __table_args__ = (UniqueConstraint("task_id", "depends_on_task_id"),)

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    depends_on_task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="blocks")  # blocks|relates_to
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TaskAttachment(OrgScopedMixin, Base):
    __tablename__ = "task_attachments"

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(400))
    kind: Mapped[str] = mapped_column(String(32), default="link")  # link|log|stack_trace|note
    url: Mapped[str | None] = mapped_column(String(2048), default=None)
    content: Mapped[str | None] = mapped_column(Text, default=None)  # redacted text content
    size: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TaskActivity(OrgScopedMixin, Base):
    __tablename__ = "task_activities"

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(40), default=None)  # None = system/automation
    kind: Mapped[str] = mapped_column(String(48))  # created|moved|updated|commented|linked|verification|...
    from_value: Mapped[str | None] = mapped_column(Text, default=None)
    to_value: Mapped[str | None] = mapped_column(Text, default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TaskContextReference(OrgScopedMixin, Base):
    __tablename__ = "task_context_refs"
    __table_args__ = (UniqueConstraint("task_id", "ref_type", "ref_id"),)

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    # finding|incident|event|session|agent|tool_invocation|policy_decision|context_item|source|approval|destination
    ref_type: Mapped[str] = mapped_column(String(32))
    ref_id: Mapped[str] = mapped_column(String(40))
    note: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PromptTemplate(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "prompt_templates"

    id: Mapped[str] = id_column()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    mode: Mapped[str] = mapped_column(String(48))  # see workspace.fix_context.PromptMode
    preset: Mapped[str] = mapped_column(String(32), default="generic")  # claude_code|codex|cursor|generic
    options: Mapped[dict[str, Any]] = mapped_column(default=dict)
    section_overrides: Mapped[dict[str, Any]] = mapped_column(default=dict)  # {section_key: extra instructions}
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)


class ContextPack(OrgScopedMixin, Base):
    __tablename__ = "context_packs"

    id: Mapped[str] = id_column()
    task_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    profile: Mapped[str] = mapped_column(String(32))  # minimal|standard|deep|security_critical|full
    # [{"key", "kind": "doc"|"source_file"|"test_file"|"record"|"policy"|"note",
    #   "ref": str (path or record id), "title", "category": "fact"|"evidence"|"assumption"|"hypothesis"|"recommendation",
    #   "reason": str, "verified": bool, "included": bool, "token_estimate": int, "excerpt": str}]
    items: Mapped[list[Any]] = mapped_column(default=list)
    token_estimate: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class GeneratedPrompt(OrgScopedMixin, Base):
    __tablename__ = "generated_prompts"

    id: Mapped[str] = id_column()
    task_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    mode: Mapped[str] = mapped_column(String(48))
    preset: Mapped[str] = mapped_column(String(32), default="generic")
    options: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Ordered: [{"key", "title", "content", "kind": "fact"|"evidence"|"assumption"|"hypothesis"|"recommendation"|"instruction",
    #   "sources": [refs], "edited": bool}]
    sections: Mapped[list[Any]] = mapped_column(default=list)
    content: Mapped[str] = mapped_column(Text, default="")  # final rendered markdown
    context_pack_id: Mapped[str | None] = mapped_column(String(40), default=None)
    template_id: Mapped[str | None] = mapped_column(String(40), default=None)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class FixAttempt(TimestampMixin, OrgScopedMixin, Base):
    __tablename__ = "fix_attempts"

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    generated_prompt_id: Mapped[str | None] = mapped_column(String(40), default=None)
    agent_tool: Mapped[str] = mapped_column(String(32), default="claude_code")
    # planned|in_progress|claimed_complete|verified|failed|abandoned — "claimed_complete" is NOT resolution.
    status: Mapped[str] = mapped_column(String(24), default="planned")
    branch: Mapped[str | None] = mapped_column(String(300), default=None)
    commit_sha: Mapped[str | None] = mapped_column(String(64), default=None)
    pr_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)


class VerificationRun(OrgScopedMixin, Base):
    __tablename__ = "verification_runs"

    id: Mapped[str] = id_column()
    task_id: Mapped[str] = mapped_column(String(40), ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    fix_attempt_id: Mapped[str | None] = mapped_column(String(40), default=None)
    kind: Mapped[str] = mapped_column(String(32))  # test_run|code_review|manual|deployment|simulation|replay
    status: Mapped[str] = mapped_column(String(16))  # passed|failed|error|pending
    summary: Mapped[str] = mapped_column(Text, default="")
    command: Mapped[str | None] = mapped_column(Text, default=None)
    evidence_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)  # e.g. {"tests_passed": 120, "tests_failed": 0}
    simulation_run_id: Mapped[str | None] = mapped_column(String(40), default=None)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
