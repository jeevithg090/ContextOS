"""Read models for the Engineering Workspace API: board summaries/details, task cards and task detail.

Everything is loaded in batches (one query per relation, not per task) and scoped to the caller's
organisation. Builders return the Pydantic ``*Out`` models from ``app.schemas.workspace_*``.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, aliased

from app.core.timeutil import utcnow
from app.models import (
    Board,
    BoardColumn,
    FixAttempt,
    GeneratedPrompt,
    Task,
    TaskActivity,
    TaskAssignment,
    TaskAttachment,
    TaskComment,
    TaskDependency,
    TaskLabel,
    TaskLabelLink,
    User,
    VerificationRun,
)
from app.schemas.workspace import AssigneeOut, LabelOut, UserRefOut
from app.schemas.workspace_boards import (
    BoardDetailOut,
    BoardSummaryOut,
    ColumnOut,
    ColumnWithTasksOut,
    TaskCardOut,
)
from app.schemas.workspace_evidence import AttachmentOut, FixAttemptOut, LinkItemOut, VerificationOut
from app.schemas.workspace_tasks import (
    ActivityOut,
    CommentOut,
    DependencyOut,
    RefOut,
    TaskBriefOut,
    TaskDetailOut,
)
from app.services.workspace_tasks_common import board_columns, task_key
from app.services.workspace_tasks_evidence import fix_attempt_rows, link_items, verification_rows
from app.services.workspace_tasks_refs import resolve_refs, task_refs
from app.services.workspace_tasks_relations import dependency_rows

ACTIVITY_LIMIT = 200


# ----------------------------------------------------------------------------- users


def users_by_id(db: Session, ids: set[str | None]) -> dict[str, UserRefOut]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {u.id: UserRefOut(id=u.id, name=u.name, email=u.email)
            for u in db.scalars(select(User).where(User.id.in_(wanted)))}


# ----------------------------------------------------------------------------- columns & boards


def column_counts(db: Session, org_id: str, column_ids: list[str]) -> dict[str, int]:
    if not column_ids:
        return {}
    rows = db.execute(select(Task.column_id, func.count(Task.id)).where(
        Task.organization_id == org_id, Task.column_id.in_(column_ids), Task.archived_at.is_(None)
    ).group_by(Task.column_id)).all()
    return {cid: int(n) for cid, n in rows}


def column_out(column: BoardColumn, count: int) -> ColumnOut:
    return ColumnOut(
        id=column.id, board_id=column.board_id, name=column.name, description=column.description, color=column.color,
        position=column.position, wip_limit=column.wip_limit, status_key=column.status_key,
        is_done_column=column.is_done_column, requires_verification=column.requires_verification,
        automation=list(column.automation or []), task_count=count,
        wip_exceeded=column.wip_limit is not None and count > column.wip_limit,
    )


def columns_out(db: Session, org_id: str, columns: list[BoardColumn]) -> list[ColumnOut]:
    counts = column_counts(db, org_id, [c.id for c in columns])
    return [column_out(c, counts.get(c.id, 0)) for c in columns]


def board_summaries(db: Session, org_id: str, boards: list[Board]) -> list[BoardSummaryOut]:
    ids = [b.id for b in boards] or [""]
    col_counts = dict(db.execute(select(BoardColumn.board_id, func.count(BoardColumn.id)).where(
        BoardColumn.organization_id == org_id, BoardColumn.board_id.in_(ids)).group_by(BoardColumn.board_id)).all())
    task_rows = db.execute(
        select(Task.board_id, func.count(Task.id),
               func.sum(case((BoardColumn.is_done_column.is_(False), 1), else_=0)))
        .join(BoardColumn, BoardColumn.id == Task.column_id)
        .where(Task.organization_id == org_id, Task.board_id.in_(ids), Task.archived_at.is_(None))
        .group_by(Task.board_id)
    ).all()
    tasks = {bid: (int(total), int(open_ or 0)) for bid, total, open_ in task_rows}
    return [_summary(b, int(col_counts.get(b.id, 0)), *tasks.get(b.id, (0, 0))) for b in boards]


def _summary(board: Board, columns: int, total: int, open_count: int) -> BoardSummaryOut:
    return BoardSummaryOut(
        id=board.id, name=board.name, description=board.description, template=board.template,
        is_default=board.is_default, config=dict(board.config or {}), created_by=board.created_by,
        created_at=board.created_at, updated_at=board.updated_at, archived_at=board.archived_at,
        column_count=columns, task_count=total, open_task_count=open_count,
    )


def board_detail(db: Session, board: Board) -> BoardDetailOut:
    org_id = board.organization_id
    columns = board_columns(db, org_id, board.id)
    tasks = list(db.scalars(select(Task).where(
        Task.organization_id == org_id, Task.board_id == board.id, Task.archived_at.is_(None)
    ).order_by(Task.position, Task.number)))
    cards = task_cards(db, org_id, tasks, columns={c.id: c for c in columns})
    by_column: dict[str, list[TaskCardOut]] = defaultdict(list)
    for card in cards:
        by_column[card.column_id].append(card)
    summary = board_summaries(db, org_id, [board])[0]
    return BoardDetailOut(
        **summary.model_dump(),
        columns=[ColumnWithTasksOut(**column_out(c, len(by_column[c.id])).model_dump(), tasks=by_column[c.id])
                 for c in columns],
    )


# ----------------------------------------------------------------------------- task cards


def _labels_for(db: Session, org_id: str, task_ids: list[str]) -> dict[str, list[LabelOut]]:
    out: dict[str, list[LabelOut]] = defaultdict(list)
    rows = db.execute(select(TaskLabelLink.task_id, TaskLabel).join(TaskLabel, TaskLabel.id == TaskLabelLink.label_id)
                      .where(TaskLabelLink.organization_id == org_id, TaskLabelLink.task_id.in_(task_ids))
                      .order_by(func.lower(TaskLabel.name))).all()
    for task_id, label in rows:
        out[task_id].append(LabelOut(id=label.id, name=label.name, color=label.color))
    return out


def _assignees_for(db: Session, org_id: str, task_ids: list[str]) -> dict[str, list[AssigneeOut]]:
    out: dict[str, list[AssigneeOut]] = defaultdict(list)
    rows = db.execute(select(TaskAssignment, User).join(User, User.id == TaskAssignment.user_id)
                      .where(TaskAssignment.organization_id == org_id, TaskAssignment.task_id.in_(task_ids))
                      .order_by(TaskAssignment.created_at)).all()
    for assignment, user in rows:
        out[assignment.task_id].append(AssigneeOut(user_id=user.id, name=user.name, email=user.email,
                                                   role=assignment.role))  # type: ignore[arg-type]
    return out


def _subtask_counts(db: Session, org_id: str, task_ids: list[str]) -> dict[str, tuple[int, int]]:
    rows = db.execute(
        select(Task.parent_task_id, func.count(Task.id), func.sum(case((BoardColumn.is_done_column.is_(True), 1),
                                                                       else_=0)))
        .join(BoardColumn, BoardColumn.id == Task.column_id)
        .where(Task.organization_id == org_id, Task.parent_task_id.in_(task_ids), Task.archived_at.is_(None))
        .group_by(Task.parent_task_id)
    ).all()
    return {pid: (int(total), int(done or 0)) for pid, total, done in rows}


def _open_blockers(db: Session, org_id: str, task_ids: list[str]) -> dict[str, int]:
    other = aliased(Task)
    rows = db.execute(
        select(TaskDependency.task_id, func.count(TaskDependency.id))
        .join(other, other.id == TaskDependency.depends_on_task_id)
        .join(BoardColumn, BoardColumn.id == other.column_id)
        .where(TaskDependency.organization_id == org_id, TaskDependency.task_id.in_(task_ids),
               TaskDependency.kind == "blocks", other.archived_at.is_(None), BoardColumn.is_done_column.is_(False))
        .group_by(TaskDependency.task_id)
    ).all()
    return {tid: int(n) for tid, n in rows}


def task_cards(db: Session, org_id: str, tasks: list[Task], *,
               columns: dict[str, BoardColumn] | None = None) -> list[TaskCardOut]:
    if not tasks:
        return []
    ids = [t.id for t in tasks]
    cols = dict(columns or {})
    missing = {t.column_id for t in tasks} - set(cols)
    if missing:
        cols.update({c.id: c for c in db.scalars(select(BoardColumn).where(
            BoardColumn.organization_id == org_id, BoardColumn.id.in_(missing)))})
    labels, assignees = _labels_for(db, org_id, ids), _assignees_for(db, org_id, ids)
    subtasks, blockers = _subtask_counts(db, org_id, ids), _open_blockers(db, org_id, ids)
    now = utcnow()
    cards = []
    for t in tasks:
        col = cols[t.column_id]
        total, done = subtasks.get(t.id, (0, 0))
        cards.append(TaskCardOut(
            id=t.id, key=task_key(t), number=t.number, board_id=t.board_id, column_id=t.column_id,
            column_name=col.name, status_key=col.status_key, is_done=col.is_done_column, position=t.position,
            title=t.title, task_type=t.task_type, priority=t.priority, severity=t.severity,
            labels=labels.get(t.id, []), assignees=assignees.get(t.id, []), due_date=t.due_date,
            is_overdue=bool(t.due_date and t.due_date < now and not col.is_done_column and t.archived_at is None),
            parent_task_id=t.parent_task_id, subtasks_total=total, subtasks_done=done,
            blocked_by_open=blockers.get(t.id, 0), verification_status=t.verification_status,
            related_finding_id=t.related_finding_id, related_incident_id=t.related_incident_id,
            related_agent_id=t.related_agent_id, created_at=t.created_at, updated_at=t.updated_at,
            completed_at=t.completed_at, archived_at=t.archived_at,
        ))
    return cards


def task_card(db: Session, task: Task) -> TaskCardOut:
    return task_cards(db, task.organization_id, [task])[0]


# ----------------------------------------------------------------------------- task detail


def _briefs(db: Session, org_id: str, ids: list[str]) -> dict[str, TaskBriefOut]:
    if not ids:
        return {}
    rows = db.execute(select(Task, BoardColumn).join(BoardColumn, BoardColumn.id == Task.column_id)
                      .where(Task.organization_id == org_id, Task.id.in_(ids))).all()
    return {t.id: TaskBriefOut(id=t.id, key=task_key(t), title=t.title, status_key=c.status_key,
                               is_done=c.is_done_column, archived=t.archived_at is not None) for t, c in rows}


def comment_out(comment: TaskComment, users: dict[str, UserRefOut]) -> CommentOut:
    return CommentOut(id=comment.id, task_id=comment.task_id, author=users.get(comment.author_user_id or ""),
                      body=comment.body, created_at=comment.created_at, edited_at=comment.edited_at)


def attachment_out(row: TaskAttachment, users: dict[str, UserRefOut]) -> AttachmentOut:
    return AttachmentOut(id=row.id, task_id=row.task_id, name=row.name, kind=row.kind, url=row.url,
                         content=row.content, size=row.size, created_by=users.get(row.created_by or ""),
                         created_at=row.created_at)


def fix_attempt_out(row: FixAttempt, users: dict[str, UserRefOut]) -> FixAttemptOut:
    return FixAttemptOut(
        id=row.id, task_id=row.task_id, generated_prompt_id=row.generated_prompt_id, agent_tool=row.agent_tool,
        status=row.status, branch=row.branch, commit_sha=row.commit_sha, pr_url=row.pr_url, notes=row.notes,
        started_at=row.started_at, completed_at=row.completed_at, created_by=users.get(row.created_by or ""),
        created_at=row.created_at, updated_at=row.updated_at, is_claim_only=row.status == "claimed_complete",
    )


def verification_out(row: VerificationRun, users: dict[str, UserRefOut], task_status: str) -> VerificationOut:
    return VerificationOut(
        id=row.id, task_id=row.task_id, fix_attempt_id=row.fix_attempt_id, kind=row.kind, status=row.status,
        summary=row.summary, command=row.command, evidence_url=row.evidence_url, evidence=dict(row.evidence or {}),
        simulation_run_id=row.simulation_run_id, created_by=users.get(row.created_by or ""),
        created_at=row.created_at, task_verification_status=task_status,
    )


def dependency_out(dep: TaskDependency, other: TaskBriefOut) -> DependencyOut:
    return DependencyOut(id=dep.id, task_id=dep.task_id, depends_on_task_id=dep.depends_on_task_id, kind=dep.kind,
                         created_at=dep.created_at, task=other)


def links_out(task: Task) -> dict[str, list[LinkItemOut]]:
    return {kind: [LinkItemOut.model_validate(i) for i in items] for kind, items in link_items(task).items()}


def _rows(db: Session, model: Any, task: Task, order: Any) -> list[Any]:
    return list(db.scalars(select(model).where(model.organization_id == task.organization_id,
                                               model.task_id == task.id).order_by(order)))


def task_detail(db: Session, task: Task) -> TaskDetailOut:
    org_id = task.organization_id
    card = task_card(db, task)
    column = db.get(BoardColumn, task.column_id)
    board = db.get(Board, task.board_id)
    comments = _rows(db, TaskComment, task, TaskComment.created_at)
    attachments = _rows(db, TaskAttachment, task, TaskAttachment.created_at)
    activity = list(db.scalars(select(TaskActivity).where(
        TaskActivity.organization_id == org_id, TaskActivity.task_id == task.id
    ).order_by(TaskActivity.created_at.desc(), TaskActivity.id.desc()).limit(ACTIVITY_LIMIT)))
    attempts, runs = fix_attempt_rows(db, task), verification_rows(db, task)
    blocked_by, blocking = dependency_rows(db, task)
    subtask_ids = list(db.scalars(select(Task.id).where(
        Task.organization_id == org_id, Task.parent_task_id == task.id).order_by(Task.number)))
    briefs = _briefs(db, org_id, [*subtask_ids, *[d.depends_on_task_id for d in blocked_by],
                                  *[d.task_id for d in blocking], *([task.parent_task_id] if task.parent_task_id else [])])
    users = users_by_id(db, {task.reporter_user_id, *(c.author_user_id for c in comments),
                             *(a.created_by for a in attachments), *(a.actor_user_id for a in activity),
                             *(f.created_by for f in attempts), *(r.created_by for r in runs)})
    prompt_ids = list(db.scalars(select(GeneratedPrompt.id).where(
        GeneratedPrompt.organization_id == org_id, GeneratedPrompt.task_id == task.id
    ).order_by(GeneratedPrompt.created_at.desc())))
    assert column is not None and board is not None
    return TaskDetailOut(
        **card.model_dump(),
        board_name=board.name, column=column_out(column, column_counts(db, org_id, [column.id]).get(column.id, 0)),
        description=task.description, reporter=users.get(task.reporter_user_id or ""),
        related_files=[str(f) for f in task.related_files or []], reproduction_steps=task.reproduction_steps,
        expected_behaviour=task.expected_behaviour, actual_behaviour=task.actual_behaviour,
        acceptance_criteria=list(task.acceptance_criteria or []), resolution=task.resolution,
        verified_at=task.verified_at, reopened_count=task.reopened_count,
        parent=briefs.get(task.parent_task_id) if task.parent_task_id else None,
        subtasks=[briefs[i] for i in subtask_ids if i in briefs],
        blocked_by=[dependency_out(d, briefs[d.depends_on_task_id]) for d in blocked_by if d.depends_on_task_id in briefs],
        blocking=[dependency_out(d, briefs[d.task_id]) for d in blocking if d.task_id in briefs],
        comments=[comment_out(c, users) for c in comments],
        refs=[RefOut.model_validate(r) for r in resolve_refs(db, org_id, task_refs(db, task))],
        attachments=[attachment_out(a, users) for a in attachments],
        links=links_out(task),
        fix_attempts=[fix_attempt_out(f, users) for f in attempts],
        verification_runs=[verification_out(r, users, task.verification_status) for r in runs],
        activity=[ActivityOut(id=a.id, kind=a.kind, actor=users.get(a.actor_user_id or ""), from_value=a.from_value,
                              to_value=a.to_value, details=dict(a.details or {}), created_at=a.created_at)
                  for a in activity],
        generated_prompt_ids=prompt_ids,
    )


def brief(db: Session, task: Task) -> TaskBriefOut:
    return _briefs(db, task.organization_id, [task.id])[task.id]
