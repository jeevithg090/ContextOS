"""Engineering Workspace tasks: create, update, archive, move (with workflow gates) and automation.

Public API (used by the routes, the AI workspace and analytics packages):
- ``create_task(db, actor, title=..., **fields) -> Task`` — numbered from ``Organization.task_seq``
  (key ``CTX-<n>``); default board = the organisation's default board, default column = its first column,
  positioned at the end. Free text is redacted before storage.
- ``update_task(db, actor, task, changes) -> list[str]`` — one ``updated`` activity per changed field
  (with from/to values), labels/archival handled as their own activity kinds.
- ``move_task(db, actor, task, column_id, position=None, override_wip=False) -> Task`` — WIP limits,
  verification gates, completion/reopen bookkeeping (see ``workspace_tasks_common``).
- ``fire_automation(db, task, trigger, cause=None)`` — column automation rules for ``pr_linked``,
  ``verification_passed``, ``verification_failed`` and ``fix_attempt_started``; recorded as system activity.
- ``task_query(org_id, **filters)`` — the filtered, ordered select behind ``GET /workspace/tasks``.

``actor`` may be a :class:`~app.services.workspace_tasks_common.Actor` or an API ``Principal``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Select, case, false, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.models import (
    Agent,
    Board,
    BoardColumn,
    Incident,
    SecurityFinding,
    Task,
    TaskAssignment,
    TaskLabel,
    TaskLabelLink,
)
from app.schemas.workspace import TEXT_MAX, TITLE_MAX
from app.services.scoping import get_scoped
from app.services.workspace_boards import default_board, get_active_board, get_board_column
from app.services.workspace_tasks_common import (
    Actor,
    apply_done_transition,
    as_actor,
    audit_task,
    board_columns,
    check_entry,
    clean_optional,
    clean_text,
    get_column,
    next_task_number,
    record_activity,
    reposition,
    task_key,
)
from app.services.workspace_tasks_relations import set_assignees, set_task_labels, validate_parent

TEXT_FIELDS = {"description": TEXT_MAX, "reproduction_steps": TEXT_MAX, "expected_behaviour": TEXT_MAX,
               "actual_behaviour": TEXT_MAX}
PLAIN_FIELDS = ("task_type", "priority", "severity", "due_date")
RELATED_MODELS: dict[str, tuple[type[Any], str]] = {
    "related_agent_id": (Agent, "Agent"),
    "related_incident_id": (Incident, "Incident"),
    "related_finding_id": (SecurityFinding, "Finding"),
}
CREATE_FIELDS = frozenset({
    *TEXT_FIELDS, *PLAIN_FIELDS, *RELATED_MODELS, "board_id", "column_id", "parent_task_id", "related_files",
    "acceptance_criteria", "label_ids", "assignee_ids", "override_wip",
})
SORTS = {
    "updated": (Task.updated_at.desc(),),
    "created": (Task.created_at.desc(),),
    "key": (Task.number.desc(),),
    "due_date": (Task.due_date.is_(None), Task.due_date.asc()),
    "position": (BoardColumn.position, Task.position),
}
PRIORITY_ORDER = ("urgent", "high", "medium", "low", "none")


# ----------------------------------------------------------------------------- field cleaning


def _criteria(items: list[Any]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        data = item if isinstance(item, dict) else item.model_dump()
        text = clean_text(data.get("text"), 1000)
        if text:
            out.append({"text": text, "done": bool(data.get("done", False))})
    return out


def _files(paths: list[Any]) -> list[str]:
    return list(dict.fromkeys(p for p in (clean_text(x, 500) for x in paths) if p))


def _criteria_summary(items: list[dict[str, Any]]) -> str:
    done = sum(1 for i in items if i.get("done"))
    return f"{len(items)} criteria ({done} done)"


def _check_related(db: Session, org_id: str, field: str, value: str | None) -> None:
    if value:
        model, label = RELATED_MODELS[field]
        get_scoped(db, model, value, org_id, label=label)


# ----------------------------------------------------------------------------- create


def create_task(db: Session, who: Any, *, title: str, **fields: Any) -> Task:
    actor = as_actor(who)
    unknown = set(fields) - CREATE_FIELDS
    if unknown:
        raise ValidationFailedError(f"Unknown task field(s): {', '.join(sorted(unknown))}")
    org_id = actor.org_id
    column: BoardColumn | None = None
    if fields.get("column_id"):
        column = get_column(db, org_id, fields["column_id"])
        board = get_active_board(db, org_id, fields.get("board_id") or column.board_id)
        if column.board_id != board.id:
            raise ValidationFailedError(f"Column '{column.name}' is not on board '{board.name}'.")
    elif fields.get("board_id"):
        board = get_active_board(db, org_id, fields["board_id"])
    else:
        board = default_board(db, org_id, actor.user_id)
    if column is None:
        columns = board_columns(db, org_id, board.id)
        if not columns:
            raise ConflictError(f"Board '{board.name}' has no columns.")
        column = columns[0]

    clean_title = clean_text(title, TITLE_MAX)
    if not clean_title:
        raise ValidationFailedError("A task needs a title.")
    overridden = check_entry(db, column, label="A new task", verification_status="unverified", task_id=None,
                             override_wip=bool(fields.get("override_wip")))
    for field in RELATED_MODELS:
        _check_related(db, org_id, field, fields.get(field))
    parent = validate_parent(db, None, fields["parent_task_id"], org_id) if fields.get("parent_task_id") else None

    task = Task(
        id=new_id("task"), organization_id=org_id, number=next_task_number(db, org_id), board_id=board.id,
        column_id=column.id, title=clean_title,
        task_type=fields.get("task_type") or (board.config or {}).get("default_task_type") or "task",
        priority=fields.get("priority") or "medium", severity=fields.get("severity"),
        reporter_user_id=actor.user_id, due_date=fields.get("due_date"),
        parent_task_id=parent.id if parent else None,
        related_agent_id=fields.get("related_agent_id"), related_incident_id=fields.get("related_incident_id"),
        related_finding_id=fields.get("related_finding_id"),
        related_files=_files(fields.get("related_files") or []), links={},
        acceptance_criteria=_criteria(fields.get("acceptance_criteria") or []),
        verification_status="unverified", reopened_count=0,
        **{k: clean_text(fields.get(k), limit) for k, limit in TEXT_FIELDS.items()},
    )
    apply_done_transition(task, None, column)
    db.add(task)
    db.flush()
    reposition(db, task, column, None)
    record_activity(db, task, actor.user_id, "created", to_value=column.name,
                    details={"board_id": board.id, "column_id": column.id, "wip_override": overridden})
    if fields.get("label_ids"):
        set_task_labels(db, actor, task, list(fields["label_ids"]))
    if fields.get("assignee_ids"):
        set_assignees(db, actor, task, [(u, "assignee") for u in dict.fromkeys(fields["assignee_ids"])])
    db.flush()
    audit_task(db, actor, task, "created", {"board_id": board.id, "column_id": column.id, "task_type": task.task_type})
    return task


# ----------------------------------------------------------------------------- update


def _set(db: Session, actor: Actor, task: Task, field: str, new: Any, *, shown: tuple[Any, Any] | None = None) -> bool:
    old = getattr(task, field)
    if old == new:
        return False
    setattr(task, field, new)
    before, after = shown if shown is not None else (old, new)
    record_activity(db, task, actor.user_id, "updated", from_value=before, to_value=after, details={"field": field})
    return True


def update_task(db: Session, who: Any, task: Task, changes: dict[str, Any]) -> list[str]:
    """Apply a PATCH. Fields absent from ``changes`` are untouched; ``None`` clears nullable fields."""
    actor = as_actor(who)
    changed: list[str] = []
    archived = changes.pop("archived", None)
    if archived is False and task.archived_at is not None:
        restore_task(db, actor, task)
        changed.append("archived")
    if task.archived_at is not None and changes:
        raise ConflictError(f"{task_key(task)} is archived. Restore it before editing.")
    for field, value in changes.items():
        if field == "title":
            if value is not None and _set(db, actor, task, "title", clean_text(value, TITLE_MAX) or task.title):
                changed.append(field)
        elif field in TEXT_FIELDS:
            if _set(db, actor, task, field, clean_text(value, TEXT_FIELDS[field])):
                changed.append(field)
        elif field == "resolution":
            if _set(db, actor, task, field, clean_optional(value, TEXT_MAX)):
                changed.append(field)
        elif field in ("task_type", "priority"):
            if value is not None and _set(db, actor, task, field, value):
                changed.append(field)
        elif field in ("severity", "due_date"):
            if _set(db, actor, task, field, value):
                changed.append(field)
        elif field in RELATED_MODELS:
            _check_related(db, task.organization_id, field, value)
            if _set(db, actor, task, field, value or None):
                changed.append(field)
        elif field == "parent_task_id":
            parent = validate_parent(db, task, value, task.organization_id) if value else None
            shown = (task.parent_task_id, task_key(parent) if parent else None)
            if _set(db, actor, task, field, parent.id if parent else None, shown=shown):
                changed.append(field)
        elif field == "related_files":
            if _set(db, actor, task, field, _files(value or [])):
                changed.append(field)
        elif field == "acceptance_criteria":
            new = _criteria(value or [])
            shown = (_criteria_summary(task.acceptance_criteria or []), _criteria_summary(new))
            if _set(db, actor, task, field, new, shown=shown):
                changed.append(field)
        elif field == "label_ids":
            added, removed = set_task_labels(db, actor, task, list(value or []))
            if added or removed:
                changed.append("labels")
        else:
            raise ValidationFailedError(f"Field '{field}' cannot be changed here.")
    edited = [f for f in changed if f != "archived"]
    if edited:
        db.flush()
        audit_task(db, actor, task, "updated", {"fields": edited})
    if archived is True and task.archived_at is None:
        archive_task(db, actor, task)
        changed.append("archived")
    return changed


def archive_task(db: Session, who: Any, task: Task) -> None:
    actor = as_actor(who)
    if task.archived_at is not None:
        return
    task.archived_at = utcnow()
    record_activity(db, task, actor.user_id, "archived")
    db.flush()
    audit_task(db, actor, task, "archived")


def restore_task(db: Session, who: Any, task: Task) -> None:
    actor = as_actor(who)
    if task.archived_at is None:
        return
    task.archived_at = None
    column = db.get(BoardColumn, task.column_id)
    if column is not None:
        reposition(db, task, column, None)
    record_activity(db, task, actor.user_id, "restored")
    db.flush()
    audit_task(db, actor, task, "restored")


# ----------------------------------------------------------------------------- move & automation


def move_task(
    db: Session, who: Any, task: Task, column_id: str, position: int | None = None, override_wip: bool = False,
    *, automation: dict[str, Any] | None = None,
) -> Task:
    """Move ``task`` into ``column_id`` at ``position`` (index; default end). Raises 409 on a closed gate."""
    actor = as_actor(who)
    if task.archived_at is not None:
        raise ConflictError(f"{task_key(task)} is archived. Restore it before moving it.")
    target = get_column(db, task.organization_id, column_id)
    board = get_active_board(db, task.organization_id, target.board_id)
    source = db.get(BoardColumn, task.column_id)
    if source is not None and source.id == target.id:
        reposition(db, task, target, position)
        db.flush()
        if automation is None:
            audit_task(db, actor, task, "reordered", {"column_id": target.id, "position": position})
        return task
    overridden = check_entry(db, target, label=task_key(task), verification_status=task.verification_status,
                             task_id=task.id, override_wip=override_wip)
    apply_done_transition(task, source, target)
    task.column_id, task.board_id = target.id, board.id
    reposition(db, task, target, position)
    details = {"from_column_id": source.id if source else None, "to_column_id": target.id,
               "wip_override": overridden}
    if automation is not None:
        record_activity(db, task, None, "automation", from_value=source.name if source else None,
                        to_value=target.name, details={**details, **automation})
    else:
        record_activity(db, task, actor.user_id, "moved", from_value=source.name if source else None,
                        to_value=target.name, details=details)
    db.flush()
    audit_task(db, actor, task, "moved", {**details, "automation": automation is not None})
    return task


def fire_automation(db: Session, task: Task, trigger: str, cause: dict[str, Any] | None = None) -> BoardColumn | None:
    """Apply the current column's rule for ``trigger``. Returns the new column, or None when nothing moved.

    Automation never bypasses gates: a rule blocked by a WIP limit or the verification gate is recorded
    as an ``automation_skipped`` system activity instead.
    """
    if task.archived_at is not None:
        return None
    column = db.get(BoardColumn, task.column_id)
    rule = next((r for r in (column.automation or []) if r.get("trigger") == trigger), None) if column else None
    if column is None or rule is None:
        return None
    info = {"trigger": trigger, "rule_column_id": column.id, **(cause or {})}
    target_id = str(rule.get("move_to_column_id"))
    system = Actor.system(task.organization_id)
    try:
        board = db.get(Board, column.board_id)
        target = get_board_column(db, board, target_id) if board else None
        if target is None:
            raise NotFoundError("target column missing")
        move_task(db, system, task, target.id, automation=info)
    except (ConflictError, NotFoundError) as exc:
        reason = exc.message if isinstance(exc, ConflictError) else "The rule's target column no longer exists."
        record_activity(db, task, None, "automation_skipped", from_value=column.name,
                        details={**info, "move_to_column_id": target_id, "reason": reason})
        db.flush()
        return None
    return target


# ----------------------------------------------------------------------------- listing


def task_query(
    org_id: str,
    *,
    user_id: str | None = None,
    board_id: str | None = None,
    column_id: str | None = None,
    assignee: str | None = None,
    task_type: str | None = None,
    priority: str | None = None,
    label: str | None = None,
    q: str | None = None,
    status_key: str | None = None,
    related_finding_id: str | None = None,
    related_incident_id: str | None = None,
    parent_task_id: str | None = None,
    overdue: bool | None = None,
    include_done: bool = False,
    include_archived: bool = False,
    sort: str = "updated",
    now: datetime | None = None,
) -> Select[tuple[Task]]:
    query = select(Task).join(BoardColumn, BoardColumn.id == Task.column_id).where(Task.organization_id == org_id)
    if not include_archived:
        query = query.where(Task.archived_at.is_(None))
    if not include_done:
        query = query.where(BoardColumn.is_done_column.is_(False))
    for column, value in ((Task.board_id, board_id), (Task.column_id, column_id), (Task.task_type, task_type),
                          (Task.priority, priority), (BoardColumn.status_key, status_key),
                          (Task.related_finding_id, related_finding_id),
                          (Task.related_incident_id, related_incident_id), (Task.parent_task_id, parent_task_id)):
        if value:
            query = query.where(column == value)
    if assignee:
        target = user_id if assignee == "me" else assignee
        if target is None:
            query = query.where(false())
        else:
            query = query.where(Task.id.in_(select(TaskAssignment.task_id).where(
                TaskAssignment.organization_id == org_id, TaskAssignment.user_id == target)))
    if label:
        query = query.where(Task.id.in_(
            select(TaskLabelLink.task_id).join(TaskLabel, TaskLabel.id == TaskLabelLink.label_id).where(
                TaskLabelLink.organization_id == org_id,
                or_(TaskLabel.id == label, func.lower(TaskLabel.name) == label.lower()))))
    if overdue is not None:
        moment = now or utcnow()
        is_overdue = (Task.due_date.is_not(None)) & (Task.due_date < moment) & BoardColumn.is_done_column.is_(False)
        query = query.where(is_overdue if overdue else ~is_overdue)
    if q and q.strip():
        term = q.strip()
        number = term.upper().removeprefix("CTX-")
        like = f"%{term.lower()}%"
        conditions = [func.lower(Task.title).like(like), func.lower(Task.description).like(like)]
        if number.isdigit():
            conditions.append(Task.number == int(number))
        query = query.where(or_(*conditions))
    if sort == "priority":
        rank = case({p: i for i, p in enumerate(PRIORITY_ORDER)}, value=Task.priority, else_=len(PRIORITY_ORDER))
        order: list[Any] = [rank, Task.updated_at.desc()]
    else:
        order = list(SORTS.get(sort, SORTS["updated"]))
    return query.order_by(*order, Task.number.desc())
