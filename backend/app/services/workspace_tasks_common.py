"""Engineering Workspace shared service helpers: actor, text cleaning, activity, audit + notify,
column-entry gates and done/reopen bookkeeping.

Used by ``workspace_boards`` and every ``workspace_tasks*`` module. Nothing here commits; callers run
inside the request transaction (``get_db`` commits on success).

Workflow gates (applied to every move, including automation and column deletion):
- **WIP limit** — entering a column whose ``wip_limit`` is already reached is refused with a 409
  unless the caller explicitly overrides it (the override is written to the task activity). The
  column is counted under the organisation write lock (``org_counters.lock_org``), so concurrent
  moves cannot all pass the check.
- **Verification gate** — entering a column with ``requires_verification``, or a done column that
  comes *after* such a column on the same board, requires ``task.verification_status == "passed"``.
  A fix attempt marked ``claimed_complete`` is a claim, never verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError
from app.core.ids import new_id
from app.core.timeutil import isoformat, utcnow
from app.domain.enums import Permission
from app.engines.redaction import redact_text, redact_value
from app.models import BoardColumn, Task, TaskActivity
from app.services.audit import append_audit
from app.services.notify import notify
from app.services.org_counters import lock_org, reserve
from app.services.scoping import get_scoped

TASK_KEY_PREFIX = "CTX"
ACTIVITY_VALUE_MAX = 500


@dataclass(frozen=True)
class Actor:
    """Who is changing workspace data. ``user_id`` is None for system / automation changes."""

    org_id: str
    type: str  # "user" | "api_key" | "system"
    id: str | None
    user_id: str | None = None
    is_admin: bool = False

    @classmethod
    def system(cls, org_id: str) -> Actor:
        return cls(org_id=org_id, type="system", id=None)


def as_actor(who: Any) -> Actor:
    """Accept an :class:`Actor` or an ``app.api.deps.Principal`` (duck-typed to avoid importing the API layer)."""
    if isinstance(who, Actor):
        return who
    has = getattr(who, "has", None)
    return Actor(
        org_id=who.org_id,
        type=who.actor_type,
        id=who.actor_id,
        user_id=getattr(who, "user_id", None),
        is_admin=bool(has(Permission.ADMIN.value)) if callable(has) else False,
    )


# ----------------------------------------------------------------------------- text


def clean_text(value: Any, limit: int) -> str:
    """Redact secrets and cap length. Used for every free-text field before it is stored."""
    if value is None:
        return ""
    text = redact_text(value if isinstance(value, str) else str(value)).text.strip()
    return text[:limit]


def clean_optional(value: Any, limit: int) -> str | None:
    text = clean_text(value, limit)
    return text or None


def clean_json(value: Any) -> Any:
    redacted, _ = redact_value(value)
    return redacted


def activity_value(value: Any) -> str | None:
    """Short, redacted string form of a field value for ``TaskActivity.from_value/to_value``."""
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, datetime):
        return isoformat(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    text = clean_text(value, ACTIVITY_VALUE_MAX + 1)
    return text if len(text) <= ACTIVITY_VALUE_MAX else text[: ACTIVITY_VALUE_MAX - 1] + "…"


def task_key(task: Task) -> str:
    return f"{TASK_KEY_PREFIX}-{task.number}"


# ----------------------------------------------------------------------------- persistence helpers


def next_task_number(db: Session, org_id: str) -> int:
    return int(reserve(db, org_id, "task_seq")[0])  # atomic: concurrent creates never share a task key


def get_task(db: Session, org_id: str, task_id: str) -> Task:
    return get_scoped(db, Task, task_id, org_id, label="Task")


def get_column(db: Session, org_id: str, column_id: str) -> BoardColumn:
    return get_scoped(db, BoardColumn, column_id, org_id, label="Column")


def record_activity(
    db: Session,
    task: Task,
    actor_user_id: str | None,
    kind: str,
    *,
    from_value: Any = None,
    to_value: Any = None,
    details: dict[str, Any] | None = None,
) -> TaskActivity:
    row = TaskActivity(
        id=new_id("task_activity"),
        organization_id=task.organization_id,
        task_id=task.id,
        actor_user_id=actor_user_id,
        kind=kind[:48],
        from_value=activity_value(from_value),
        to_value=activity_value(to_value),
        details=clean_json(details or {}),
        created_at=utcnow(),
    )
    db.add(row)
    return row


def audit_task(db: Session, actor: Actor, task: Task, action: str, details: dict[str, Any] | None = None) -> None:
    """Audit ``task.<action>`` and queue a ``task.updated`` live notification (ids only)."""
    task.updated_at = utcnow()
    append_audit(
        db, task.organization_id, action=f"task.{action}", actor_type=actor.type, actor_id=actor.id,
        target_type="task", target_id=task.id, details={"key": task_key(task), **(details or {})},
    )
    notify(db, task.organization_id, "task.updated", id=task.id, board_id=task.board_id)


def audit_board(db: Session, actor: Actor, board_id: str, action: str, details: dict[str, Any] | None = None) -> None:
    append_audit(
        db, actor.org_id, action=f"board.{action}", actor_type=actor.type, actor_id=actor.id,
        target_type="board", target_id=board_id, details=details or {},
    )
    notify(db, actor.org_id, "task.updated", board_id=board_id)


# ----------------------------------------------------------------------------- columns & gates


def board_columns(db: Session, org_id: str, board_id: str) -> list[BoardColumn]:
    return list(db.scalars(
        select(BoardColumn)
        .where(BoardColumn.organization_id == org_id, BoardColumn.board_id == board_id)
        .order_by(BoardColumn.position, BoardColumn.created_at)
    ))


def column_task_count(db: Session, column: BoardColumn, *, exclude_task_id: str | None = None) -> int:
    query = select(func.count()).select_from(Task).where(
        Task.organization_id == column.organization_id, Task.column_id == column.id, Task.archived_at.is_(None)
    )
    if exclude_task_id:
        query = query.where(Task.id != exclude_task_id)
    return int(db.scalar(query) or 0)


def verification_gate(db: Session, column: BoardColumn) -> BoardColumn | None:
    """The column whose verification requirement applies when entering ``column`` (None = no gate)."""
    if column.requires_verification:
        return column
    if not column.is_done_column:
        return None
    return db.scalars(
        select(BoardColumn).where(
            BoardColumn.organization_id == column.organization_id,
            BoardColumn.board_id == column.board_id,
            BoardColumn.requires_verification.is_(True),
            BoardColumn.position < column.position,
        ).order_by(BoardColumn.position)
    ).first()


def verification_block_message(label: str, target: BoardColumn, gate: BoardColumn, status: str) -> str:
    where = (
        f"'{target.name}' requires it" if gate.id == target.id
        else f"'{target.name}' comes after the verification gate '{gate.name}' on this board"
    )
    return (
        f"{label} cannot move into '{target.name}': it needs passed verification evidence ({where}; current "
        f"verification status is '{status}'). Record a passed verification run (test run, code review, "
        "simulation, replay, deployment or manual check) first. A fix attempt marked claimed_complete is a "
        "claim, not verification."
    )


def check_entry(
    db: Session,
    target: BoardColumn,
    *,
    label: str,
    verification_status: str,
    task_id: str | None,
    override_wip: bool,
    incoming: int = 1,
) -> bool:
    """Raise ``ConflictError`` when ``incoming`` task(s) may not enter ``target``.

    Returns True when the WIP limit was exceeded and the caller chose to override it.
    """
    gate = verification_gate(db, target)
    if gate is not None and verification_status != "passed":
        raise ConflictError(
            verification_block_message(label, target, gate, verification_status),
            details={"reason": "verification_required", "column_id": target.id, "gate_column_id": gate.id,
                     "verification_status": verification_status},
        )
    if target.wip_limit is None:
        return False
    # Count under the organisation write lock: concurrent entries are checked one after the other, and
    # the limit is re-read in case it was changed meanwhile.
    lock_org(db, target.organization_id)
    limit = db.scalar(select(BoardColumn.wip_limit).where(
        BoardColumn.organization_id == target.organization_id, BoardColumn.id == target.id))
    if limit is None:
        return False
    current = column_task_count(db, target, exclude_task_id=task_id)
    if current + incoming <= limit:
        return False
    if not override_wip:
        raise ConflictError(
            f"'{target.name}' has a WIP limit of {limit} and already holds {current} task"
            f"{'s' if current != 1 else ''}. Finish or move work out of it first, or override the limit "
            "explicitly (the override is recorded on the task).",
            details={"reason": "wip_limit_exceeded", "column_id": target.id, "wip_limit": limit,
                     "task_count": current},
        )
    return True


def apply_done_transition(task: Task, source: BoardColumn | None, target: BoardColumn) -> None:
    """Entering a done column completes the task; leaving one reopens it."""
    was_done = bool(source and source.is_done_column)
    if target.is_done_column and not was_done:
        task.completed_at = utcnow()
    elif was_done and not target.is_done_column:
        task.completed_at = None
        task.reopened_count = (task.reopened_count or 0) + 1


def reposition(db: Session, task: Task, column: BoardColumn, index: int | None) -> None:
    """Place ``task`` at ``index`` within ``column`` (default: end) and renumber the column densely."""
    siblings = list(db.scalars(
        select(Task).where(
            Task.organization_id == column.organization_id, Task.column_id == column.id,
            Task.archived_at.is_(None), Task.id != task.id,
        ).order_by(Task.position, Task.number)
    ))
    at = len(siblings) if index is None else max(0, min(index, len(siblings)))
    siblings.insert(at, task)
    for pos, row in enumerate(siblings):
        row.position = float(pos)
