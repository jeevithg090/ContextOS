"""Engineering Workspace boards and columns: seeding, templates, customisation.

Contracts used by other packages:
- ``seed_default_board(db, org_id, created_by)`` — called by organisation bootstrap. Idempotent: when the
  organisation has no boards it creates "Engineering" (``software_development``, the default board) and
  "Security Remediation" (``security_remediation``).
- ``default_board`` / ``remediation_board`` — resolve (creating when missing) the board new tasks and
  finding remediation tasks land on.

Column layouts are validated with ``app.workspace.templates.validate_columns``; automation rules must
point at another column of the same board. Deleting a column is only allowed when it holds no active
tasks, or when a target column is given — the tasks are then moved through the normal workflow gates.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.models import Board, BoardColumn, Task
from app.schemas.workspace_boards import CARD_FIELDS
from app.services.org_counters import lock_org
from app.services.scoping import get_scoped
from app.services.workspace_tasks_common import (
    Actor,
    apply_done_transition,
    audit_board,
    board_columns,
    check_entry,
    clean_optional,
    clean_text,
    record_activity,
    reposition,
    task_key,
    verification_block_message,
    verification_gate,
)
from app.workspace.templates import DEFAULT_TEMPLATE, get_template, validate_columns

ENGINEERING_BOARD = ("Engineering", DEFAULT_TEMPLATE)
REMEDIATION_TEMPLATE = "security_remediation"
REMEDIATION_BOARD = ("Security Remediation", REMEDIATION_TEMPLATE)
AUTOMATION_TRIGGERS = ("pr_linked", "verification_passed", "verification_failed", "fix_attempt_started")
_COLUMN_FIELDS = ("name", "description", "color", "status_key", "wip_limit", "is_done_column", "requires_verification")
MAX_COLUMNS = 30


# ----------------------------------------------------------------------------- lookup & seeding


def get_board(db: Session, org_id: str, board_id: str) -> Board:
    return get_scoped(db, Board, board_id, org_id, label="Board")


def get_active_board(db: Session, org_id: str, board_id: str) -> Board:
    board = get_board(db, org_id, board_id)
    if board.archived_at is not None:
        raise ConflictError(f"Board '{board.name}' is archived. Restore it before adding or moving work on it.")
    return board


def list_boards(db: Session, org_id: str, *, include_archived: bool = False) -> list[Board]:
    query = select(Board).where(Board.organization_id == org_id)
    if not include_archived:
        query = query.where(Board.archived_at.is_(None))
    return list(db.scalars(query.order_by(Board.is_default.desc(), Board.created_at)))


def _create_from_template(
    db: Session, org_id: str, *, name: str, template: str, description: str | None, created_by: str | None,
    is_default: bool = False,
) -> Board:
    try:
        tpl = get_template(template)
    except KeyError as exc:
        raise ValidationFailedError(str(exc.args[0])) from exc
    board = Board(
        id=new_id("board"), organization_id=org_id, name=name, description=description or tpl["description"],
        template=template, is_default=is_default, config={}, created_by=created_by,
    )
    db.add(board)
    db.flush()
    for position, spec in enumerate(tpl["columns"]):
        db.add(BoardColumn(id=new_id("board_column"), organization_id=org_id, board_id=board.id, position=position,
                           automation=[], **{k: spec[k] for k in _COLUMN_FIELDS}))
    db.flush()
    return board


def seed_default_board(db: Session, org_id: str, created_by: str | None = None) -> list[Board]:
    """Create the Engineering and Security Remediation boards when the organisation has no boards."""
    def has_boards() -> bool:
        return bool(db.scalar(select(func.count()).select_from(Board).where(Board.organization_id == org_id)))

    if has_boards():
        return []
    lock_org(db, org_id)  # concurrent first visits seed once: the second re-checks after the first commits
    if has_boards():
        return []
    boards = [
        _create_from_template(db, org_id, name=ENGINEERING_BOARD[0], template=ENGINEERING_BOARD[1], description=None,
                              created_by=created_by, is_default=True),
        _create_from_template(db, org_id, name=REMEDIATION_BOARD[0], template=REMEDIATION_BOARD[1], description=None,
                              created_by=created_by),
    ]
    return boards


def default_board(db: Session, org_id: str, created_by: str | None = None) -> Board:
    """The organisation's default board (seeding the defaults when the organisation has no boards)."""
    seed_default_board(db, org_id, created_by)
    board = db.scalars(select(Board).where(
        Board.organization_id == org_id, Board.archived_at.is_(None)
    ).order_by(Board.is_default.desc(), Board.created_at)).first()
    if board is None:
        raise ConflictError("Every board is archived. Restore or create a board first.")
    return board


def remediation_board(db: Session, org_id: str, created_by: str | None = None) -> Board:
    """The oldest active Security Remediation board, created from its template when none exists."""
    seed_default_board(db, org_id, created_by)
    board = db.scalars(select(Board).where(
        Board.organization_id == org_id, Board.archived_at.is_(None), Board.template == REMEDIATION_TEMPLATE,
    ).order_by(Board.created_at)).first()
    if board is not None:
        return board
    return _create_from_template(db, org_id, name=REMEDIATION_BOARD[0], template=REMEDIATION_TEMPLATE,
                                 description=None, created_by=created_by)


# ----------------------------------------------------------------------------- boards


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    clean = {k: v for k, v in config.items() if v is not None}
    fields = clean.get("card_fields")
    if fields is not None:
        unknown = [f for f in fields if f not in CARD_FIELDS]
        if unknown:
            raise ValidationFailedError(
                f"Unknown card field(s): {', '.join(unknown)}. Choose from: {', '.join(CARD_FIELDS)}.",
                details={"errors": [f"Unknown card field '{f}'" for f in unknown]},
            )
        clean["card_fields"] = list(dict.fromkeys(fields))
    return clean


def create_board(db: Session, actor: Actor, *, name: str, template: str, description: str | None) -> Board:
    board = _create_from_template(
        db, actor.org_id, name=clean_text(name, 200), template=template,
        description=clean_optional(description, 4000), created_by=actor.user_id,
        is_default=not list_boards(db, actor.org_id),
    )
    audit_board(db, actor, board.id, "created", {"name": board.name, "template": template})
    return board


def _clear_other_defaults(db: Session, board: Board) -> None:
    for other in db.scalars(select(Board).where(
        Board.organization_id == board.organization_id, Board.is_default.is_(True), Board.id != board.id
    )):
        other.is_default = False


def update_board(db: Session, actor: Actor, board: Board, changes: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    if "name" in changes and changes["name"] is not None:
        name = clean_text(changes["name"], 200)
        if name and name != board.name:
            board.name, changed = name, [*changed, "name"]
    if "description" in changes:
        description = clean_optional(changes["description"], 4000)
        if description != board.description:
            board.description, changed = description, [*changed, "description"]
    if changes.get("config") is not None:
        config = {**(board.config or {}), **_validate_config(dict(changes["config"]))}
        if config != (board.config or {}):
            board.config, changed = config, [*changed, "config"]
    if "archived" in changes and changes["archived"] is not None:
        if changes["archived"] and board.archived_at is None:
            _archive(db, board)
            changed.append("archived")
        elif not changes["archived"] and board.archived_at is not None:
            board.archived_at = None
            changed.append("archived")
    if changes.get("is_default") is True and not board.is_default:
        if board.archived_at is not None:
            raise ConflictError("An archived board cannot be the default board.")
        _clear_other_defaults(db, board)
        board.is_default, changed = True, [*changed, "is_default"]
    elif changes.get("is_default") is False and board.is_default:
        raise ConflictError("The organisation always has one default board. Make another board the default instead.")
    if changed:
        audit_board(db, actor, board.id, "updated", {"fields": changed})
    return changed


def _archive(db: Session, board: Board) -> None:
    if board.is_default:
        raise ConflictError("The default board cannot be archived. Make another board the default first.")
    board.archived_at = utcnow()


def archive_board(db: Session, actor: Actor, board: Board) -> None:
    if board.archived_at is not None:
        return
    _archive(db, board)
    audit_board(db, actor, board.id, "archived", {"name": board.name})


def duplicate_board(db: Session, actor: Actor, board: Board, name: str | None) -> Board:
    """Copy the board's settings and column layout (with automation rules remapped). Tasks are not copied."""
    copy = Board(
        id=new_id("board"), organization_id=board.organization_id,
        name=clean_text(name, 200) if name else f"{board.name} (copy)"[:200], description=board.description,
        template=board.template, is_default=False, config=dict(board.config or {}), created_by=actor.user_id,
    )
    db.add(copy)
    db.flush()
    columns = board_columns(db, board.organization_id, board.id)
    id_map = {col.id: new_id("board_column") for col in columns}
    for col in columns:
        db.add(BoardColumn(
            id=id_map[col.id], organization_id=col.organization_id, board_id=copy.id, position=col.position,
            automation=[{"trigger": r["trigger"], "move_to_column_id": id_map[r["move_to_column_id"]]}
                        for r in (col.automation or []) if r.get("move_to_column_id") in id_map],
            **{k: getattr(col, k) for k in _COLUMN_FIELDS},
        ))
    db.flush()
    audit_board(db, actor, copy.id, "duplicated", {"source_board_id": board.id, "name": copy.name})
    return copy


# ----------------------------------------------------------------------------- columns


def _layout_errors(layout: list[dict[str, Any]]) -> list[str]:
    errors = validate_columns(layout)
    if len(layout) > MAX_COLUMNS:
        errors.append(f"A board can have at most {MAX_COLUMNS} columns.")
    return errors


def _automation_errors(rules: list[dict[str, Any]], column_id: str, board_column_ids: set[str]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, rule in enumerate(rules, start=1):
        trigger, target = rule.get("trigger"), rule.get("move_to_column_id")
        if trigger not in AUTOMATION_TRIGGERS:
            errors.append(f"Automation rule {index}: unknown trigger {trigger!r}.")
        elif trigger in seen:
            errors.append(f"Automation rule {index}: '{trigger}' already has a rule in this column.")
        else:
            seen.add(trigger)
        if target == column_id:
            errors.append(f"Automation rule {index}: a column cannot move tasks into itself.")
        elif target not in board_column_ids:
            errors.append(f"Automation rule {index}: column {target!r} is not a column of this board.")
    return errors


def _raise_if(errors: list[str]) -> None:
    if errors:
        raise ValidationFailedError(errors[0] if len(errors) == 1 else "The column layout is invalid.",
                                    details={"errors": errors})


def _as_layout(columns: list[BoardColumn]) -> list[dict[str, Any]]:
    return [{k: getattr(c, k) for k in _COLUMN_FIELDS} for c in columns]


def _column_values(data: dict[str, Any]) -> dict[str, Any]:
    values = {k: data[k] for k in _COLUMN_FIELDS if k in data}
    if "name" in values and values["name"] is not None:
        values["name"] = clean_text(values["name"], 100)
    if "description" in values:
        values["description"] = clean_optional(values["description"], 2000)
    return values


def get_board_column(db: Session, board: Board, column_id: str) -> BoardColumn:
    column = get_scoped(db, BoardColumn, column_id, board.organization_id, label="Column")
    if column.board_id != board.id:
        raise NotFoundError(f"Column '{column_id}' not found on board '{board.name}'")
    return column


def add_column(db: Session, actor: Actor, board: Board, data: dict[str, Any]) -> BoardColumn:
    columns = board_columns(db, board.organization_id, board.id)
    column = BoardColumn(id=new_id("board_column"), organization_id=board.organization_id, board_id=board.id,
                         automation=[], **_column_values(data))
    rules = [dict(r) for r in data.get("automation") or []]
    index = len(columns) if data.get("position") is None else min(int(data["position"]), len(columns))
    columns.insert(index, column)
    _raise_if(_layout_errors(_as_layout(columns))
              + _automation_errors(rules, column.id, {c.id for c in columns}))
    column.automation = rules
    db.add(column)
    for position, col in enumerate(columns):
        col.position = position
    db.flush()
    audit_board(db, actor, board.id, "column_added", {"column_id": column.id, "name": column.name})
    return column


def update_column(db: Session, actor: Actor, board: Board, column: BoardColumn, changes: dict[str, Any]) -> list[str]:
    columns = board_columns(db, board.organization_id, board.id)
    values = _column_values(changes)
    if values.get("name") is None:
        values.pop("name", None)
    for key in ("color", "status_key", "is_done_column", "requires_verification"):
        if key in values and values[key] is None:
            values.pop(key)
    layout = [{**{k: getattr(c, k) for k in _COLUMN_FIELDS}, **(values if c.id == column.id else {})} for c in columns]
    errors = _layout_errors(layout)
    rules = None
    if changes.get("automation") is not None:
        rules = [dict(r) for r in changes["automation"]]
        errors += _automation_errors(rules, column.id, {c.id for c in columns})
    _raise_if(errors)
    changed = [k for k, v in values.items() if getattr(column, k) != v]
    was_done = column.is_done_column
    for key in changed:
        setattr(column, key, values[key])
    if rules is not None and rules != (column.automation or []):
        column.automation = rules
        changed.append("automation")
    affected = _sync_completion(db, column) if column.is_done_column != was_done else 0
    if changed:
        db.flush()
        audit_board(db, actor, board.id, "column_updated",
                    {"column_id": column.id, "fields": changed, "tasks_completion_updated": affected})
    return changed


def _sync_completion(db: Session, column: BoardColumn) -> int:
    """Keep ``completed_at`` consistent when a column's done flag is changed (configuration, not a reopen)."""
    tasks = list(db.scalars(select(Task).where(Task.organization_id == column.organization_id,
                                               Task.column_id == column.id)))
    now = utcnow()
    for task in tasks:
        task.completed_at = (task.completed_at or now) if column.is_done_column else None
    return len(tasks)


def delete_column(
    db: Session, actor: Actor, board: Board, column: BoardColumn, *, move_to: str | None, override_wip: bool = False
) -> dict[str, Any]:
    """Delete a column. Active tasks block deletion unless ``move_to`` names another column of the board."""
    columns = board_columns(db, board.organization_id, board.id)
    remaining = [c for c in columns if c.id != column.id]
    _raise_if(_layout_errors(_as_layout(remaining)))
    tasks = list(db.scalars(select(Task).where(
        Task.organization_id == board.organization_id, Task.column_id == column.id
    ).order_by(Task.position, Task.number)))
    active = [t for t in tasks if t.archived_at is None]
    if active and not move_to:
        raise ConflictError(
            f"'{column.name}' still holds {len(active)} task{'s' if len(active) != 1 else ''}. Move them out first "
            "or choose a column to move them to.",
            details={"reason": "column_not_empty", "task_count": len(active)},
        )
    target = get_board_column(db, board, move_to) if move_to else remaining[0]
    if target.id == column.id:
        raise ValidationFailedError("Choose a different column to move the tasks to.")
    if active:
        gate = verification_gate(db, target)
        blocked = [t for t in active if t.verification_status != "passed"]
        if gate is not None and blocked:
            raise ConflictError(
                verification_block_message(f"{len(blocked)} task(s) including {task_key(blocked[0])}", target, gate,
                                           blocked[0].verification_status),
                details={"reason": "verification_required", "column_id": target.id, "gate_column_id": gate.id,
                         "task_ids": [t.id for t in blocked]},
            )
        overridden = check_entry(db, target, label=f"{len(active)} task(s)", verification_status="passed",
                                 task_id=None, override_wip=override_wip, incoming=len(active))
        for task in active:
            apply_done_transition(task, column, target)
            task.column_id = target.id
            reposition(db, task, target, None)
            record_activity(db, task, actor.user_id, "moved", from_value=column.name, to_value=target.name,
                            details={"from_column_id": column.id, "to_column_id": target.id,
                                     "reason": "column_deleted", "wip_override": overridden})
            db.flush()
    for task in tasks:
        if task.archived_at is not None:
            task.column_id = target.id
    removed_rules = 0
    for other in remaining:
        rules = list(other.automation or [])
        kept = [r for r in rules if r.get("move_to_column_id") != column.id]
        if len(kept) != len(rules):
            removed_rules += len(rules) - len(kept)
            other.automation = kept
    db.flush()
    db.delete(column)
    for position, col in enumerate(remaining):
        col.position = position
    db.flush()
    result = {"deleted_column_id": column.id, "moved_task_count": len(active),
              "moved_to_column_id": target.id if active else None, "removed_automation_rules": removed_rules}
    audit_board(db, actor, board.id, "column_deleted", {"name": column.name, **result})
    return result


def reorder_columns(db: Session, actor: Actor, board: Board, column_ids: list[str]) -> list[BoardColumn]:
    columns = board_columns(db, board.organization_id, board.id)
    by_id = {c.id: c for c in columns}
    if len(column_ids) != len(set(column_ids)) or set(column_ids) != set(by_id):
        raise ValidationFailedError(
            "column_ids must list every column of the board exactly once.",
            details={"errors": ["column_ids must list every column of the board exactly once"],
                     "expected": sorted(by_id)},
        )
    for position, column_id in enumerate(column_ids):
        by_id[column_id].position = position
    db.flush()
    audit_board(db, actor, board.id, "columns_reordered", {"column_ids": column_ids})
    return [by_id[c] for c in column_ids]
