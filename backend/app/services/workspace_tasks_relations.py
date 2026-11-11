"""Task relations: labels, assignees, subtasks (parent links), dependencies and comments.

Rules:
- Labels are unique per organisation (case-insensitive).
- Assignees and reviewers must be members of the task's organisation.
- A task cannot be its own ancestor (no parent cycles) and ``blocks`` dependencies cannot form a cycle.
- Comments are redacted before storage; only the author may edit a comment; the author or an admin may
  delete it.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.models import (
    Membership,
    Task,
    TaskAssignment,
    TaskComment,
    TaskDependency,
    TaskLabel,
    TaskLabelLink,
    User,
)
from app.schemas.workspace import TEXT_MAX
from app.services.scoping import get_scoped
from app.services.workspace_tasks_common import (
    Actor,
    audit_task,
    clean_text,
    get_task,
    record_activity,
    task_key,
)
from app.workspace.templates import COLOR_TOKENS

MAX_PARENT_DEPTH = 10


def _valid_color(color: str) -> bool:
    return color in COLOR_TOKENS or (
        len(color) == 7 and color.startswith("#") and all(c in "0123456789abcdefABCDEF" for c in color[1:])
    )


# ----------------------------------------------------------------------------- labels


def list_labels(db: Session, org_id: str) -> list[tuple[TaskLabel, int]]:
    usage = (
        select(TaskLabelLink.label_id, func.count(TaskLabelLink.id).label("n"))
        .join(Task, Task.id == TaskLabelLink.task_id)
        .where(TaskLabelLink.organization_id == org_id, Task.archived_at.is_(None))
        .group_by(TaskLabelLink.label_id)
        .subquery()
    )
    rows = db.execute(
        select(TaskLabel, func.coalesce(usage.c.n, 0))
        .outerjoin(usage, usage.c.label_id == TaskLabel.id)
        .where(TaskLabel.organization_id == org_id)
        .order_by(func.lower(TaskLabel.name))
    ).all()
    return [(label, int(count)) for label, count in rows]


def create_label(db: Session, actor: Actor, *, name: str, color: str) -> TaskLabel:
    clean = clean_text(name, 64)
    if not clean:
        raise ValidationFailedError("A label needs a name.")
    if not _valid_color(color):
        raise ValidationFailedError(f"Label colour must be a token name ({', '.join(COLOR_TOKENS)}) or #rrggbb.")
    exists = db.scalar(select(TaskLabel.id).where(
        TaskLabel.organization_id == actor.org_id, func.lower(TaskLabel.name) == clean.lower()
    ))
    if exists:
        raise ConflictError(f"A label named '{clean}' already exists.", details={"label_id": exists})
    label = TaskLabel(id=new_id("task_label"), organization_id=actor.org_id, name=clean, color=color)
    db.add(label)
    db.flush()
    return label


def task_label_ids(db: Session, task: Task) -> list[str]:
    return list(db.scalars(select(TaskLabelLink.label_id).where(
        TaskLabelLink.organization_id == task.organization_id, TaskLabelLink.task_id == task.id
    )))


def set_task_labels(db: Session, actor: Actor, task: Task, label_ids: list[str]) -> tuple[list[str], list[str]]:
    """Replace the task's labels. Returns ``(added_names, removed_names)``; unknown ids are a 404."""
    wanted = list(dict.fromkeys(label_ids))
    labels = {row.id: row for row in db.scalars(select(TaskLabel).where(
        TaskLabel.organization_id == task.organization_id, TaskLabel.id.in_(wanted or [""])
    ))}
    missing = [i for i in wanted if i not in labels]
    if missing:
        raise NotFoundError(f"Label '{missing[0]}' not found")
    current = set(task_label_ids(db, task))
    added, removed = [i for i in wanted if i not in current], [i for i in current if i not in wanted]
    for label_id in added:
        db.add(TaskLabelLink(id=new_id("tll"), organization_id=task.organization_id, task_id=task.id, label_id=label_id))
    if removed:
        for link in db.scalars(select(TaskLabelLink).where(
            TaskLabelLink.organization_id == task.organization_id, TaskLabelLink.task_id == task.id,
            TaskLabelLink.label_id.in_(removed),
        )):
            db.delete(link)
    names_removed = list(db.scalars(select(TaskLabel.name).where(
        TaskLabel.organization_id == task.organization_id, TaskLabel.id.in_(removed or [""]))))
    added_names, removed_names = [labels[i].name for i in added], names_removed
    if added or removed:
        record_activity(db, task, actor.user_id, "labels_changed",
                        details={"added": added_names, "removed": removed_names})
        db.flush()
    return added_names, removed_names


# ----------------------------------------------------------------------------- assignees


def _members(db: Session, org_id: str, user_ids: list[str]) -> dict[str, User]:
    rows = db.execute(
        select(User).join(Membership, Membership.user_id == User.id)
        .where(Membership.organization_id == org_id, User.id.in_(user_ids or [""]))
    ).scalars()
    return {u.id: u for u in rows}


def set_assignees(db: Session, actor: Actor, task: Task, assignees: list[tuple[str, str]]) -> list[str]:
    """Replace assignees/reviewers. Every user must be a member of the organisation (422 otherwise)."""
    user_ids = [u for u, _ in assignees]
    if len(user_ids) != len(set(user_ids)):
        raise ValidationFailedError("Each person can be listed only once (as assignee or reviewer).")
    members = _members(db, task.organization_id, user_ids)
    unknown = [u for u in user_ids if u not in members]
    if unknown:
        raise ValidationFailedError(f"User '{unknown[0]}' is not a member of this organisation.",
                                    details={"errors": [f"User '{u}' is not a member" for u in unknown]})
    current = {a.user_id: a for a in db.scalars(select(TaskAssignment).where(
        TaskAssignment.organization_id == task.organization_id, TaskAssignment.task_id == task.id
    ))}
    wanted = dict(assignees)
    changes: list[str] = []
    for user_id, row in current.items():
        if user_id not in wanted:
            db.delete(row)
            changes.append(f"removed {row.role} {user_id}")
        elif row.role != wanted[user_id]:
            changes.append(f"{user_id}: {row.role} → {wanted[user_id]}")
            row.role = wanted[user_id]
    for user_id, role in assignees:
        if user_id not in current:
            db.add(TaskAssignment(id=new_id("task_assignment"), organization_id=task.organization_id,
                                  task_id=task.id, user_id=user_id, role=role, created_at=utcnow()))
            changes.append(f"added {role} {user_id}")
    if changes:
        added = [members[u].name for u, _ in assignees if u not in current]
        removed_ids = [u for u in current if u not in wanted]
        removed = [n for n in db.scalars(select(User.name).where(User.id.in_(removed_ids or [""])))]
        record_activity(db, task, actor.user_id, "assignees_changed",
                        details={"added": added, "removed": removed, "changes": changes})
        db.flush()
        audit_task(db, actor, task, "assignees_changed", {"assignees": [{"user_id": u, "role": r} for u, r in assignees]})
    return changes


# ----------------------------------------------------------------------------- parent / subtasks


def validate_parent(db: Session, task: Task | None, parent_id: str, org_id: str) -> Task:
    """Return the parent task if linking is allowed (same org, no cycle, bounded depth)."""
    parent = get_task(db, org_id, parent_id)
    if task is not None and parent.id == task.id:
        raise ValidationFailedError("A task cannot be its own parent.")
    seen: set[str] = set()
    cursor: Task | None = parent
    depth = 0
    while cursor is not None:
        if task is not None and cursor.id == task.id:
            raise ConflictError(
                f"{task_key(parent)} is a subtask of {task_key(task)}, so it cannot also be its parent.",
                details={"reason": "parent_cycle"},
            )
        if cursor.id in seen:
            break
        seen.add(cursor.id)
        depth += 1
        if depth > MAX_PARENT_DEPTH:
            raise ValidationFailedError(f"Subtasks can be nested at most {MAX_PARENT_DEPTH} levels deep.")
        cursor = db.get(Task, cursor.parent_task_id) if cursor.parent_task_id else None
    return parent


# ----------------------------------------------------------------------------- dependencies


def _blocking_path(db: Session, org_id: str, start_id: str, goal_id: str) -> list[str] | None:
    """Ids from ``start_id`` to ``goal_id`` following ``blocks`` dependencies (task → depends_on), or None."""
    parents: dict[str, str | None] = {start_id: None}
    frontier = [start_id]
    while frontier:
        edges = db.execute(select(TaskDependency.task_id, TaskDependency.depends_on_task_id).where(
            TaskDependency.organization_id == org_id, TaskDependency.kind == "blocks",
            TaskDependency.task_id.in_(frontier),
        )).all()
        frontier = []
        for src, dst in edges:
            if dst in parents:
                continue
            parents[dst] = src
            if dst == goal_id:
                path, node = [], dst
                while node is not None:
                    path.append(node)
                    node = parents[node]
                return list(reversed(path))
            frontier.append(dst)
    return None


def add_dependency(db: Session, actor: Actor, task: Task, depends_on_task_id: str, kind: str) -> TaskDependency:
    """``task`` depends on ``depends_on_task_id``. ``blocks`` dependencies may not form a cycle."""
    other = get_task(db, task.organization_id, depends_on_task_id)
    if other.id == task.id:
        raise ValidationFailedError("A task cannot depend on itself.")
    pair = (TaskDependency.task_id == task.id) & (TaskDependency.depends_on_task_id == other.id)
    if kind == "relates_to":  # "relates to" is symmetric: the reverse link counts as the same link
        pair = pair | ((TaskDependency.task_id == other.id) & (TaskDependency.depends_on_task_id == task.id)
                       & (TaskDependency.kind == "relates_to"))
    existing = db.scalar(select(TaskDependency).where(TaskDependency.organization_id == task.organization_id, pair))
    if existing is not None:
        raise ConflictError(f"{task_key(task)} and {task_key(other)} are already linked ({existing.kind}).",
                            details={"dependency_id": existing.id})
    if kind == "blocks":
        path = _blocking_path(db, task.organization_id, other.id, task.id)
        if path is not None:
            keys = {t.id: task_key(t) for t in db.scalars(select(Task).where(Task.id.in_(path)))}
            chain = " → ".join([task_key(task), *(keys.get(i, i) for i in path)])
            raise ConflictError(
                f"This dependency would create a cycle: {chain}. Remove one of the existing dependencies first.",
                details={"reason": "dependency_cycle", "path": [task.id, *path]},
            )
    dep = TaskDependency(id=new_id("task_dependency"), organization_id=task.organization_id, task_id=task.id,
                         depends_on_task_id=other.id, kind=kind, created_at=utcnow())
    db.add(dep)
    db.flush()
    record_activity(db, task, actor.user_id, "dependency_added", to_value=task_key(other),
                    details={"depends_on_task_id": other.id, "kind": kind})
    audit_task(db, actor, task, "dependency_added", {"depends_on_task_id": other.id, "kind": kind})
    return dep


def remove_dependency(db: Session, actor: Actor, dependency_id: str) -> None:
    dep = get_scoped(db, TaskDependency, dependency_id, actor.org_id, label="Dependency")
    task = get_task(db, actor.org_id, dep.task_id)
    other = db.get(Task, dep.depends_on_task_id)
    db.delete(dep)
    record_activity(db, task, actor.user_id, "dependency_removed", from_value=task_key(other) if other else None,
                    details={"depends_on_task_id": dep.depends_on_task_id, "kind": dep.kind})
    db.flush()
    audit_task(db, actor, task, "dependency_removed", {"depends_on_task_id": dep.depends_on_task_id})


# ----------------------------------------------------------------------------- comments


def add_comment(db: Session, actor: Actor, task: Task, body: str) -> TaskComment:
    text = clean_text(body, TEXT_MAX)
    if not text:
        raise ValidationFailedError("A comment cannot be empty.")
    comment = TaskComment(id=new_id("task_comment"), organization_id=task.organization_id, task_id=task.id,
                          author_user_id=actor.user_id, body=text, created_at=utcnow())
    db.add(comment)
    db.flush()
    record_activity(db, task, actor.user_id, "commented", details={"comment_id": comment.id})
    audit_task(db, actor, task, "commented", {"comment_id": comment.id})
    return comment


def _comment(db: Session, actor: Actor, comment_id: str) -> tuple[TaskComment, Task]:
    comment = get_scoped(db, TaskComment, comment_id, actor.org_id, label="Comment")
    return comment, get_task(db, actor.org_id, comment.task_id)


def edit_comment(db: Session, actor: Actor, comment_id: str, body: str) -> TaskComment:
    comment, task = _comment(db, actor, comment_id)
    if actor.user_id is None or comment.author_user_id != actor.user_id:
        raise PermissionDeniedError("Only the author can edit this comment.")
    text = clean_text(body, TEXT_MAX)
    if not text:
        raise ValidationFailedError("A comment cannot be empty.")
    if text != comment.body:
        comment.body, comment.edited_at = text, utcnow()
        record_activity(db, task, actor.user_id, "comment_edited", details={"comment_id": comment.id})
        audit_task(db, actor, task, "comment_edited", {"comment_id": comment.id})
    return comment


def delete_comment(db: Session, actor: Actor, comment_id: str) -> None:
    comment, task = _comment(db, actor, comment_id)
    is_author = actor.user_id is not None and comment.author_user_id == actor.user_id
    if not (is_author or actor.is_admin):
        raise PermissionDeniedError("Only the author or an organisation admin can delete this comment.")
    db.delete(comment)
    record_activity(db, task, actor.user_id, "comment_deleted", details={"comment_id": comment.id,
                                                                          "by_admin": not is_author})
    db.flush()
    audit_task(db, actor, task, "comment_deleted", {"comment_id": comment.id})


def dependency_rows(db: Session, task: Task) -> tuple[list[TaskDependency], list[TaskDependency]]:
    """``(blocked_by, blocking)``: dependencies of this task, and dependencies on this task."""
    base = select(TaskDependency).where(TaskDependency.organization_id == task.organization_id)
    blocked_by = list(db.scalars(base.where(TaskDependency.task_id == task.id).order_by(TaskDependency.created_at)))
    blocking = list(db.scalars(base.where(TaskDependency.depends_on_task_id == task.id)
                               .order_by(TaskDependency.created_at)))
    return blocked_by, blocking
