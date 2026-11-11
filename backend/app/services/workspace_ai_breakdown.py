"""Task breakdown: deterministic subtask drafts, and applying (possibly edited) drafts as real subtasks.

Drafts come from :func:`app.workspace.breakdown.decompose`; nothing is created until the user applies
them. Applying creates one subtask per draft (``parent_task_id`` = the task) through the regular task
services — so WIP limits, redaction, activity and audit all apply — then adds ``blocks`` dependencies
between them. Draft dependencies are validated as an acyclic graph before anything is written; the task
services check the stored graph for cycles again. The whole apply runs in one transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ValidationFailedError
from app.models import SecurityFinding, Task, TaskContextReference
from app.services.workspace_tasks import create_task
from app.services.workspace_tasks_common import Actor, audit_task, get_task, record_activity, task_key
from app.services.workspace_tasks_relations import add_dependency
from app.workspace.breakdown import PLAN_KEYS, SubtaskDraft, choose_plan, decompose

BREAKDOWN_NOTE = ("Drafts come from a deterministic plan template chosen from the task type and linked finding "
                  "category. Review and edit them before creating subtasks; nothing is created until you apply them.")


@dataclass
class AppliedBreakdown:
    parent: Task
    created: list[Task]
    dependencies: list[tuple[str, str]]


def _finding_category(db: Session, task: Task) -> str | None:
    ids = [task.related_finding_id] if task.related_finding_id else []
    ids += list(db.scalars(select(TaskContextReference.ref_id).where(
        TaskContextReference.organization_id == task.organization_id, TaskContextReference.task_id == task.id,
        TaskContextReference.ref_type == "finding").order_by(TaskContextReference.created_at)))
    for finding_id in ids:
        category = db.scalar(select(SecurityFinding.category).where(
            SecurityFinding.organization_id == task.organization_id, SecurityFinding.id == finding_id))
        if category:
            return category
    return None


def existing_subtasks(db: Session, task: Task) -> int:
    return int(db.scalar(select(func.count()).select_from(Task).where(
        Task.organization_id == task.organization_id, Task.parent_task_id == task.id, Task.archived_at.is_(None),
    )) or 0)


def draft_breakdown(db: Session, org_id: str, task_id: str, plan: str | None = None,
                    ) -> tuple[Task, str, list[SubtaskDraft]]:
    task = get_task(db, org_id, task_id)
    if plan is not None and plan not in PLAN_KEYS:
        message = f"Unknown breakdown plan '{plan}'; expected one of: {', '.join(PLAN_KEYS)}"
        raise ValidationFailedError(message, details={"errors": [message]})
    mapping = {"title": task.title, "description": task.description, "task_type": task.task_type,
               "related_finding_id": task.related_finding_id, "category": _finding_category(db, task)}
    key = plan or choose_plan(mapping)
    return task, key, decompose(mapping, plan=key)


def _check_graph(drafts: list[Any]) -> None:
    count = len(drafts)
    errors: list[str] = []
    for index, draft in enumerate(drafts):
        for dep in draft.depends_on:
            if dep == index:
                errors.append(f"Draft {index + 1} cannot depend on itself.")
            elif not 0 <= dep < count:
                errors.append(f"Draft {index + 1} depends on draft {dep + 1}, which does not exist.")
    if errors:
        raise ValidationFailedError(" ".join(errors), details={"errors": errors})
    # Kahn's algorithm: anything left over sits on a cycle.
    remaining = {i: set(d.depends_on) for i, d in enumerate(drafts)}
    while True:
        ready = [i for i, deps in remaining.items() if not deps]
        if not ready:
            break
        for i in ready:
            del remaining[i]
        for deps in remaining.values():
            deps.difference_update(ready)
    if remaining:
        cycle = ", ".join(str(i + 1) for i in sorted(remaining))
        message = f"Draft dependencies form a cycle (drafts {cycle}). Remove one of the dependencies between them."
        raise ValidationFailedError(message, details={"errors": [message], "reason": "dependency_cycle"})


def _description(draft: Any) -> str:
    text = (draft.description or "").strip()
    tests = [t.strip() for t in draft.testing_requirements if t and t.strip()]
    if tests:
        text += ("\n\n" if text else "") + "Testing requirements:\n" + "\n".join(f"- {t}" for t in tests)
    return text


def apply_breakdown(db: Session, actor: Actor, task_id: str, drafts: list[Any], *, priority: str | None = None,
                    override_wip: bool = False) -> AppliedBreakdown:
    parent = get_task(db, actor.org_id, task_id)
    if parent.archived_at is not None:
        raise ConflictError(f"{task_key(parent)} is archived. Restore it before adding subtasks.")
    _check_graph(drafts)
    created: list[Task] = []
    for draft in drafts:
        created.append(create_task(
            db, actor, title=draft.title, board_id=parent.board_id, task_type=draft.task_type,
            priority=priority or parent.priority, severity=parent.severity, parent_task_id=parent.id,
            related_agent_id=parent.related_agent_id, related_incident_id=parent.related_incident_id,
            related_files=list(parent.related_files or []), description=_description(draft),
            acceptance_criteria=[{"text": c, "done": False} for c in draft.acceptance_criteria if c and c.strip()],
            override_wip=override_wip,
        ))
    dependencies: list[tuple[str, str]] = []
    for index, draft in enumerate(drafts):
        for dep in dict.fromkeys(draft.depends_on):
            add_dependency(db, actor, created[index], created[dep].id, "blocks")
            dependencies.append((created[index].id, created[dep].id))
    details = {"subtask_ids": [t.id for t in created], "dependencies": len(dependencies)}
    record_activity(db, parent, actor.user_id, "breakdown_applied",
                    to_value=f"{len(created)} subtask{'s' if len(created) != 1 else ''}", details=details)
    db.flush()
    audit_task(db, actor, parent, "breakdown_applied", details)
    return AppliedBreakdown(parent=parent, created=created, dependencies=dependencies)

