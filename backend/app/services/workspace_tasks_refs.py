"""Task context references: links from a task to security records (findings, sessions, events...).

A reference stores only ``(ref_type, ref_id)``; the referenced record is never copied into the task.
Adding a reference validates that the record exists **in the task's organisation** (a record of another
organisation is reported exactly like a missing one: 404). Labels are resolved at read time, redacted
and shortened, and a reference whose record has since been deleted is returned with ``exists=False``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.models import (
    Agent,
    AgentSession,
    Approval,
    ContextItem,
    ContextSource,
    Destination,
    Incident,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    Task,
    TaskContextReference,
    Tool,
    ToolInvocation,
)
from app.services.scoping import get_scoped
from app.services.workspace_tasks_common import (
    Actor,
    audit_task,
    clean_optional,
    clean_text,
    get_task,
    record_activity,
)

LABEL_MAX = 300


def _finding(r: SecurityFinding) -> tuple[str, str]:
    return r.title, f"{r.severity} · {r.status} · {r.category.replace('_', ' ')}"


def _incident(r: Incident) -> tuple[str, str]:
    return f"INC-{r.number} {r.title}", f"{r.severity} · {r.status}"


def _event(r: IngestedEvent) -> tuple[str, str]:
    return f"{r.event_type} (event #{r.sequence})", r.processing_status + (" · simulation" if r.is_simulation else "")


def _session(r: AgentSession) -> tuple[str, str]:
    return f"Session {r.external_session_id}", f"{r.status} · risk {r.risk_score}"


def _agent(r: Agent) -> tuple[str, str]:
    return r.name, f"{r.framework} · {r.environment} · {r.status}"


def _decision(r: PolicyDecision) -> tuple[str, str]:
    return f"{r.decision} decision", f"{r.enforcement} · {r.explanation[:160]}" if r.explanation else r.enforcement


def _context_item(r: ContextItem) -> tuple[str, str]:
    return f"Context via {r.collected_via}", f"{r.trust_level} · {r.sensitivity}"


def _source(r: ContextSource) -> tuple[str, str]:
    return r.display_name or r.identifier, f"{r.source_type} · {r.trust_level}"


def _approval(r: Approval) -> tuple[str, str]:
    return (r.summary[:160] if r.summary else "Approval request"), r.status


def _destination(r: Destination) -> tuple[str, str]:
    return r.display_name or r.identifier, f"{r.kind} · {r.classification}"


def _invocation(r: ToolInvocation) -> tuple[str, str]:  # label completed in _invocation_labels (needs Tool)
    return "Tool call", f"{r.status} · {r.decision or 'no decision'} ({r.enforcement})"


REF_MODELS: dict[str, tuple[type[Any], str, Callable[[Any], tuple[str, str]]]] = {
    "finding": (SecurityFinding, "Finding", _finding),
    "incident": (Incident, "Incident", _incident),
    "event": (IngestedEvent, "Event", _event),
    "session": (AgentSession, "Session", _session),
    "agent": (Agent, "Agent", _agent),
    "tool_invocation": (ToolInvocation, "Tool invocation", _invocation),
    "policy_decision": (PolicyDecision, "Policy decision", _decision),
    "context_item": (ContextItem, "Context item", _context_item),
    "source": (ContextSource, "Source", _source),
    "approval": (Approval, "Approval", _approval),
    "destination": (Destination, "Destination", _destination),
}


def _tool_names(db: Session, org_id: str, invocations: list[ToolInvocation]) -> dict[str, str]:
    tool_ids = {i.tool_id for i in invocations}
    if not tool_ids:
        return {}
    return dict(db.execute(select(Tool.id, Tool.name).where(Tool.organization_id == org_id, Tool.id.in_(tool_ids))).all())


def _labels(db: Session, org_id: str, ref_type: str, rows: list[Any]) -> dict[str, tuple[str, str]]:
    _, _, describe = REF_MODELS[ref_type]
    out = {}
    names = _tool_names(db, org_id, rows) if ref_type == "tool_invocation" else {}
    for row in rows:
        label, detail = describe(row)
        if ref_type == "tool_invocation":
            label = f"{names.get(row.tool_id, 'Unknown tool')} call"
        out[row.id] = (clean_text(label, LABEL_MAX) or ref_type, clean_text(detail, LABEL_MAX))
    return out


def resolve_ref(db: Session, org_id: str, ref_type: str, ref_id: str) -> tuple[str, str]:
    """``(label, detail)`` for one record, or 404 when it does not exist in this organisation."""
    if ref_type not in REF_MODELS:
        raise NotFoundError(f"Unknown reference type '{ref_type}'")
    model, label, _ = REF_MODELS[ref_type]
    row = get_scoped(db, model, ref_id, org_id, label=label)
    return _labels(db, org_id, ref_type, [row])[row.id]


def resolve_refs(db: Session, org_id: str, refs: list[TaskContextReference]) -> list[dict[str, Any]]:
    """Reference rows with resolved labels (batched per type)."""
    by_type: dict[str, list[str]] = {}
    for ref in refs:
        by_type.setdefault(ref.ref_type, []).append(ref.ref_id)
    resolved: dict[tuple[str, str], tuple[str, str]] = {}
    for ref_type, ids in by_type.items():
        if ref_type not in REF_MODELS:
            continue
        model = REF_MODELS[ref_type][0]
        rows = list(db.scalars(select(model).where(model.organization_id == org_id, model.id.in_(ids))))
        for row_id, value in _labels(db, org_id, ref_type, rows).items():
            resolved[(ref_type, row_id)] = value
    out = []
    for ref in refs:
        found = resolved.get((ref.ref_type, ref.ref_id))
        out.append({
            "id": ref.id, "task_id": ref.task_id, "ref_type": ref.ref_type, "ref_id": ref.ref_id, "note": ref.note,
            "label": found[0] if found else f"{ref.ref_type.replace('_', ' ')} {ref.ref_id} (no longer available)",
            "detail": found[1] if found else None, "exists": found is not None, "created_at": ref.created_at,
        })
    return out


def task_refs(db: Session, task: Task) -> list[TaskContextReference]:
    return list(db.scalars(select(TaskContextReference).where(
        TaskContextReference.organization_id == task.organization_id, TaskContextReference.task_id == task.id
    ).order_by(TaskContextReference.created_at, TaskContextReference.id)))


def _existing(db: Session, task: Task, ref_type: str, ref_id: str) -> TaskContextReference | None:
    return db.scalar(select(TaskContextReference).where(
        TaskContextReference.organization_id == task.organization_id, TaskContextReference.task_id == task.id,
        TaskContextReference.ref_type == ref_type, TaskContextReference.ref_id == ref_id,
    ))


def _insert(db: Session, task: Task, ref_type: str, ref_id: str, note: str | None) -> TaskContextReference:
    ref = TaskContextReference(id=new_id("task_context_ref"), organization_id=task.organization_id, task_id=task.id,
                               ref_type=ref_type, ref_id=ref_id, note=clean_optional(note, 2000), created_at=utcnow())
    db.add(ref)
    db.flush()
    return ref


def ensure_ref(db: Session, task: Task, ref_type: str, ref_id: str | None, note: str | None = None) -> bool:
    """Attach a reference if the record exists in the org and is not yet linked (used by generators)."""
    if not ref_id or _existing(db, task, ref_type, ref_id) is not None:
        return False
    model = REF_MODELS[ref_type][0]
    if db.scalar(select(model.id).where(model.organization_id == task.organization_id, model.id == ref_id)) is None:
        return False
    _insert(db, task, ref_type, ref_id, note)
    return True


def add_ref(db: Session, actor: Actor, task: Task, ref_type: str, ref_id: str, note: str | None) -> TaskContextReference:
    label, _ = resolve_ref(db, task.organization_id, ref_type, ref_id)
    if _existing(db, task, ref_type, ref_id) is not None:
        raise ConflictError(f"This task already references {ref_type.replace('_', ' ')} '{ref_id}'.")
    ref = _insert(db, task, ref_type, ref_id, note)
    record_activity(db, task, actor.user_id, "reference_added", to_value=label,
                    details={"ref_type": ref_type, "ref_id": ref_id})
    audit_task(db, actor, task, "reference_added", {"ref_type": ref_type, "ref_id": ref_id})
    return ref


def remove_ref(db: Session, actor: Actor, ref_row_id: str) -> None:
    ref = get_scoped(db, TaskContextReference, ref_row_id, actor.org_id, label="Reference")
    task = get_task(db, actor.org_id, ref.task_id)
    db.delete(ref)
    record_activity(db, task, actor.user_id, "reference_removed",
                    details={"ref_type": ref.ref_type, "ref_id": ref.ref_id})
    db.flush()
    audit_task(db, actor, task, "reference_removed", {"ref_type": ref.ref_type, "ref_id": ref.ref_id})
