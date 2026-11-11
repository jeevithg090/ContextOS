"""The remediation link: turn security findings (and incidents) into Engineering Workspace tasks.

``create_task_from_finding`` is idempotent: while an open (not archived, not done) task already tracks
the finding, that task is returned with ``created=False``. A new task:

- is titled "Remediate: <finding title>" and lands in the first column of the Security Remediation
  board unless another board is given;
- maps the finding category to a task type and the severity to a priority, and copies the severity;
- links the evidence by **reference** (finding, session, agent, source, context item, tool invocation,
  policy decision, destination, incident) — records are never copied into the task;
- drafts reproduction steps from the recorded event sequence (event types and tool/source types only,
  never content) and default acceptance criteria that require independent verification.

All text derived from records is redacted again before it is stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError
from app.models import (
    AgentSession,
    BoardColumn,
    ContextItem,
    Incident,
    IngestedEvent,
    SecurityFinding,
    SimulationRun,
    Task,
)
from app.models import TaskContextReference as Ref
from app.services.incidents import add_activity
from app.services.notify import notify
from app.services.org_counters import lock_org
from app.services.scoping import get_scoped
from app.services.workspace_boards import get_active_board, remediation_board
from app.services.workspace_tasks import create_task
from app.services.workspace_tasks_common import (
    Actor,
    as_actor,
    audit_task,
    clean_text,
    record_activity,
    task_key,
)
from app.services.workspace_tasks_refs import ensure_ref

OPEN_FINDING_STATUSES = ("open", "acknowledged")
MAX_REPRO_EVENTS = 15
PRIORITY_BY_SEVERITY = {"critical": "urgent", "high": "high", "medium": "medium", "low": "low", "info": "none"}
TYPE_BY_CATEGORY = {
    "prompt_injection": "prompt_injection",
    "secret_exposure": "data_exposure",
    "exfiltration": "data_exposure",
    "dangerous_permissions": "agent_misconfiguration",
    "permission_escalation": "agent_misconfiguration",
}
EXPECTED_BY_TYPE = {
    "prompt_injection": "Instructions embedded in untrusted content are treated as data and do not change what "
                        "the agent does or which tools it calls.",
    "data_exposure": "Credentials and sensitive data never leave the environment through agent tool calls; "
                     "attempts are denied or require approval at the enforcement boundary.",
    "agent_misconfiguration": "The agent runs with only the permissions its task needs; dangerous capabilities "
                              "are removed or gated by policy.",
    "security_vulnerability": "The behaviour that raised this finding no longer occurs, and policy blocks or "
                              "flags any recurrence.",
}


@dataclass
class FromFindingResult:
    task: Task
    created: bool


def task_type_for(category: str) -> str:
    return TYPE_BY_CATEGORY.get(category, "security_vulnerability")


def open_task_for_finding(db: Session, org_id: str, finding_id: str) -> Task | None:
    """An open task (not archived, not in a done column) tracking this finding, oldest first."""
    referenced = select(Ref.task_id).where(Ref.organization_id == org_id, Ref.ref_type == "finding",
                                           Ref.ref_id == finding_id)
    return db.scalars(
        select(Task).join(BoardColumn, BoardColumn.id == Task.column_id).where(
            Task.organization_id == org_id, Task.archived_at.is_(None), BoardColumn.is_done_column.is_(False),
            (Task.related_finding_id == finding_id) | Task.id.in_(referenced),
        ).order_by(Task.created_at)
    ).first()


def _description(finding: SecurityFinding) -> str:
    parts = [
        f"ContextOS raised a {finding.severity} {finding.category.replace('_', ' ')} finding "
        f"(rule {finding.rule_id}, confidence {round(finding.confidence * 100)}%, seen {finding.occurrence_count}×).",
        "",
        "Why it was raised:",
        clean_text(finding.explanation, 2000),
    ]
    if finding.remediation:
        parts += ["", "Suggested remediation:", clean_text(finding.remediation, 2000)]
    parts += ["", "Evidence is linked from this task as references to the recorded finding, session and "
                  "events; it is not copied here."]
    if finding.is_simulation:
        parts += ["", "This finding came from a Simulation Lab run, not from production traffic."]
    return "\n".join(parts)


def _event_title(event: IngestedEvent) -> str:
    payload = event.payload_redacted or {}
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else None
    source = payload.get("source") if isinstance(payload.get("source"), dict) else None
    if tool and tool.get("name"):
        return f"{event.event_type} — tool {clean_text(tool['name'], 100)}"
    if source and source.get("type"):
        return f"{event.event_type} — {clean_text(source['type'], 40)} source"
    return event.event_type


def _triggered(event: IngestedEvent, finding: SecurityFinding) -> bool:
    refs = event.refs or {}
    return finding.id in (refs.get("finding_ids") or []) or (
        bool(finding.context_item_id) and refs.get("context_item_id") == finding.context_item_id
    ) or (bool(finding.tool_invocation_id) and refs.get("tool_invocation_id") == finding.tool_invocation_id)


def _reproduction_steps(db: Session, finding: SecurityFinding) -> str:
    if not finding.session_id:
        return ("No recorded event sequence is linked to this finding. Reproduce it from the evidence on the "
                "finding page.")
    events = list(db.scalars(select(IngestedEvent).where(
        IngestedEvent.organization_id == finding.organization_id, IngestedEvent.session_id == finding.session_id,
    ).order_by(IngestedEvent.sequence)))
    trigger_index = next((i for i, e in enumerate(events) if _triggered(e, finding)), len(events) - 1)
    window = events[max(0, trigger_index - MAX_REPRO_EVENTS + 1): trigger_index + 1]
    if not window:
        return "The finding's session has no recorded events. Reproduce it from the evidence on the finding page."
    lines = ["Recorded event sequence in the affected session (types only; open the session replay for detail):"]
    for number, event in enumerate(window, start=1):
        marker = "  ← finding raised here" if _triggered(event, finding) else ""
        lines.append(f"{number}. {_event_title(event)}{marker}")
    lines += ["", "Replay this sequence (Session replay, or a Simulation Lab scenario of the same attack) against "
                  "the fixed configuration and confirm the finding is not raised again."]
    return "\n".join(lines)


def _scenario(db: Session, finding: SecurityFinding) -> SimulationRun | None:
    if not finding.session_id:
        return None
    session = db.get(AgentSession, finding.session_id)
    if session is None or session.organization_id != finding.organization_id or not session.simulation_run_id:
        return None
    return db.scalar(select(SimulationRun).where(SimulationRun.organization_id == finding.organization_id,
                                                 SimulationRun.id == session.simulation_run_id))


def _acceptance(db: Session, finding: SecurityFinding, task_type: str) -> list[dict[str, Any]]:
    scenario = _scenario(db, finding)
    sim = (f"Simulation scenario '{clean_text(scenario.scenario_name, 200)}' ({scenario.scenario_id}) passes against "
           "the fixed configuration" if scenario else
           f"A Simulation Lab scenario covering this {finding.category.replace('_', ' ')} attack passes against the "
           "fixed configuration")
    items = [
        "Regression test reproduces the original attack and passes",
        sim,
        "Replaying the recorded session no longer raises this finding",
    ]
    if task_type == "data_exposure":
        items.append("Any credential that was exposed is rotated and the old value revoked")
    items.append("Passed verification evidence is recorded on this task before it moves to Verified")
    return [{"text": text, "done": False} for text in items]


def _attach_refs(db: Session, task: Task, finding: SecurityFinding) -> int:
    pairs = [("finding", finding.id), ("session", finding.session_id), ("agent", finding.agent_id),
             ("source", finding.source_id), ("context_item", finding.context_item_id),
             ("tool_invocation", finding.tool_invocation_id), ("policy_decision", finding.policy_decision_id),
             ("destination", finding.destination_id), ("incident", finding.incident_id)]
    count = sum(1 for ref_type, ref_id in pairs if ensure_ref(db, task, ref_type, ref_id))
    if finding.context_item_id and not finding.tool_invocation_id:
        item = db.get(ContextItem, finding.context_item_id)
        if item is not None and item.organization_id == finding.organization_id and item.tool_invocation_id:
            count += ensure_ref(db, task, "tool_invocation", item.tool_invocation_id,
                                note="The tool call that returned the flagged content (observed, not causal).")
    return count


def create_task_from_finding(
    db: Session, principal: Any, finding_id: str, board_id: str | None = None, *, parent_task_id: str | None = None
) -> FromFindingResult:
    actor = as_actor(principal)
    finding = get_scoped(db, SecurityFinding, finding_id, actor.org_id, label="Finding")
    # Two requests for the same finding (a double click, two analysts) check one after the other.
    lock_org(db, actor.org_id)
    existing = open_task_for_finding(db, actor.org_id, finding.id)
    if existing is not None:
        return FromFindingResult(task=existing, created=False)
    board = get_active_board(db, actor.org_id, board_id) if board_id else remediation_board(db, actor.org_id,
                                                                                             actor.user_id)
    task_type = task_type_for(finding.category)
    task = create_task(
        db, actor, title=f"Remediate: {finding.title}", board_id=board.id, task_type=task_type,
        priority=PRIORITY_BY_SEVERITY.get(finding.severity, "medium"), severity=finding.severity,
        description=_description(finding), related_finding_id=finding.id, related_agent_id=finding.agent_id,
        related_incident_id=finding.incident_id, parent_task_id=parent_task_id,
        reproduction_steps=_reproduction_steps(db, finding),
        expected_behaviour=EXPECTED_BY_TYPE.get(task_type, EXPECTED_BY_TYPE["security_vulnerability"]),
        actual_behaviour=clean_text(finding.explanation, 2000),
        acceptance_criteria=_acceptance(db, finding, task_type),
    )
    refs = _attach_refs(db, task, finding)
    record_activity(db, task, actor.user_id, "created_from_finding", to_value=finding.title,
                    details={"finding_id": finding.id, "references": refs})
    if finding.incident_id:
        add_activity(db, actor.org_id, finding.incident_id, actor=actor.user_id or "system", kind="task_linked",
                     body=f"{task_key(task)} created to remediate: {clean_text(finding.title, 300)}",
                     details={"task_id": task.id, "finding_id": finding.id})
        notify(db, actor.org_id, "incident.updated", id=finding.incident_id)
    db.flush()
    audit_task(db, actor, task, "created_from_finding", {"finding_id": finding.id, "references": refs})
    return FromFindingResult(task=task, created=True)


@dataclass
class FromIncidentResult:
    incident_id: str
    mode: str
    parent: Task | None
    items: list[tuple[str | None, bool, Task]]

    @property
    def created_count(self) -> int:
        return sum(1 for _, created, _ in self.items if created)

    @property
    def existing_count(self) -> int:
        return sum(1 for _, created, _ in self.items if not created)


def _parent_for_incident(db: Session, actor: Actor, incident: Incident, board_id: str) -> tuple[Task, bool]:
    existing = db.scalars(
        select(Task).join(BoardColumn, BoardColumn.id == Task.column_id).where(
            Task.organization_id == actor.org_id, Task.related_incident_id == incident.id,
            Task.related_finding_id.is_(None), Task.parent_task_id.is_(None), Task.archived_at.is_(None),
            BoardColumn.is_done_column.is_(False),
        ).order_by(Task.created_at)
    ).first()
    if existing is not None:
        return existing, False
    task = create_task(
        db, actor, title=f"Remediate incident INC-{incident.number}: {incident.title}", board_id=board_id,
        task_type="security_vulnerability", priority=PRIORITY_BY_SEVERITY.get(incident.severity, "medium"),
        severity=incident.severity, related_incident_id=incident.id, related_agent_id=incident.primary_agent_id,
        description=("Parent task for the remediation of this incident. Each open finding has its own subtask.\n\n"
                     + clean_text(incident.summary, 2000)),
        acceptance_criteria=[{"text": "Every remediation subtask is verified and done", "done": False},
                             {"text": "The incident's post-incident actions are recorded", "done": False}],
    )
    ensure_ref(db, task, "incident", incident.id)
    ensure_ref(db, task, "session", incident.primary_session_id)
    ensure_ref(db, task, "agent", incident.primary_agent_id)
    return task, True


def create_tasks_from_incident(
    db: Session, principal: Any, incident_id: str, board_id: str | None = None, mode: str = "per_finding"
) -> FromIncidentResult:
    """One remediation task per open finding of the incident, or a parent task with one subtask each."""
    actor = as_actor(principal)
    incident = get_scoped(db, Incident, incident_id, actor.org_id, label="Incident")
    findings = list(db.scalars(select(SecurityFinding).where(
        SecurityFinding.organization_id == actor.org_id, SecurityFinding.incident_id == incident.id,
        SecurityFinding.status.in_(OPEN_FINDING_STATUSES),
    ).order_by(SecurityFinding.first_seen_at, SecurityFinding.id)))
    if not findings:
        raise ConflictError(f"Incident INC-{incident.number} has no open findings to create remediation tasks from.")
    board = get_active_board(db, actor.org_id, board_id) if board_id else remediation_board(db, actor.org_id,
                                                                                             actor.user_id)
    parent: Task | None = None
    items: list[tuple[str | None, bool, Task]] = []
    if mode == "parent_with_subtasks":
        parent, created = _parent_for_incident(db, actor, incident, board.id)
        items.append((None, created, parent))
    for finding in findings:
        result = create_task_from_finding(db, actor, finding.id, board.id,
                                          parent_task_id=parent.id if parent else None)
        if parent is not None and not result.created and result.task.parent_task_id is None \
                and result.task.id != parent.id:
            result.task.parent_task_id = parent.id
            record_activity(db, result.task, actor.user_id, "updated", to_value=task_key(parent),
                            details={"field": "parent_task_id", "reason": "grouped under incident task"})
            audit_task(db, actor, result.task, "updated", {"fields": ["parent_task_id"]})
        items.append((finding.id, result.created, result.task))
    db.flush()
    return FromIncidentResult(incident_id=incident.id, mode=mode, parent=parent, items=items)
