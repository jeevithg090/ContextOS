"""Assemble fix-context input for a task from org-scoped records.

``collect(db, task)`` gathers, for one task (plus the records linked to its parent task, one level):

- the task's own fields and acceptance criteria;
- findings referenced by the task (``TaskContextReference`` rows and ``related_finding_id``) with their
  redacted evidence;
- the linked incident and its most recent timeline entries;
- event summaries (types and titles only, never content) for the referenced sessions, bounded;
- agent metadata; provenance risky paths when the provenance service is available;
- policies involved, taken from the referenced decisions' ``matched_policies``;
- previous fix attempts and verification runs.

Every query filters on the task's organisation. Text is redacted again here (defence in depth) even
though the stored rows are already redacted. ``to_input`` turns the bundle plus context-pack items into
:class:`~app.workspace.fix_context.FixContextInput`; ``pack_records`` turns it into context-pack records.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutil import isoformat
from app.engines.redaction import redact_value
from app.models import (
    Agent,
    BoardColumn,
    Incident,
    IncidentActivity,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    Task,
    TaskLabel,
    TaskLabelLink,
)
from app.services.workspace_tasks_common import task_key
from app.services.workspace_tasks_evidence import fix_attempt_rows, verification_rows
from app.services.workspace_tasks_refs import task_refs
from app.workspace.fix_context import FixContextInput
from app.workspace.text import clean, inline

log = get_logger(__name__)

MAX_FINDINGS = 50
MAX_SESSIONS = 5
MAX_EVENTS = 60
MAX_TIMELINE = 10
MAX_DECISIONS = 30
MAX_PATHS = 30
PROVENANCE_MODULE = "app.services.provenance_service"
# Functions the provenance service may expose: (db, org_id, session_id) -> list[RiskyPath | dict].
PROVENANCE_FUNCTIONS = ("risky_paths_for_session", "session_risky_paths")
PROVENANCE_UNAVAILABLE = ("Provenance risky-path analysis is not available on this server, so no provenance paths "
                          "are included.")


@dataclass
class TaskBundle:
    """Org-scoped, redacted records linked to one task."""

    task: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    incident: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    agent: dict[str, Any] | None = None
    provenance_paths: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    previous_attempts: list[dict[str, Any]] = field(default_factory=list)
    verification_runs: list[dict[str, Any]] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _redacted(value: Any) -> Any:
    out, _ = redact_value(value)
    return out


def _ids(values: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(v for v in values if isinstance(v, str) and v))


def _rows(db: Session, model: Any, org_id: str, ids: list[str]) -> list[Any]:
    if not ids:
        return []
    return list(db.scalars(select(model).where(model.organization_id == org_id, model.id.in_(ids))))


# ----------------------------------------------------------------------------- task


def task_fields(db: Session, task: Task) -> dict[str, Any]:
    column = db.get(BoardColumn, task.column_id)
    labels = list(db.scalars(
        select(TaskLabel.name).join(TaskLabelLink, TaskLabelLink.label_id == TaskLabel.id).where(
            TaskLabelLink.organization_id == task.organization_id, TaskLabelLink.task_id == task.id)
    ))
    return _redacted({
        "id": task.id, "key": task_key(task), "number": task.number, "title": task.title,
        "description": task.description, "task_type": task.task_type, "priority": task.priority,
        "severity": task.severity, "status": column.status_key if column else None,
        "reproduction_steps": task.reproduction_steps, "expected_behaviour": task.expected_behaviour,
        "actual_behaviour": task.actual_behaviour, "acceptance_criteria": list(task.acceptance_criteria or []),
        "related_files": [p for p in task.related_files or [] if isinstance(p, str)], "labels": labels,
        "related_finding_id": task.related_finding_id,
    })


def _linked_ids(db: Session, task: Task) -> tuple[dict[str, list[str]], Task | None]:
    """Referenced record ids by type, for the task and (one level up) its parent task."""
    chain = [task]
    parent = None
    if task.parent_task_id:
        parent = db.scalar(select(Task).where(Task.organization_id == task.organization_id,
                                              Task.id == task.parent_task_id))
        if parent is not None:
            chain.append(parent)
    out: dict[str, list[str]] = {}
    for item in chain:
        for ref in task_refs(db, item):
            out.setdefault(ref.ref_type, []).append(ref.ref_id)
        for ref_type, value in (("finding", item.related_finding_id), ("incident", item.related_incident_id),
                                ("agent", item.related_agent_id)):
            if value:
                out.setdefault(ref_type, []).append(value)
    return {k: _ids(v) for k, v in out.items()}, parent


# ----------------------------------------------------------------------------- records


def _finding(row: SecurityFinding) -> dict[str, Any]:
    evidence = []
    for ev in (row.evidence or [])[:20]:
        if isinstance(ev, dict):
            evidence.append({k: ev.get(k) for k in ("type", "id", "excerpt", "detail") if ev.get(k) is not None})
    return _redacted({
        "id": row.id, "title": row.title, "category": row.category, "severity": row.severity,
        "status": row.status, "confidence": row.confidence, "explanation": row.explanation,
        "evidence": evidence, "remediation": row.remediation, "rule_id": row.rule_id,
        "session_id": row.session_id, "agent_id": row.agent_id, "policy_decision_id": row.policy_decision_id,
        "is_simulation": row.is_simulation,
    })


def _incident(db: Session, row: Incident) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    incident = _redacted({"id": row.id, "number": row.number, "title": f"INC-{row.number}: {row.title}",
                          "summary": row.summary, "severity": row.severity, "status": row.status})
    activities = list(db.scalars(select(IncidentActivity).where(
        IncidentActivity.organization_id == row.organization_id, IncidentActivity.incident_id == row.id,
    ).order_by(IncidentActivity.created_at.desc(), IncidentActivity.id.desc()).limit(MAX_TIMELINE)))
    timeline = [{"id": a.id, "type": f"incident.{a.kind}", "at": isoformat(a.created_at),
                 "summary": inline(a.body, 240) or a.kind.replace("_", " ")} for a in reversed(activities)]
    return incident, timeline


def _event_summary(event: IngestedEvent, decisions: dict[str, PolicyDecision]) -> str:
    payload = event.payload_redacted if isinstance(event.payload_redacted, dict) else {}
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else None
    source = payload.get("source") if isinstance(payload.get("source"), dict) else None
    bits: list[str] = []
    if tool and tool.get("name"):
        bits.append(f"tool {inline(tool['name'], 100)}")
    elif source and source.get("type"):
        bits.append(f"{inline(source['type'], 40)} source")
    refs = event.refs if isinstance(event.refs, dict) else {}
    decision = decisions.get(str(refs.get("policy_decision_id") or ""))
    if decision is not None:
        bits.append(f"decision {decision.decision} ({decision.enforcement})")
    findings = refs.get("finding_ids") or []
    if isinstance(findings, list) and findings:
        bits.append(f"raised {len(findings)} finding{'s' if len(findings) != 1 else ''}")
    if event.processing_status == "error":
        bits.append("processing error")
    text = " · ".join(bits)
    return f"[simulation] {text}".strip() if event.is_simulation else text


def _events(db: Session, org_id: str, session_ids: list[str], event_ids: list[str]) -> list[IngestedEvent]:
    rows: dict[str, IngestedEvent] = {}
    if session_ids:
        latest = list(db.scalars(select(IngestedEvent).where(
            IngestedEvent.organization_id == org_id, IngestedEvent.session_id.in_(session_ids),
        ).order_by(IngestedEvent.sequence.desc()).limit(MAX_EVENTS)))
        rows.update({e.id: e for e in latest})
    for event in _rows(db, IngestedEvent, org_id, event_ids[:MAX_EVENTS]):
        rows.setdefault(event.id, event)
    return sorted(rows.values(), key=lambda e: e.sequence)[-MAX_EVENTS:]


def _decisions(db: Session, org_id: str, ids: list[str]) -> dict[str, PolicyDecision]:
    return {d.id: d for d in _rows(db, PolicyDecision, org_id, ids[:200])}


def _policies(decisions: list[PolicyDecision]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for decision in decisions:
        for match in decision.matched_policies or []:
            if not isinstance(match, dict):
                continue
            key = str(match.get("policy_id") or match.get("name") or "")
            if not key or key in out:
                continue
            mode = f", {match['mode']} mode" if match.get("mode") else ""
            explanation = (f"{clean(match.get('explanation'), 400)} (matched decision {decision.id}: returned "
                           f"{decision.decision}, enforcement {decision.enforcement}{mode})")
            out[key] = {"id": match.get("policy_id"), "name": match.get("name"),
                        "outcome": match.get("outcome") or decision.decision, "explanation": explanation}
    return _redacted(list(out.values()))


def _agent(row: Agent) -> dict[str, Any]:
    return _redacted({"id": row.id, "name": row.name, "framework": row.framework, "environment": row.environment,
                      "owner": row.owner, "status": row.status, "description": row.description,
                      "risk_score": row.risk_score})


def _path_dict(path: Any) -> dict[str, Any] | None:
    data = path.to_dict() if hasattr(path, "to_dict") else path
    if not isinstance(data, dict):
        return None
    return _redacted({"title": data.get("title"), "explanation": data.get("explanation"),
                      "severity": data.get("severity")})


def provenance_paths(db: Session, org_id: str, session_ids: list[str]) -> tuple[list[dict[str, Any]], str | None]:
    """Risky paths for the sessions via the provenance service, imported lazily. ``(paths, note)``."""
    if not session_ids:
        return [], None
    try:
        module = importlib.import_module(PROVENANCE_MODULE)
    except ModuleNotFoundError:
        return [], PROVENANCE_UNAVAILABLE
    except Exception:  # noqa: BLE001 — a broken optional module must not break prompt generation
        log.exception("provenance_service_import_failed")
        return [], PROVENANCE_UNAVAILABLE
    fn = next((getattr(module, name) for name in PROVENANCE_FUNCTIONS if callable(getattr(module, name, None))), None)
    if fn is None:
        return [], PROVENANCE_UNAVAILABLE
    paths: list[dict[str, Any]] = []
    for session_id in session_ids:
        try:
            found = fn(db, org_id, session_id) or []
        except Exception:  # noqa: BLE001 — degrade to a visible note instead of failing prompt generation
            log.exception("provenance_paths_failed", extra={"session_id": session_id})
            return paths, "Provenance risky-path analysis failed for a linked session; paths may be incomplete."
        paths.extend(p for p in (_path_dict(x) for x in found) if p)
        if len(paths) >= MAX_PATHS:
            break
    return paths[:MAX_PATHS], None


def _attempts(db: Session, task: Task) -> list[dict[str, Any]]:
    return _redacted([{"id": a.id, "status": a.status, "agent_tool": a.agent_tool, "notes": a.notes,
                       "branch": a.branch, "pr_url": a.pr_url} for a in fix_attempt_rows(db, task)])


def _runs(db: Session, task: Task) -> list[dict[str, Any]]:
    return _redacted([{"id": r.id, "kind": r.kind, "status": r.status, "summary": r.summary, "command": r.command}
                      for r in verification_rows(db, task)])


# ----------------------------------------------------------------------------- public


def collect(db: Session, task: Task, *, with_provenance: bool = True) -> TaskBundle:
    org_id = task.organization_id
    linked, parent = _linked_ids(db, task)
    bundle = TaskBundle(task=task_fields(db, task))
    if parent is not None:
        bundle.notes.append(f"Includes records linked to the parent task {task_key(parent)}.")

    finding_rows = _rows(db, SecurityFinding, org_id, linked.get("finding", [])[:MAX_FINDINGS])
    order = {fid: i for i, fid in enumerate(linked.get("finding", []))}
    finding_rows.sort(key=lambda f: order.get(f.id, 0))
    bundle.findings = [_finding(f) for f in finding_rows]

    incident_ids = _ids([*linked.get("incident", []), *(f.incident_id for f in finding_rows)])
    incident_row = next(iter(_rows(db, Incident, org_id, incident_ids[:1])), None)
    timeline: list[dict[str, Any]] = []
    if incident_row is not None:
        bundle.incident, timeline = _incident(db, incident_row)

    bundle.session_ids = _ids([*linked.get("session", []), *(f.session_id for f in finding_rows),
                               incident_row.primary_session_id if incident_row else None])[:MAX_SESSIONS]
    decision_ids = _ids([*linked.get("policy_decision", []), *(f.policy_decision_id for f in finding_rows)])
    events = _events(db, org_id, bundle.session_ids, linked.get("event", []))
    event_decision_ids = _ids(str((e.refs or {}).get("policy_decision_id") or "") for e in events)
    decisions = _decisions(db, org_id, _ids([*decision_ids, *event_decision_ids]))
    bundle.events = _redacted([{"id": e.id, "type": e.event_type, "at": isoformat(e.received_at),
                                "summary": _event_summary(e, decisions)} for e in events]) + timeline
    bundle.policies = _policies([decisions[d] for d in decision_ids[:MAX_DECISIONS] if d in decisions])

    agent_ids = _ids([*linked.get("agent", []), *(f.agent_id for f in finding_rows),
                      incident_row.primary_agent_id if incident_row else None])
    agent_row = next(iter(_rows(db, Agent, org_id, agent_ids[:1])), None)
    bundle.agent = _agent(agent_row) if agent_row is not None else None

    if with_provenance:
        bundle.provenance_paths, note = provenance_paths(db, org_id, bundle.session_ids)
        if note:
            bundle.notes.append(note)
    bundle.previous_attempts = _attempts(db, task)
    bundle.verification_runs = _runs(db, task)
    return bundle


def to_input(bundle: TaskBundle, pack_items: list[dict[str, Any]]) -> FixContextInput:
    return FixContextInput(
        task=bundle.task, findings=bundle.findings, incident=bundle.incident, events=bundle.events,
        agent=bundle.agent, provenance_paths=bundle.provenance_paths, policies=bundle.policies,
        previous_attempts=bundle.previous_attempts, verification_runs=bundle.verification_runs,
        context_pack_items=[i for i in pack_items if isinstance(i, dict)],
    )


def pack_records(bundle: TaskBundle) -> list[dict[str, Any]]:
    """Context-pack records (persisted ContextOS data) for the task's linked records."""
    records: list[dict[str, Any]] = []
    for f in bundle.findings:
        body = [f"Severity {f.get('severity')}, category {str(f.get('category') or '').replace('_', ' ')}, "
                f"status {f.get('status')}.", str(f.get("explanation") or "")]
        if f.get("remediation"):
            body.append(f"Suggested remediation: {f['remediation']}")
        records.append({"ref": f"finding:{f['id']}", "kind": "record", "category": "evidence",
                        "title": f"Finding — {f.get('title')}", "summary": "\n\n".join(body),
                        "reason": "Finding linked to this task."})
    if bundle.incident:
        inc = bundle.incident
        records.append({"ref": f"incident:{inc['id']}", "kind": "record", "category": "evidence",
                        "title": f"Incident — {inc.get('title')}",
                        "summary": f"Status {inc.get('status')}, severity {inc.get('severity')}.\n\n"
                                   f"{inc.get('summary') or ''}",
                        "reason": "Incident linked to this task."})
    for p in bundle.policies:
        if p.get("id"):
            records.append({"ref": f"policy:{p['id']}", "kind": "policy", "category": "fact",
                            "title": f"Policy — {p.get('name') or p['id']}",
                            "summary": f"Outcome {p.get('outcome')}. {p.get('explanation') or ''}",
                            "reason": "Policy matched by a decision linked to this task."})
    if bundle.agent:
        ag = bundle.agent
        records.append({"ref": f"agent:{ag['id']}", "kind": "record", "category": "fact",
                        "title": f"Agent — {ag.get('name')}",
                        "summary": f"Framework {ag.get('framework')}, environment {ag.get('environment')}, "
                                   f"status {ag.get('status')}, owner {ag.get('owner') or 'not set'}."
                                   + (f"\n\n{ag['description']}" if ag.get("description") else ""),
                        "reason": "Agent linked to this task."})
    return records
