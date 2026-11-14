"""Incident read models: the list, the investigator's detail view and the records an incident involves.

"Involved" agents, sessions, sources and destinations are derived from the incident's findings (and
its primary agent/session): they are the records ContextOS observed alongside the detections, not a
claim that each one caused the incident. Every query filters on the caller's organisation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, FindingStatus
from app.engines.redaction import redact_text
from app.models import (
    Agent,
    AgentSession,
    BoardColumn,
    ContextItem,
    ContextSource,
    Destination,
    Incident,
    IncidentActivity,
    Membership,
    SecurityFinding,
    Task,
    TaskContextReference,
    ToolInvocation,
    User,
)
from app.services.incidents import allowed_transitions, incident_key
from app.services.scoping import get_scoped, scoped
from app.services.sessions_service import risk_flags

OPEN_FINDINGS = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value)
INVOLVED_NOTE = (
    "Involved records are the agents, sessions, sources and destinations attached to this incident's findings. "
    "They were observed together with the detections; being listed here does not mean a record caused the incident."
)


def clip(text: str | None, limit: int | None = None) -> str | None:
    """Re-redact stored free text before it leaves the server (defence in depth) and truncate it."""
    if text is None:
        return None
    out = redact_text(text).text
    return out if limit is None or len(out) <= limit else out[: limit - 1] + "…"


def severity_order() -> Any:
    return case({s: r for s, r in SEVERITY_RANK.items()}, value=Incident.severity, else_=0)


# Work that still needs attention first: open/investigating, then contained, then closed.
_STATUS_RANK = {"open": 0, "investigating": 0, "contained": 1, "resolved": 2, "false_positive": 2}


def _status_order() -> Any:
    return case(_STATUS_RANK, value=Incident.status, else_=3)


# ----------------------------------------------------------------------------- people


def user_names(db: Session, org_id: str, ids: set[str]) -> dict[str, str]:
    """Names of users who are (or were, while still members) part of this organisation."""
    ids = {i for i in ids if i and i != "system"}
    if not ids:
        return {}
    rows = db.execute(
        select(User.id, User.name)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.organization_id == org_id, User.id.in_(ids))
    )
    return {uid: name for uid, name in rows}


def actor_ref(actor: str | None, names: dict[str, str]) -> dict[str, Any]:
    if not actor or actor == "system":
        return {"type": "system", "id": None, "name": "ContextOS"}
    return {"type": "user", "id": actor, "name": names.get(actor, "Former member")}


def user_ref(user_id: str | None, names: dict[str, str]) -> dict[str, Any] | None:
    if not user_id:
        return None
    return {"id": user_id, "name": names.get(user_id, "Former member")}


# ----------------------------------------------------------------------------- list


@dataclass(frozen=True)
class IncidentFilters:
    statuses: list[str] | None = None
    severities: list[str] | None = None
    include_simulated: bool = False
    q: str | None = None
    assignee_user_id: str | None = None
    unassigned: bool = False
    agent_id: str | None = None


def _conditions(org_id: str, f: IncidentFilters) -> list[Any]:
    conds: list[Any] = [Incident.organization_id == org_id]
    if f.statuses:
        conds.append(Incident.status.in_(f.statuses))
    if f.severities:
        conds.append(Incident.severity.in_(f.severities))
    if not f.include_simulated:
        conds.append(Incident.is_simulation.is_(False))
    if f.assignee_user_id:
        conds.append(Incident.assignee_user_id == f.assignee_user_id)
    elif f.unassigned:
        conds.append(Incident.assignee_user_id.is_(None))
    if f.agent_id:
        linked = select(SecurityFinding.incident_id).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.agent_id == f.agent_id
        )
        conds.append(or_(Incident.primary_agent_id == f.agent_id, Incident.id.in_(linked)))
    if f.q and f.q.strip():
        q = f.q.strip()
        number = q.upper().removeprefix("INC-")
        options = [Incident.title.icontains(q, autoescape=True), Incident.id == q]
        if number.isdigit():
            options.append(Incident.number == int(number))
        conds.append(or_(*options))
    return conds


def list_incidents(
    db: Session, org_id: str, f: IncidentFilters, *, sort: str, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    """Incidents for the list view. ``priority`` puts active, severe incidents first."""
    query: Select[Any] = select(Incident).where(*_conditions(org_id, f))
    if sort == "recent":
        query = query.order_by(Incident.opened_at.desc(), Incident.id.desc())
    elif sort == "updated":
        query = query.order_by(Incident.updated_at.desc(), Incident.id.desc())
    else:
        query = query.order_by(
            _status_order(), severity_order().desc(), Incident.opened_at.desc(), Incident.id.desc()
        )
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    incidents = list(db.scalars(query.limit(limit).offset(offset)))
    return summaries(db, org_id, incidents), int(total)


def _finding_counts(db: Session, org_id: str, ids: list[str]) -> dict[str, dict[str, Any]]:
    if not ids:
        return {}
    open_case = func.sum(case((SecurityFinding.status.in_(OPEN_FINDINGS), 1), else_=0))
    rows = db.execute(
        select(SecurityFinding.incident_id, SecurityFinding.severity, func.count(), open_case)
        .where(
            SecurityFinding.organization_id == org_id,
            SecurityFinding.incident_id.in_(ids),
        )
        .group_by(SecurityFinding.incident_id, SecurityFinding.severity)
    )
    out: dict[str, dict[str, Any]] = {}
    for incident_id, severity, count, open_count in rows:
        entry = out.setdefault(
            incident_id, {"finding_count": 0, "open_finding_count": 0, "max_finding_severity": None}
        )
        entry["finding_count"] += int(count)
        entry["open_finding_count"] += int(open_count or 0)
        current = entry["max_finding_severity"]
        if current is None or SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(current, 0):
            entry["max_finding_severity"] = severity
    return out


def _agents(db: Session, org_id: str, ids: set[str]) -> dict[str, Agent]:
    ids = {i for i in ids if i}
    return {a.id: a for a in db.scalars(scoped(Agent, org_id).where(Agent.id.in_(ids)))} if ids else {}


def _sessions(db: Session, org_id: str, ids: set[str]) -> dict[str, AgentSession]:
    ids = {i for i in ids if i}
    return (
        {s.id: s for s in db.scalars(scoped(AgentSession, org_id).where(AgentSession.id.in_(ids)))}
        if ids
        else {}
    )


def summaries(db: Session, org_id: str, incidents: list[Incident]) -> list[dict[str, Any]]:
    counts = _finding_counts(db, org_id, [i.id for i in incidents])
    agents = _agents(db, org_id, {i.primary_agent_id for i in incidents if i.primary_agent_id})
    sessions = _sessions(db, org_id, {i.primary_session_id for i in incidents if i.primary_session_id})
    names = user_names(
        db,
        org_id,
        {i.assignee_user_id for i in incidents if i.assignee_user_id} | {i.created_by for i in incidents},
    )
    return [summary(i, counts.get(i.id), agents, sessions, names) for i in incidents]


def summary(
    incident: Incident,
    counts: dict[str, Any] | None,
    agents: dict[str, Agent],
    sessions: dict[str, AgentSession],
    names: dict[str, str],
) -> dict[str, Any]:
    counts = counts or {"finding_count": 0, "open_finding_count": 0, "max_finding_severity": None}
    agent = agents.get(incident.primary_agent_id or "")
    session = sessions.get(incident.primary_session_id or "")
    return {
        "id": incident.id,
        "number": incident.number,
        "key": incident_key(incident),
        "title": clip(incident.title, 400) or "",
        "severity": incident.severity,
        "status": incident.status,
        "assignee": user_ref(incident.assignee_user_id, names),
        "primary_agent": {"id": agent.id, "name": agent.name} if agent else None,
        "primary_session": {"id": session.id, "external_session_id": session.external_session_id}
        if session
        else None,
        **counts,
        "opened_at": incident.opened_at,
        "updated_at": incident.updated_at,
        "resolved_at": incident.resolved_at,
        "created_by": actor_ref(incident.created_by, names),
        "is_simulation": bool(incident.is_simulation),
    }


# ----------------------------------------------------------------------------- involved records


@dataclass
class Involvement:
    """Ids an incident touches, with how many of its findings reference each one."""

    findings: list[SecurityFinding]
    agents: Counter[str] = field(default_factory=Counter)
    sessions: Counter[str] = field(default_factory=Counter)
    sources: Counter[str] = field(default_factory=Counter)
    destinations: Counter[str] = field(default_factory=Counter)
    context_items: set[str] = field(default_factory=set)
    tool_invocations: set[str] = field(default_factory=set)
    policy_decisions: set[str] = field(default_factory=set)

    @property
    def session_ids(self) -> list[str]:
        return sorted(self.sessions)


def incident_findings(db: Session, org_id: str, incident_id: str) -> list[SecurityFinding]:
    rank = case({s: r for s, r in SEVERITY_RANK.items()}, value=SecurityFinding.severity, else_=0)
    return list(
        db.scalars(
            scoped(SecurityFinding, org_id)
            .where(SecurityFinding.incident_id == incident_id)
            .order_by(rank.desc(), SecurityFinding.first_seen_at, SecurityFinding.id)
        )
    )


def involvement(
    db: Session, org_id: str, incident: Incident, findings: list[SecurityFinding] | None = None
) -> Involvement:
    found = findings if findings is not None else incident_findings(db, org_id, incident.id)
    inv = Involvement(findings=found)
    for f in found:
        refs: dict[str, set[str]] = {k: set() for k in ("agent", "session", "source", "destination")}
        for key, value in (
            ("agent", f.agent_id),
            ("session", f.session_id),
            ("source", f.source_id),
            ("destination", f.destination_id),
        ):
            if value:
                refs[key].add(value)
        for ev in f.evidence or []:
            kind, ref_id = (ev.get("type"), ev.get("id")) if isinstance(ev, dict) else (None, None)
            if not ref_id:
                continue
            if kind in ("source", "destination"):
                refs[kind].add(str(ref_id))
            elif kind == "context_item":
                inv.context_items.add(str(ref_id))
            elif kind == "tool_invocation":
                inv.tool_invocations.add(str(ref_id))
            elif kind == "policy_decision":
                inv.policy_decisions.add(str(ref_id))
        for collection, ids in (
            (inv.agents, refs["agent"]),
            (inv.sessions, refs["session"]),
            (inv.sources, refs["source"]),
            (inv.destinations, refs["destination"]),
        ):
            collection.update(ids)
        for coll, value in (
            (inv.context_items, f.context_item_id),
            (inv.tool_invocations, f.tool_invocation_id),
            (inv.policy_decisions, f.policy_decision_id),
        ):
            if value:
                coll.add(value)
    # Sources behind referenced context items and destinations behind referenced tool calls.
    if inv.context_items:
        for (source_id,) in db.execute(
            select(ContextItem.source_id).where(
                ContextItem.organization_id == org_id, ContextItem.id.in_(inv.context_items)
            )
        ):
            inv.sources.setdefault(source_id, 0)
    if inv.tool_invocations:
        for (dest_id,) in db.execute(
            select(ToolInvocation.destination_id).where(
                ToolInvocation.organization_id == org_id,
                ToolInvocation.id.in_(inv.tool_invocations),
                ToolInvocation.destination_id.is_not(None),
            )
        ):
            inv.destinations.setdefault(dest_id, 0)
    if incident.primary_session_id:
        inv.sessions.setdefault(incident.primary_session_id, 0)
    if incident.primary_agent_id:
        inv.agents.setdefault(incident.primary_agent_id, 0)
    for s in _sessions(db, org_id, set(inv.sessions)).values():
        inv.agents.setdefault(s.agent_id, 0)
    return inv


def _involved(db: Session, org_id: str, incident: Incident, inv: Involvement) -> dict[str, Any]:
    agents = _agents(db, org_id, set(inv.agents))
    sessions = _sessions(db, org_id, set(inv.sessions))
    agent_names = {a.id: a.name for a in agents.values()}
    missing = {s.agent_id for s in sessions.values()} - set(agent_names)
    agent_names.update({a.id: a.name for a in _agents(db, org_id, missing).values()})
    sources = (
        list(db.scalars(scoped(ContextSource, org_id).where(ContextSource.id.in_(set(inv.sources)))))
        if inv.sources
        else []
    )
    dests = (
        list(db.scalars(scoped(Destination, org_id).where(Destination.id.in_(set(inv.destinations)))))
        if inv.destinations
        else []
    )

    def by_count(counter: Counter[str]) -> Any:
        return lambda row: (-counter.get(row.id, 0), row.id)

    return {
        "agents": [
            {
                "id": a.id,
                "name": a.name,
                "framework": a.framework,
                "environment": a.environment,
                "status": a.status,
                "finding_count": inv.agents.get(a.id, 0),
                "is_primary": a.id == incident.primary_agent_id,
            }
            for a in sorted(agents.values(), key=by_count(inv.agents))
        ],
        "sessions": [
            {
                "id": s.id,
                "external_session_id": s.external_session_id,
                "agent_id": s.agent_id,
                "agent_name": agent_names.get(s.agent_id, s.agent_id),
                "status": s.status,
                "started_at": s.started_at,
                "ended_at": s.ended_at,
                "event_count": s.event_count,
                **{k: v for k, v in risk_flags(s).items() if k in ("risk_score", "risk_level", "trifecta")},
                "finding_count": inv.sessions.get(s.id, 0),
                "is_primary": s.id == incident.primary_session_id,
            }
            for s in sorted(
                sessions.values(), key=lambda s: (s.id != incident.primary_session_id, s.started_at)
            )
        ],
        "sources": [
            {
                "id": s.id,
                "source_type": s.source_type,
                "identifier": clip(s.identifier, 500) or "",
                "display_name": clip(s.display_name, 200),
                "trust_level": s.trust_level,
                "trust_reasons": [clip(str(r), 300) for r in (s.trust_reasons or [])[:3]],
                "finding_count": inv.sources.get(s.id, 0),
            }
            for s in sorted(sources, key=by_count(inv.sources))
        ],
        "destinations": [
            {
                "id": d.id,
                "kind": d.kind,
                "identifier": clip(d.identifier, 500) or "",
                "display_name": clip(d.display_name, 200),
                "classification": d.classification,
                "transfer_count": d.transfer_count,
                "blocked_count": d.blocked_count,
                "finding_count": inv.destinations.get(d.id, 0),
            }
            for d in sorted(dests, key=by_count(inv.destinations))
        ],
        "note": INVOLVED_NOTE,
    }


# ----------------------------------------------------------------------------- detail


def _finding_out(f: SecurityFinding, agents: dict[str, str], sessions: dict[str, str]) -> dict[str, Any]:
    return {
        "id": f.id,
        "title": clip(f.title, 400) or "",
        "category": f.category,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "status": f.status,
        "confidence": f.confidence,
        "explanation": clip(f.explanation, 1000) or "",
        "agent": {"id": f.agent_id, "name": agents.get(f.agent_id, f.agent_id)} if f.agent_id else None,
        "session": {"id": f.session_id, "external_session_id": sessions.get(f.session_id, f.session_id)}
        if f.session_id
        else None,
        "source_id": f.source_id,
        "context_item_id": f.context_item_id,
        "tool_invocation_id": f.tool_invocation_id,
        "policy_decision_id": f.policy_decision_id,
        "destination_id": f.destination_id,
        "occurrence_count": f.occurrence_count,
        "first_seen_at": f.first_seen_at,
        "last_seen_at": f.last_seen_at,
    }


def _activity(db: Session, org_id: str, incident_id: str, names: dict[str, str]) -> list[dict[str, Any]]:
    rows = list(
        db.scalars(
            scoped(IncidentActivity, org_id)
            .where(IncidentActivity.incident_id == incident_id)
            .order_by(IncidentActivity.created_at, IncidentActivity.id)
        )
    )
    names.update(user_names(db, org_id, {r.actor for r in rows} - set(names)))
    return [
        {
            "id": r.id,
            "kind": r.kind,
            "actor": actor_ref(r.actor, names),
            "body": clip(r.body) or "",
            "details": r.details or {},
            "created_at": r.created_at,
        }
        for r in rows
    ]


def linked_tasks(db: Session, org_id: str, incident_id: str, finding_ids: list[str]) -> list[dict[str, Any]]:
    """Tasks tied to the incident directly, through a context reference, or through one of its findings."""
    by_ref = select(TaskContextReference.task_id).where(
        TaskContextReference.organization_id == org_id,
        TaskContextReference.ref_type == "incident",
        TaskContextReference.ref_id == incident_id,
    )
    options = [Task.related_incident_id == incident_id, Task.id.in_(by_ref)]
    if finding_ids:
        options.append(Task.related_finding_id.in_(finding_ids))
    rows = db.execute(
        select(Task, BoardColumn.name)
        .outerjoin(BoardColumn, BoardColumn.id == Task.column_id)
        .where(Task.organization_id == org_id, or_(*options))
        .order_by(Task.number)
    )
    from app.services.workspace_tasks_common import task_key

    return [
        {
            "id": t.id,
            "key": task_key(t),
            "title": clip(t.title, 400) or "",
            "priority": t.priority,
            "column": column,
            "done": t.completed_at is not None,
            "archived": t.archived_at is not None,
            "related_finding_id": t.related_finding_id,
            "parent_task_id": t.parent_task_id,
        }
        for t, column in rows
    ]


def incident_detail(db: Session, org_id: str, incident_id: str) -> dict[str, Any]:
    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    findings = incident_findings(db, org_id, incident.id)
    inv = involvement(db, org_id, incident, findings)
    names = user_names(db, org_id, {incident.assignee_user_id or "", incident.created_by})
    counts = _finding_counts(db, org_id, [incident.id]).get(incident.id)
    agents = _agents(db, org_id, {incident.primary_agent_id or ""} | {f.agent_id or "" for f in findings})
    sessions = _sessions(
        db, org_id, {incident.primary_session_id or ""} | {f.session_id or "" for f in findings}
    )
    base = summary(incident, counts, agents, sessions, names)
    agent_names = {a.id: a.name for a in agents.values()}
    session_names = {s.id: s.external_session_id for s in sessions.values()}
    return {
        **base,
        "summary": clip(incident.summary) or "",
        "resolution": clip(incident.resolution),
        "tags": list(incident.tags or []),
        "allowed_transitions": allowed_transitions(incident.status),
        "findings": [_finding_out(f, agent_names, session_names) for f in findings],
        "involved": _involved(db, org_id, incident, inv),
        "activity": _activity(db, org_id, incident.id, names),
        "tasks": linked_tasks(db, org_id, incident.id, [f.id for f in findings]),
    }
