"""Security Intelligence read side: finding lists, statistics and detail.

Every query is scoped to one organisation. Simulated findings (Simulation Lab) are excluded unless
``include_simulated`` is set. Statistics are computed from persisted rows only:

- the *open backlog* is the current state (open + acknowledged), independent of the window;
- *period* figures count findings first detected inside the window (trend and top sources leave out
  false positives, which an analyst judged not to be suspicious);
- mean time to resolve uses the resolving audit entry (``finding.resolved``) of findings that are
  still resolved, measured from the finding's first detection.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc, utcnow
from app.domain.enums import SEVERITY_RANK, FindingStatus, IncidentStatus, Severity
from app.models import (
    Agent,
    AgentSession,
    AuditEvent,
    BoardColumn,
    ContextItem,
    ContextSource,
    Destination,
    Incident,
    IngestedEvent,
    Membership,
    PolicyDecision,
    SecurityFinding,
    Task,
    TaskContextReference,
    Tool,
    ToolInvocation,
    User,
)
from app.services.findings import (
    ACTIVE_STATUSES,
    STATUS_AUDIT_ACTIONS,
    TRIAGE_AUDIT_ACTIONS,
    allowed_transitions,
)
from app.services.scoping import find_scoped, get_scoped, paginate, scoped
from app.services.sessions_service import risk_flags
from app.services.workspace_tasks_common import task_key

F = SecurityFinding
SEVERITIES = [s.value for s in Severity]
WINDOWS: dict[str, tuple[int, str]] = {
    "24h": (24, "hour"),
    "7d": (7, "day"),
    "30d": (30, "day"),
    "90d": (90, "day"),
}
SORTS = ("severity", "recent", "first_seen", "occurrences")
_SEVERITY_ORDER = case({k: v for k, v in SEVERITY_RANK.items()}, value=F.severity, else_=-1)
_OPEN_INCIDENT = (
    IncidentStatus.OPEN.value,
    IncidentStatus.INVESTIGATING.value,
    IncidentStatus.CONTAINED.value,
)
_FP = FindingStatus.FALSE_POSITIVE.value


@dataclass
class FindingFilters:
    statuses: list[str] | None = None
    severities: list[str] | None = None
    categories: list[str] | None = None
    agent_id: str | None = None
    session_id: str | None = None
    source_id: str | None = None
    incident_id: str | None = None
    include_simulated: bool = False
    q: str | None = None
    since: datetime | None = None


def _like(value: str) -> str:
    escaped = value.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _conditions(org_id: str, f: FindingFilters) -> list[Any]:
    conds: list[Any] = [F.organization_id == org_id]
    if not f.include_simulated:
        conds.append(F.is_simulation.is_(False))
    for column, values in ((F.status, f.statuses), (F.severity, f.severities), (F.category, f.categories)):
        if values:
            conds.append(column.in_(values))
    for column, value in (
        (F.agent_id, f.agent_id),
        (F.session_id, f.session_id),
        (F.source_id, f.source_id),
        (F.incident_id, f.incident_id),
    ):
        if value:
            conds.append(column == value)
    if f.since is not None:
        conds.append(F.last_seen_at >= f.since)
    if f.q and f.q.strip():
        needle = _like(f.q)
        conds.append(
            or_(
                F.id == f.q.strip(),
                func.lower(F.title).like(needle, escape="\\"),
                func.lower(F.rule_id).like(needle, escape="\\"),
                func.lower(F.explanation).like(needle, escape="\\"),
            )
        )
    return conds


def list_findings(
    db: Session, org_id: str, f: FindingFilters, *, sort: str = "severity", limit: int = 50, offset: int = 0
) -> tuple[list[dict[str, Any]], int]:
    """Most severe first, then most recently seen (or the requested ordering)."""
    order = {
        "severity": (_SEVERITY_ORDER.desc(), F.last_seen_at.desc()),
        "recent": (F.last_seen_at.desc(),),
        "first_seen": (F.first_seen_at.desc(),),
        "occurrences": (F.occurrence_count.desc(), F.last_seen_at.desc()),
    }[sort]
    stmt = select(F).where(*_conditions(org_id, f)).order_by(*order, F.id.desc())
    rows, total = paginate(db, stmt, limit=limit, offset=offset)
    return summaries(db, org_id, rows), total


# ----------------------------------------------------------------------------- summaries


def _by_id(db: Session, model: Any, org_id: str, ids: set[str | None]) -> dict[str, Any]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {r.id: r for r in db.scalars(scoped(model, org_id).where(model.id.in_(wanted)))}


def incident_ref(i: Incident) -> dict[str, Any]:
    return {"id": i.id, "number": i.number, "title": i.title, "status": i.status, "severity": i.severity}


def source_ref(s: ContextSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "source_type": s.source_type,
        "identifier": s.identifier,
        "display_name": s.display_name,
        "trust_level": s.trust_level,
    }


def summaries(db: Session, org_id: str, rows: list[SecurityFinding]) -> list[dict[str, Any]]:
    agents = _by_id(db, Agent, org_id, {r.agent_id for r in rows})
    sessions = _by_id(db, AgentSession, org_id, {r.session_id for r in rows})
    sources = _by_id(db, ContextSource, org_id, {r.source_id for r in rows})
    incidents = _by_id(db, Incident, org_id, {r.incident_id for r in rows})
    out = []
    for r in rows:
        agent, session = agents.get(r.agent_id or ""), sessions.get(r.session_id or "")
        source, incident = sources.get(r.source_id or ""), incidents.get(r.incident_id or "")
        out.append(
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "rule_id": r.rule_id,
                "severity": r.severity,
                "confidence": float(r.confidence or 0),
                "status": r.status,
                "agent": {"id": agent.id, "name": agent.name} if agent else None,
                "session": {"id": session.id, "external_session_id": session.external_session_id}
                if session
                else None,
                "source": source_ref(source) if source else None,
                "incident": incident_ref(incident) if incident else None,
                "occurrence_count": r.occurrence_count or 1,
                "first_seen_at": r.first_seen_at,
                "last_seen_at": r.last_seen_at,
                "is_simulation": bool(r.is_simulation),
            }
        )
    return out


# ----------------------------------------------------------------------------- statistics


def _severity_counts(pairs: list[tuple[str, int]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for severity, n in pairs:
        if severity in counts:
            counts[severity] += int(n)
    return counts


def _categories(pairs: list[tuple[str, int]]) -> list[dict[str, Any]]:
    totals: dict[str, int] = {}
    for category, n in pairs:
        totals[category] = totals.get(category, 0) + int(n)
    return [{"category": c, "count": n} for c, n in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))]


def _window_start(now: datetime, window: str) -> tuple[datetime, str, int, timedelta]:
    size, bucket = WINDOWS[window]
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    floor = now.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        floor = floor.replace(hour=0)
    return floor - step * (size - 1), bucket, size, step


def finding_stats(
    db: Session, org_id: str, *, window: str = "7d", include_simulated: bool = False
) -> dict[str, Any]:
    now = utcnow()
    since, bucket, size, step = _window_start(now, window)
    base: list[Any] = [F.organization_id == org_id]
    if not include_simulated:
        base.append(F.is_simulation.is_(False))

    backlog = db.execute(
        select(F.status, F.severity, F.category, func.count(F.id), func.min(F.first_seen_at))
        .where(*base, F.status.in_(ACTIVE_STATUSES))
        .group_by(F.status, F.severity, F.category)
    ).all()
    oldest = min((ensure_utc(r[4]) for r in backlog if r[4] is not None), default=None)
    simulated_open = (
        0
        if include_simulated
        else int(
            db.scalar(
                select(func.count(F.id)).where(
                    F.organization_id == org_id, F.is_simulation.is_(True), F.status.in_(ACTIVE_STATUSES)
                )
            )
            or 0
        )
    )

    period = db.execute(
        select(F.status, F.severity, F.category, func.count(F.id))
        .where(*base, F.first_seen_at >= since)
        .group_by(F.status, F.severity, F.category)
    ).all()
    by_status = dict.fromkeys([s.value for s in FindingStatus], 0)
    for status, _sev, _cat, n in period:
        by_status[status] = by_status.get(status, 0) + int(n)

    return {
        "window": window,
        "bucket": bucket,
        "since": since,
        "until": now,
        "include_simulated": include_simulated,
        "simulated_open": simulated_open,
        "open": {
            "total": sum(int(r[3]) for r in backlog),
            "needs_triage": sum(int(r[3]) for r in backlog if r[0] == FindingStatus.OPEN.value),
            "acknowledged": sum(int(r[3]) for r in backlog if r[0] == FindingStatus.ACKNOWLEDGED.value),
            "by_severity": _severity_counts([(r[1], r[3]) for r in backlog]),
            "by_category": _categories([(r[2], r[3]) for r in backlog]),
            "oldest_first_seen_at": oldest,
        },
        "period": {
            "total": sum(int(r[3]) for r in period),
            "by_severity": _severity_counts([(r[1], r[3]) for r in period]),
            "by_category": _categories([(r[2], r[3]) for r in period]),
            "by_status": by_status,
            "trend": _trend(db, base, since, bucket, size, step),
            "top_sources": _top_sources(db, org_id, base, since),
            "mttr": _mttr(db, org_id, base, since),
        },
        "agents": _agent_facet(db, org_id, base),
        "categories": _categories(
            list(db.execute(select(F.category, func.count(F.id)).where(*base).group_by(F.category)).tuples())
        ),
    }


def _trend(
    db: Session, base: list[Any], since: datetime, bucket: str, size: int, step: timedelta
) -> list[dict[str, Any]]:
    points = [{"t": since + step * i, **dict.fromkeys(SEVERITIES, 0), "total": 0} for i in range(size)]
    rows = db.execute(
        select(F.first_seen_at, F.severity).where(*base, F.first_seen_at >= since, F.status != _FP)
    )
    for first_seen, severity in rows:
        seen = ensure_utc(first_seen)
        if seen is None:
            continue
        index = int((seen - since) // step)
        if 0 <= index < size and severity in SEVERITY_RANK:
            points[index][severity] += 1
            points[index]["total"] += 1
    return points


def _top_sources(
    db: Session, org_id: str, base: list[Any], since: datetime, limit: int = 8
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(F.source_id, F.severity, func.count(F.id))
        .where(*base, F.first_seen_at >= since, F.status != _FP, F.source_id.is_not(None))
        .group_by(F.source_id, F.severity)
    ).all()
    totals: dict[str, list[Any]] = {}
    for source_id, severity, n in rows:
        entry = totals.setdefault(source_id, [0, None])
        entry[0] += int(n)
        if SEVERITY_RANK.get(severity, -1) > SEVERITY_RANK.get(entry[1] or "", -1):
            entry[1] = severity
    ranked = sorted(
        totals.items(), key=lambda kv: (-kv[1][0], -SEVERITY_RANK.get(kv[1][1] or "", -1), kv[0])
    )[:limit]
    sources = _by_id(db, ContextSource, org_id, {sid for sid, _ in ranked})
    return [
        {**source_ref(sources[sid]), "count": count, "max_severity": worst}
        for sid, (count, worst) in ranked
        if sid in sources
    ]


def _mttr(db: Session, org_id: str, base: list[Any], since: datetime) -> dict[str, Any]:
    resolved_at = {
        fid: at
        for fid, at in db.execute(
            select(AuditEvent.target_id, func.max(AuditEvent.occurred_at))
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.target_type == "finding",
                AuditEvent.action == STATUS_AUDIT_ACTIONS[FindingStatus.RESOLVED.value],
                AuditEvent.occurred_at >= since,
            )
            .group_by(AuditEvent.target_id)
        )
    }
    durations: list[float] = []
    if resolved_at:
        rows = db.execute(
            select(F.id, F.first_seen_at).where(
                *base, F.id.in_(list(resolved_at)), F.status == FindingStatus.RESOLVED.value
            )
        )
        for fid, first_seen in rows:
            end, start = ensure_utc(resolved_at[fid]), ensure_utc(first_seen)
            if end and start:
                durations.append(max(0.0, (end - start).total_seconds()))
    return {
        "mean_seconds": statistics.fmean(durations) if durations else None,
        "median_seconds": statistics.median(durations) if durations else None,
        "resolved_count": len(durations),
    }


def _agent_facet(db: Session, org_id: str, base: list[Any], limit: int = 100) -> list[dict[str, Any]]:
    rows = db.execute(
        select(F.agent_id, func.count(F.id))
        .where(*base, F.agent_id.is_not(None))
        .group_by(F.agent_id)
        .order_by(func.count(F.id).desc())
        .limit(limit)
    ).all()
    agents = _by_id(db, Agent, org_id, {aid for aid, _ in rows})
    return [{"id": aid, "name": agents[aid].name, "count": int(n)} for aid, n in rows if aid in agents]


# ----------------------------------------------------------------------------- detail


def _clip(value: str | None, limit: int = 80) -> str | None:
    if not value:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _evidence_labels(
    db: Session, org_id: str, ids: dict[str, set[str]]
) -> dict[tuple[str, str], dict[str, Any]]:
    """(type, id) -> {"label", "session_id"} for records that exist in this organisation."""
    out: dict[tuple[str, str], dict[str, Any]] = {}

    def put(kind: str, rows: Any, label: Any, session: Any = lambda r: None) -> None:
        for r in rows:
            out[(kind, r.id)] = {"label": _clip(label(r)), "session_id": session(r)}

    if ids.get("context_item"):
        put(
            "context_item",
            db.execute(
                select(
                    ContextItem.id,
                    ContextItem.session_id,
                    ContextSource.display_name,
                    ContextSource.identifier,
                )
                .join(ContextSource, ContextSource.id == ContextItem.source_id)
                .where(ContextItem.organization_id == org_id, ContextItem.id.in_(ids["context_item"]))
            ),
            lambda r: r.display_name or r.identifier,
            lambda r: r.session_id,
        )
    if ids.get("tool_invocation"):
        put(
            "tool_invocation",
            db.execute(
                select(ToolInvocation.id, ToolInvocation.session_id, Tool.name)
                .join(Tool, Tool.id == ToolInvocation.tool_id)
                .where(
                    ToolInvocation.organization_id == org_id, ToolInvocation.id.in_(ids["tool_invocation"])
                )
            ),
            lambda r: r.name,
            lambda r: r.session_id,
        )
    if ids.get("session"):
        put(
            "session",
            db.execute(
                select(AgentSession.id, AgentSession.external_session_id).where(
                    AgentSession.organization_id == org_id, AgentSession.id.in_(ids["session"])
                )
            ),
            lambda r: r.external_session_id,
            lambda r: r.id,
        )
    simple: list[tuple[str, Any, Any, Any]] = [
        (
            "policy_decision",
            PolicyDecision,
            lambda r: f"{r.decision} ({r.enforcement})",
            lambda r: r.session_id,
        ),
        ("event", IngestedEvent, lambda r: r.event_type, lambda r: r.session_id),
        ("source", ContextSource, lambda r: r.display_name or r.identifier, lambda r: None),
        ("destination", Destination, lambda r: r.display_name or r.identifier, lambda r: None),
        ("finding", SecurityFinding, lambda r: r.title, lambda r: r.session_id),
        ("tool", Tool, lambda r: r.name, lambda r: None),
        ("agent", Agent, lambda r: r.name, lambda r: None),
    ]
    for kind, model, label, session in simple:
        if ids.get(kind):
            put(kind, db.scalars(scoped(model, org_id).where(model.id.in_(ids[kind]))), label, session)
    return out


def resolve_evidence(db: Session, org_id: str, evidence: list[Any] | None) -> list[dict[str, Any]]:
    items = [
        e
        for e in (evidence or [])
        if isinstance(e, dict) and isinstance(e.get("type"), str) and e.get("type")
    ]
    ids: dict[str, set[str]] = {}
    for e in items:
        if e.get("id"):
            ids.setdefault(e["type"], set()).add(str(e["id"]))
    labels = _evidence_labels(db, org_id, ids)
    out = []
    for e in items:
        ref_id = str(e["id"]) if e.get("id") else None
        hit = labels.get((e["type"], ref_id or ""))
        out.append(
            {
                "type": e["type"],
                "id": ref_id,
                "label": hit["label"] if hit else None,
                "session_id": hit["session_id"] if hit else None,
                "excerpt": e.get("excerpt") if isinstance(e.get("excerpt"), str) else None,
                "detail": e.get("detail") if isinstance(e.get("detail"), str) else None,
                "found": hit is not None,
            }
        )
    return out


def _invocation(db: Session, org_id: str, inv_id: str | None) -> tuple[ToolInvocation, Tool] | None:
    if not inv_id:
        return None
    row = db.execute(
        select(ToolInvocation, Tool)
        .join(Tool, Tool.id == ToolInvocation.tool_id)
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.id == inv_id)
    ).first()
    return (row[0], row[1]) if row else None


def _related(db: Session, org_id: str, f: SecurityFinding) -> dict[str, Any]:
    item = find_scoped(db, ContextItem, f.context_item_id, org_id)
    source = find_scoped(db, ContextSource, f.source_id or (item.source_id if item else None), org_id)
    agent = find_scoped(db, Agent, f.agent_id, org_id)
    session = find_scoped(db, AgentSession, f.session_id, org_id)
    call = _invocation(db, org_id, f.tool_invocation_id)
    retrieval = _invocation(db, org_id, item.tool_invocation_id if item else None)
    decision = find_scoped(
        db, PolicyDecision, f.policy_decision_id or (call[0].policy_decision_id if call else None), org_id
    )
    destination = find_scoped(
        db, Destination, f.destination_id or (call[0].destination_id if call else None), org_id
    )
    incident = find_scoped(db, Incident, f.incident_id, org_id)
    return {
        "agent": {
            "id": agent.id,
            "name": agent.name,
            "framework": agent.framework,
            "environment": agent.environment,
            "status": agent.status,
        }
        if agent
        else None,
        "session": {
            "id": session.id,
            "external_session_id": session.external_session_id,
            "status": session.status,
            "started_at": session.started_at,
            **{k: v for k, v in risk_flags(session).items() if k in ("risk_score", "risk_level", "trifecta")},
        }
        if session
        else None,
        "source": {
            **source_ref(source),
            "finding_count": source.finding_count or 0,
            "max_finding_severity": source.max_finding_severity,
            "manually_classified": bool(source.manually_classified),
        }
        if source
        else None,
        "context_item": {
            "id": item.id,
            "collected_via": item.collected_via,
            "received_at": item.received_at,
            "trust_level": item.trust_level,
            "sensitivity": item.sensitivity,
            "contains_secrets": bool(item.contains_secrets),
            "content_length": item.content_length or 0,
            "retrieved_by": {"id": retrieval[0].id, "tool_name": retrieval[1].name} if retrieval else None,
        }
        if item
        else None,
        "tool_invocation": {
            "id": call[0].id,
            "session_id": call[0].session_id,
            "tool_name": call[1].name,
            "tool_category": call[1].category,
            "status": call[0].status,
            "decision": call[0].decision,
            "enforcement": call[0].enforcement,
            "requested_at": call[0].requested_at,
        }
        if call
        else None,
        "decision": {
            "id": decision.id,
            "session_id": decision.session_id,
            "decision": decision.decision,
            "enforcement": decision.enforcement,
            "explanation": decision.explanation or "",
            "evaluated_at": decision.evaluated_at,
            "matched_policies": [
                {
                    "policy_id": m.get("policy_id"),
                    "name": str(m.get("name") or "Policy"),
                    "outcome": m.get("outcome"),
                    "mode": m.get("mode"),
                }
                for m in (decision.matched_policies or [])
                if isinstance(m, dict)
            ],
        }
        if decision
        else None,
        "destination": {
            "id": destination.id,
            "kind": destination.kind,
            "identifier": destination.identifier,
            "classification": destination.classification,
        }
        if destination
        else None,
        "incident": incident_ref(incident) if incident else None,
        "tasks": _tasks(db, org_id, f.id),
    }


def _tasks(db: Session, org_id: str, finding_id: str) -> list[dict[str, Any]]:
    referenced = select(TaskContextReference.task_id).where(
        TaskContextReference.organization_id == org_id,
        TaskContextReference.ref_type == "finding",
        TaskContextReference.ref_id == finding_id,
    )
    rows = db.execute(
        select(Task, BoardColumn.name, BoardColumn.is_done_column)
        .outerjoin(BoardColumn, BoardColumn.id == Task.column_id)
        .where(
            Task.organization_id == org_id,
            or_(Task.related_finding_id == finding_id, Task.id.in_(referenced)),
        )
        .order_by(Task.created_at.desc())
        .limit(20)
    ).all()
    return [
        {
            "id": t.id,
            "key": task_key(t),
            "title": t.title,
            "priority": t.priority,
            "column": column,
            "done": bool(done) or t.completed_at is not None,
            "archived": t.archived_at is not None,
        }
        for t, column, done in rows
    ]


def _history(db: Session, org_id: str, finding_id: str) -> list[dict[str, Any]]:
    rows = list(
        db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.target_type == "finding",
                AuditEvent.target_id == finding_id,
                AuditEvent.action.in_(TRIAGE_AUDIT_ACTIONS),
            )
            .order_by(AuditEvent.seq.desc())
            .limit(50)
        )
    )
    user_ids = {r.actor_id for r in rows if r.actor_type == "user" and r.actor_id}
    names = (
        {uid: name for uid, name in db.execute(select(User.id, User.name).where(User.id.in_(user_ids)))}
        if user_ids
        else {}
    )
    out = []
    for r in rows:
        details = r.details or {}
        actor = (
            names.get(r.actor_id or "", "Former member")
            if r.actor_type == "user"
            else ("API key" if r.actor_type == "api_key" else "ContextOS")
        )
        note = details.get("note")
        out.append(
            {
                "action": r.action,
                "from_status": details.get("from"),
                "to_status": details.get("to"),
                "actor": actor,
                "note": note if isinstance(note, str) else None,
                "occurred_at": r.occurred_at,
            }
        )
    return out


def _resolver(db: Session, org_id: str, user_id: str | None) -> dict[str, Any] | None:
    if not user_id:
        return None
    row = db.execute(
        select(User.id, User.name)
        .join(Membership, Membership.user_id == User.id)
        .where(User.id == user_id, Membership.organization_id == org_id)
    ).first()
    return {"id": row.id, "name": row.name} if row else None


def _incident_candidates(
    db: Session, org_id: str, f: SecurityFinding, limit: int = 6
) -> list[dict[str, Any]]:
    rows = list(
        db.scalars(
            scoped(Incident, org_id)
            .where(
                Incident.status.in_(_OPEN_INCIDENT),
                Incident.is_simulation.is_(bool(f.is_simulation)),
            )
            .order_by(Incident.opened_at.desc())
            .limit(50)
        )
    )

    def reason(i: Incident) -> tuple[int, str]:
        if f.session_id and i.primary_session_id == f.session_id:
            return 0, "Same session"
        if f.agent_id and i.primary_agent_id == f.agent_id:
            return 1, "Same agent"
        return 2, "Recent open incident"

    ranked = sorted(rows, key=lambda i: reason(i)[0])[:limit]
    return [{**incident_ref(i), "reason": reason(i)[1]} for i in ranked]


def finding_detail(db: Session, org_id: str, finding_id: str) -> dict[str, Any]:
    f = get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")
    return {
        **summaries(db, org_id, [f])[0],
        "explanation": f.explanation,
        "remediation": f.remediation,
        "resolution_note": f.resolution_note,
        "resolved_by": _resolver(db, org_id, f.resolved_by_user_id),
        "evidence": resolve_evidence(db, org_id, f.evidence),
        "related": _related(db, org_id, f),
        "history": _history(db, org_id, f.id),
        "allowed_transitions": allowed_transitions(f.status),
        "incident_candidates": [] if f.incident_id else _incident_candidates(db, org_id, f),
    }


def finding_summary(db: Session, org_id: str, finding_id: str) -> dict[str, Any]:
    return summaries(db, org_id, [get_scoped(db, SecurityFinding, finding_id, org_id, label="Finding")])[0]
