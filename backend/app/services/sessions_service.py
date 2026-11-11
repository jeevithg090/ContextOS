"""Agent sessions: filtered lists and detail (risk state with lethal-trifecta evidence resolved to
records). The plain-language timeline is built in ``sessions_timeline`` and re-exported here.

Everything is read from persisted, already-redacted rows of the caller's organisation. The trifecta
is reported as a risk condition with its evidence, never as proof of an attack, and decisions are
worded by their enforcement mode (only ``enforced`` decisions are described as denials/holds).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, UNTRUSTED_LEVELS, ApprovalStatus, FindingStatus
from app.engines.risk.session import risk_level_for
from app.models import (
    Agent,
    AgentSession,
    Approval,
    ContextItem,
    ContextSource,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.services.scoping import find_scoped, get_scoped, paginate, scoped
from app.services.sessions_timeline import clip, session_timeline, timeline_entries, timeline_query

# Re-exported: the timeline lives in ``sessions_timeline``; ``_entries`` is the former private name.
_entries = timeline_entries
_clip = clip

__all__ = [
    "CONDITIONS", "UNRESOLVED", "agent_ref", "finding_brief", "list_sessions", "risk_flags", "session_detail",
    "session_ref", "session_timeline", "summarize", "timeline_entries", "timeline_query",
]

UNRESOLVED = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value)
MAX_CHILDREN = 100
MAX_SESSION_FINDINGS = 25
CONDITIONS = (
    ("sensitive_access", "Sensitive data access", "The session read secrets, credentials or confidential data."),
    ("untrusted_exposure", "Untrusted content", "Content from a source that is not trusted entered the context."),
    ("outbound_channel", "Outbound channel", "The agent could send data out (network, email, messaging or shell)."),
)


# ----------------------------------------------------------------------------- summaries


def agent_ref(agent: Agent) -> dict[str, Any]:
    return {"id": agent.id, "name": agent.name, "framework": agent.framework, "environment": agent.environment,
            "status": agent.status, "is_simulation": agent.is_simulation}


def risk_flags(session: AgentSession) -> dict[str, Any]:
    state = session.risk_state or {}
    score = int(session.risk_score or 0)
    return {"risk_score": score, "risk_level": str(state.get("level") or risk_level_for(score)),
            "trifecta": bool(state.get("trifecta")), "sensitive_access": bool(state.get("sensitive_access")),
            "untrusted_exposure": bool(state.get("untrusted_exposure")),
            "outbound_channel": bool(state.get("outbound_channel"))}


def _agents(db: Session, org_id: str, ids: set[str]) -> dict[str, Agent]:
    if not ids:
        return {}
    return {a.id: a for a in db.scalars(scoped(Agent, org_id).where(Agent.id.in_(ids)))}


def session_ref(session: AgentSession, agent: Agent) -> dict[str, Any]:
    flags = risk_flags(session)
    return {"id": session.id, "external_session_id": session.external_session_id, "agent": agent_ref(agent),
            "status": session.status, "started_at": session.started_at, "risk_score": flags["risk_score"],
            "risk_level": flags["risk_level"], "trifecta": flags["trifecta"]}


def summarize(db: Session, org_id: str, sessions: list[AgentSession]) -> list[dict[str, Any]]:
    if not sessions:
        return []
    ids = [s.id for s in sessions]
    agents = _agents(db, org_id, {s.agent_id for s in sessions})
    open_findings = dict(db.execute(
        select(SecurityFinding.session_id, func.count()).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.session_id.in_(ids),
            SecurityFinding.status.in_(UNRESOLVED),
        ).group_by(SecurityFinding.session_id)
    ).all())
    children = dict(db.execute(
        select(AgentSession.parent_session_id, func.count()).where(
            AgentSession.organization_id == org_id, AgentSession.parent_session_id.in_(ids),
        ).group_by(AgentSession.parent_session_id)
    ).all())
    return [
        {"id": s.id, "agent": agent_ref(agents[s.agent_id]), "external_session_id": s.external_session_id,
         "parent_session_id": s.parent_session_id, "status": s.status, "started_at": s.started_at,
         "ended_at": s.ended_at, "last_event_at": s.last_event_at, "event_count": s.event_count or 0,
         **risk_flags(s), "open_findings": int(open_findings.get(s.id, 0)), "child_count": int(children.get(s.id, 0)),
         "is_simulation": s.is_simulation, "simulation_run_id": s.simulation_run_id}
        for s in sessions if s.agent_id in agents
    ]


def list_sessions(
    db: Session, org_id: str, *, agent_id: str | None = None, status: str | None = None,
    min_risk: int | None = None, trifecta: bool | None = None, include_simulated: bool = False,
    q: str | None = None, sort: str = "recent", limit: int = 50, offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query = scoped(AgentSession, org_id)
    if agent_id:
        query = query.where(AgentSession.agent_id == agent_id)
    if status:
        query = query.where(AgentSession.status == status)
    if min_risk is not None:
        query = query.where(AgentSession.risk_score >= min_risk)
    if trifecta is not None:
        flag = AgentSession.risk_state["trifecta"].as_boolean()
        query = query.where(flag.is_(True)) if trifecta else query.where(or_(flag.is_(None), flag.is_(False)))
    if not include_simulated:
        query = query.where(AgentSession.is_simulation.is_(False))
    if q and q.strip():
        query = query.where(AgentSession.external_session_id.icontains(q.strip(), autoescape=True))
    recent = func.coalesce(AgentSession.last_event_at, AgentSession.started_at)
    order = [AgentSession.risk_score.desc(), recent.desc()] if sort == "risk" else [recent.desc()]
    rows, total = paginate(db, query.order_by(*order, AgentSession.id.desc()), limit=limit, offset=offset)
    return summarize(db, org_id, rows), total


# ----------------------------------------------------------------------------- detail


def session_detail(db: Session, org_id: str, session_id: str) -> dict[str, Any]:
    session = get_scoped(db, AgentSession, session_id, org_id, label="Session")
    base = summarize(db, org_id, [session])[0]
    parent = find_scoped(db, AgentSession, session.parent_session_id, org_id)
    children = list(db.scalars(scoped(AgentSession, org_id).where(AgentSession.parent_session_id == session.id)
                               .order_by(AgentSession.started_at).limit(MAX_CHILDREN)))
    related = _agents(db, org_id, {s.agent_id for s in children} | ({parent.agent_id} if parent else set()))
    findings = db.scalars(scoped(SecurityFinding, org_id).where(SecurityFinding.session_id == session.id)
                          .order_by(SecurityFinding.last_seen_at.desc()).limit(500)).all()
    findings = sorted(findings, key=lambda f: (f.status not in UNRESOLVED, -SEVERITY_RANK.get(f.severity, 0)))
    return {
        **base,
        "metadata": session.session_metadata or {},
        "risk": _risk(db, org_id, session),
        "parent": session_ref(parent, related[parent.agent_id]) if parent and parent.agent_id in related else None,
        "children": [session_ref(c, related[c.agent_id]) for c in children if c.agent_id in related],
        "counts": _counts(db, org_id, timeline_query(org_id, session, base["agent"]["name"]), session.id),
        "findings": [finding_brief(f) for f in findings[:MAX_SESSION_FINDINGS]],
    }


def finding_brief(f: SecurityFinding) -> dict[str, Any]:
    return {"id": f.id, "title": f.title, "category": f.category, "severity": f.severity, "status": f.status,
            "session_id": f.session_id, "last_seen_at": f.last_seen_at, "occurrence_count": f.occurrence_count or 1,
            "is_simulation": f.is_simulation}


def _risk(db: Session, org_id: str, session: AgentSession) -> dict[str, Any]:
    state = session.risk_state or {}
    legs = state.get("trifecta_evidence") or {}
    factors = [f for f in state.get("factors") or [] if isinstance(f, dict)]
    raw = [e for key, _l, _d in CONDITIONS for e in legs.get(key) or []]
    raw += [e for f in factors for e in f.get("evidence") or []]
    resolved = _resolve_evidence(db, org_id, [e for e in raw if isinstance(e, dict)])

    def evidence(items: list[Any]) -> list[dict[str, Any]]:
        out = []
        for e in items or []:
            if isinstance(e, dict) and e.get("type"):
                key = (str(e["type"]), str(e.get("id") or ""))
                out.append({"type": key[0], "id": key[1], "detail": str(e.get("detail") or ""), **resolved.get(key, {})})
        return out

    flags = risk_flags(session)
    return {
        "score": int(state.get("score", flags["risk_score"]) or 0), "level": flags["risk_level"],
        "summary": str(state.get("summary") or "No risk signals have been recorded for this session yet."),
        "trifecta": flags["trifecta"],
        "conditions": [{"key": k, "label": label, "description": desc, "active": bool(state.get(k)),
                        "evidence": evidence(legs.get(k) or [])} for k, label, desc in CONDITIONS],
        "factors": [{"key": str(f.get("key") or ""), "label": str(f.get("label") or ""), "weight": int(f.get("weight") or 0),
                     "explanation": str(f.get("explanation") or ""), "evidence": evidence(f.get("evidence") or [])}
                    for f in factors],
        "computed_at": state.get("computed_at"),
    }


def _resolve_evidence(db: Session, org_id: str, items: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Display labels for evidence records (only records of this organisation resolve)."""
    ids: dict[str, set[str]] = {}
    for e in items:
        if e.get("id"):
            ids.setdefault(str(e["type"]), set()).add(str(e["id"]))
    out: dict[tuple[str, str], dict[str, Any]] = {}
    if ids.get("context_item"):
        for r in db.execute(
            select(ContextItem.id, ContextItem.session_id, ContextItem.trust_level, ContextSource.display_name,
                   ContextSource.identifier).join(ContextSource, ContextSource.id == ContextItem.source_id)
            .where(ContextItem.organization_id == org_id, ContextItem.id.in_(ids["context_item"]))
        ):
            out[("context_item", r.id)] = {"label": _clip(r.display_name or r.identifier, 80),
                                           "trust_level": r.trust_level, "session_id": r.session_id}
    if ids.get("tool_invocation"):
        for r in db.execute(
            select(ToolInvocation.id, ToolInvocation.session_id, Tool.name).join(Tool, Tool.id == ToolInvocation.tool_id)
            .where(ToolInvocation.organization_id == org_id, ToolInvocation.id.in_(ids["tool_invocation"]))
        ):
            out[("tool_invocation", r.id)] = {"label": r.name, "session_id": r.session_id}
    if ids.get("finding"):
        for r in db.execute(select(SecurityFinding.id, SecurityFinding.title, SecurityFinding.session_id).where(
                SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(ids["finding"]))):
            out[("finding", r.id)] = {"label": _clip(r.title, 80), "session_id": r.session_id}
    if ids.get("session"):
        for r in db.execute(select(AgentSession.id, Agent.name).join(Agent, Agent.id == AgentSession.agent_id).where(
                AgentSession.organization_id == org_id, AgentSession.id.in_(ids["session"]))):
            out[("session", r.id)] = {"label": f"Session of {r.name}"}
    return out


def _grouped(db: Session, column: Any, model: Any, org_id: str, *conds: Any) -> dict[str, int]:
    rows = db.execute(select(column, func.count()).where(model.organization_id == org_id, *conds).group_by(column))
    return {str(k): int(n) for k, n in rows if k is not None}


def _count(db: Session, model: Any, org_id: str, *conds: Any) -> int:
    return int(db.scalar(select(func.count()).select_from(model).where(model.organization_id == org_id, *conds)) or 0)


def _counts(db: Session, org_id: str, timeline: Select[Any], session_id: str) -> dict[str, Any]:
    def total(query: Select[Any]) -> int:
        return int(db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0)

    return {
        "timeline_entries": total(timeline),
        "context_items": _count(db, ContextItem, org_id, ContextItem.session_id == session_id),
        "untrusted_context_items": _count(db, ContextItem, org_id, ContextItem.session_id == session_id,
                                          ContextItem.trust_level.in_([str(t) for t in UNTRUSTED_LEVELS])),
        "tool_invocations": _count(db, ToolInvocation, org_id, ToolInvocation.session_id == session_id),
        "decisions": _grouped(db, PolicyDecision.decision, PolicyDecision, org_id, PolicyDecision.session_id == session_id),
        "enforcement": _grouped(db, PolicyDecision.enforcement, PolicyDecision, org_id,
                                PolicyDecision.session_id == session_id),
        "findings_open": _count(db, SecurityFinding, org_id, SecurityFinding.session_id == session_id,
                                SecurityFinding.status.in_(UNRESOLVED)),
        "findings_total": _count(db, SecurityFinding, org_id, SecurityFinding.session_id == session_id),
        "approvals_pending": _count(db, Approval, org_id, Approval.session_id == session_id,
                                    Approval.status == ApprovalStatus.PENDING.value),
        "processing_errors": total(timeline.where(IngestedEvent.processing_status == "error")),
    }
