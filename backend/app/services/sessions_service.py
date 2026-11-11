"""Agent sessions: filtered lists, detail (risk state with lethal-trifecta evidence resolved to
records) and the plain-language timeline built from the ingested-event log.

Everything is read from persisted, already-redacted rows of the caller's organisation. The trifecta
is reported as a risk condition with its evidence, never as proof of an attack, and decisions are
worded by their enforcement mode (only ``enforced`` decisions are described as denials/holds).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, UNTRUSTED_LEVELS, ApprovalStatus, FindingStatus
from app.engines.risk.session import risk_level_for
from app.models import (
    Agent,
    AgentSession,
    Approval,
    ContextItem,
    ContextSource,
    Destination,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.services.scoping import find_scoped, get_scoped, paginate, scoped

UNRESOLVED = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value)
MAX_CHILDREN = 100
MAX_SESSION_FINDINGS = 25
CONDITIONS = (
    ("sensitive_access", "Sensitive data access", "The session read secrets, credentials or confidential data."),
    ("untrusted_exposure", "Untrusted content", "Content from a source that is not trusted entered the context."),
    ("outbound_channel", "Outbound channel", "The agent could send data out (network, email, messaging or shell)."),
)
_QUERY_KEYS = ("query", "q", "search_query", "search", "keywords")
_TOOL_EVENTS = {"tool.requested", "tool.completed", "tool.failed"}
_SOURCE_TITLES = {
    "file": "Read file {}", "repository": "Read repository file {}", "web": "Fetched web page {}",
    "browser": "Viewed page {}", "document": "Read document {}", "email": "Read email {}",
    "api": "Received API response from {}", "mcp_server": "Received content from MCP server {}",
    "mcp_tool": "Received MCP tool output {}", "database": "Read database result {}",
    "user_upload": "Received uploaded file {}", "tool_output": "Received tool output {}",
    "agent_output": "Received output from agent {}", "system": "Loaded system context {}",
}
_COMPLETED = {
    "file_read": "Read file {}", "file_write": "Wrote file {}", "http": "Fetched {}", "browser": "Browsed {}",
    "shell": "Ran `{}`", "search": "Searched for “{}”",
}
_ENFORCED = {"ALLOW": "Allowed {}", "AUDIT": "Allowed {} (audited)", "RESTRICT": "Restricted {}",
             "DENY": "Denied {}", "REQUIRE_APPROVAL": "Held {} for approval"}
_ADVISED = {"ALLOW": "Advised to allow {}", "AUDIT": "Advised to allow {} (audit)", "RESTRICT": "Advised to restrict {}",
            "DENY": "Advised to deny {}", "REQUIRE_APPROVAL": "Advised to require approval for {}"}


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


# ----------------------------------------------------------------------------- timeline


def timeline_query(org_id: str, session: AgentSession, agent_name: str) -> Select[Any]:
    """The session's events, events recorded elsewhere that delivered content into it (a parent's
    delegation carrying this session's task) and events that failed before the session was resolved
    (matched by the integration's session id and agent name kept in their redacted payload)."""
    delivered = select(ContextItem.event_id).where(
        ContextItem.organization_id == org_id, ContextItem.session_id == session.id,
        ContextItem.origin_session_id.is_not(None),
    )
    payload = IngestedEvent.payload_redacted
    failed = and_(
        IngestedEvent.session_id.is_(None), IngestedEvent.processing_status == "error",
        payload["session_id"].as_string() == session.external_session_id,
        payload["agent"]["name"].as_string() == agent_name,
    )
    return scoped(IngestedEvent, org_id).where(
        or_(IngestedEvent.session_id == session.id, IngestedEvent.id.in_(delivered), failed)
    )


def session_timeline(db: Session, org_id: str, session_id: str, *, limit: int, offset: int,
                     focus_invocation_id: str | None = None) -> dict[str, Any]:
    """One page of the timeline in server sequence order. With ``focus_invocation_id`` the page that
    contains that tool call's first event is returned (``offset`` is ignored)."""
    session = get_scoped(db, AgentSession, session_id, org_id, label="Session")
    agent = get_scoped(db, Agent, session.agent_id, org_id, label="Agent")
    query = timeline_query(org_id, session, agent.name)
    focus: list[str] = []
    if focus_invocation_id:
        inv = db.scalar(scoped(ToolInvocation, org_id).where(ToolInvocation.id == focus_invocation_id,
                                                             ToolInvocation.session_id == session.id))
        event_ids = [e for e in ((inv.request_event_id, inv.result_event_id) if inv else ()) if e]
        first = db.scalar(select(func.min(IngestedEvent.sequence)).where(
            IngestedEvent.organization_id == org_id, IngestedEvent.id.in_(event_ids))) if event_ids else None
        if first is not None:
            before = db.scalar(select(func.count()).select_from(
                query.where(IngestedEvent.sequence < first).subquery())) or 0
            offset, focus = (int(before) // limit) * limit, event_ids
    rows, total = paginate(db, query.order_by(IngestedEvent.sequence), limit=limit, offset=offset)
    return {"items": _entries(db, org_id, session, rows), "total": total, "limit": limit, "offset": offset,
            "focus_event_ids": focus}


def _entries(db: Session, org_id: str, session: AgentSession, rows: list[IngestedEvent]) -> list[dict[str, Any]]:
    refs = [r.refs or {} for r in rows]
    inv_ids = {str(r["tool_invocation_id"]) for r in refs if r.get("tool_invocation_id")}
    item_ids = {str(i) for r in refs for i in _item_ids(r)}
    dec_ids = {str(r["policy_decision_id"]) for r in refs if r.get("policy_decision_id")}
    fnd_ids = {str(f) for r in refs for f in r.get("finding_ids") or []}
    invs = {inv.id: (inv, tool) for inv, tool in db.execute(
        select(ToolInvocation, Tool).join(Tool, Tool.id == ToolInvocation.tool_id)
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.id.in_(inv_ids)))} if inv_ids else {}
    dest_ids = {inv.destination_id for inv, _t in invs.values() if inv.destination_id}
    dests = dict(db.execute(select(Destination.id, Destination.identifier).where(
        Destination.organization_id == org_id, Destination.id.in_(dest_ids))).all()) if dest_ids else {}
    items = {r.id: r for r in db.execute(
        select(ContextItem.id, ContextItem.session_id, ContextItem.trust_level, ContextItem.content_length,
               ContextItem.sensitivity, ContextItem.detection_summary, ContextSource.source_type,
               ContextSource.identifier, ContextSource.display_name)
        .join(ContextSource, ContextSource.id == ContextItem.source_id)
        .where(ContextItem.organization_id == org_id, ContextItem.id.in_(item_ids)))} if item_ids else {}
    decisions = {r.id: r for r in db.execute(
        select(PolicyDecision.id, PolicyDecision.decision, PolicyDecision.enforcement, PolicyDecision.explanation)
        .where(PolicyDecision.organization_id == org_id, PolicyDecision.id.in_(dec_ids)))} if dec_ids else {}
    severities = dict(db.execute(select(SecurityFinding.id, SecurityFinding.severity).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(fnd_ids))).all()) if fnd_ids else {}

    out = []
    for row, ref in zip(rows, refs, strict=True):
        other = row.session_id is not None and row.session_id != session.id
        candidates = [items[i] for i in _item_ids(ref) if i in items]
        item = next((c for c in candidates if c.session_id == session.id), candidates[0] if candidates else None)
        inv, tool = invs.get(str(ref.get("tool_invocation_id") or ""), (None, None))
        dec = decisions.get(str(ref.get("policy_decision_id") or ""))
        decision = dec.decision if dec else None
        enforcement = dec.enforcement if dec else None
        sevs = [severities[f] for f in ref.get("finding_ids") or [] if f in severities]
        payload = row.payload_redacted or {}
        if row.processing_status == "error":
            title = f"Could not process {row.event_type} event"
            summary = _clip(row.processing_error, 300) or "The pipeline recorded an error for this event."
        elif row.event_type in _TOOL_EVENTS:
            dest = dests.get(inv.destination_id) if inv and inv.destination_id else None
            title, summary = _tool_text(row.event_type, payload, ref, inv, tool, item, dec, dest)
        else:
            title, summary = _describe(row.event_type, payload, ref, item, other)
        out.append({
            "id": row.id, "sequence": row.sequence, "received_at": row.received_at, "occurred_at": row.occurred_at,
            "event_type": row.event_type, "title": title, "summary": summary,
            "trust_level": item.trust_level if item else None, "decision": decision, "enforcement": enforcement,
            "severity": max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0)) if sevs else None,
            "processing_status": row.processing_status, "from_other_session": other,
            "tool": {"name": tool.name, "category": tool.category, "status": inv.status if inv else None} if tool else None,
            "refs": {"context_item_id": item.id if item else None, "tool_invocation_id": inv.id if inv else None,
                     "policy_decision_id": dec.id if dec else None,
                     "finding_ids": [str(f) for f in ref.get("finding_ids") or []],
                     "approval_id": ref.get("approval_id"),
                     "child_session_id": ref.get("child_session_id") if not other else None,
                     "source_id": ref.get("source_id"), "destination_id": ref.get("destination_id")},
        })
    return out


def _item_ids(ref: dict[str, Any]) -> list[str]:
    many = ref.get("context_item_ids") or []
    return [str(i) for i in many] or ([str(ref["context_item_id"])] if ref.get("context_item_id") else [])


# ----------------------------------------------------------------------------- plain-language text


def _clip(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _basename(path: str) -> str:
    parts = [p for p in re.split(r"[\\/]", path.strip()) if p]
    return _clip(parts[-1] if parts else path, 60) or path


def _url_label(url: str) -> str:
    parts = urlsplit(url if "://" in url else f"//{url}")
    host = parts.hostname or url
    path = parts.path if parts.path not in ("", "/") else ""
    return _clip(host + path, 60) or host


def _preview(digest: Any) -> str | None:
    if not isinstance(digest, dict):
        return None
    if digest.get("preview"):
        return _clip(digest["preview"], 200)
    length = digest.get("length")
    return f"{int(length):,} characters (content previews are disabled)" if isinstance(length, int) else None


def _meta_summary(meta: Any) -> str | None:
    if not isinstance(meta, dict):
        return None
    parts = [f"{k.replace('_', ' ')}: {_clip(meta[k], 60)}" for k in ("model", "cwd", "permission_mode", "reason")
             if isinstance(meta.get(k), str | int | float) and str(meta[k]).strip()]
    return " · ".join(parts) or None


def _arg(args: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _target(category: str, inv: ToolInvocation | None, args: dict[str, Any], dest: str | None) -> tuple[str, str] | None:
    res = [r for r in ((inv.resources if inv else None) or []) if isinstance(r, dict) and r.get("id")]

    def first(*kinds: str) -> str | None:
        return next((str(r["id"]) for r in res if r.get("kind") in kinds), None)

    if category in ("file_read", "file_write"):
        path = first("file", "glob") or _arg(args, "file_path", "path", "notebook_path", "pattern")
        return ("file", _basename(path)) if path else None
    if category in ("shell", "code_execution"):
        cmd = _arg(args, "command", "cmd", "code", "script")
        return ("command", _clip(cmd, 60) or "") if cmd else None
    if category == "search":
        query = _arg(args, *_QUERY_KEYS)
        return ("query", _clip(query, 60) or "") if query else None
    url = first("url") or _arg(args, "url")
    if url:
        return "url", _url_label(url)
    if dest:
        return "dest", _clip(dest, 60) or dest
    other = first("host", "email", "channel", "table", "agent", "file")
    return ("resource", _clip(other, 60) or "") if other else None


def _phrase(name: str, target: tuple[str, str] | None) -> str:
    if not target:
        return name
    kind, label = target
    if kind == "command":
        return f"{name} `{label}`"
    if kind == "query":
        return f"{name} for “{label}”"
    return f"{name} to {label}" if kind in ("url", "dest") else f"{name} {label}"


def _tool_text(event_type: str, payload: dict[str, Any], ref: dict[str, Any], inv: ToolInvocation | None,
               tool: Tool | None, item: Any, dec: Any, dest: str | None) -> tuple[str, str | None]:
    name = tool.name if tool else str((payload.get("tool") or {}).get("name") or "Tool")
    category = tool.category if tool else "other"
    args = (inv.arguments_redacted if inv else payload.get("arguments")) or {}
    target = _target(category, inv, args if isinstance(args, dict) else {}, dest)
    phrase = _phrase(name, target)
    if event_type == "tool.requested":
        if dec is None:
            return f"Requested {phrase}", None
        explanation = _clip(dec.explanation, 300)
        if dec.enforcement == "enforced":
            return _ENFORCED.get(dec.decision, "Decided {}").format(phrase), explanation
        if dec.enforcement == "advisory":
            return _ADVISED.get(dec.decision, "Advised on {}").format(phrase), (
                f"Advisory: the integration may not honour this decision. {explanation or ''}".strip())
        return f"Observed request: {phrase}", (
            f"Policy outcome {dec.decision} recorded after the fact; nothing could be prevented. {explanation or ''}".strip())
    if event_type == "tool.failed" or payload.get("is_error"):
        return f"{phrase} failed", _clip(inv.error if inv else None, 300)
    if ref.get("executed_despite") and inv is not None:
        return (f"{phrase} ran although ContextOS returned {inv.decision}",
                f"The call was {str(ref['executed_despite']).replace('_', ' ')} when the integration reported a result.")
    template = _COMPLETED.get(category)
    title = template.format(target[1]) if template and target else f"{phrase} completed"
    if item is not None:
        summary = f"Result recorded as context: {int(item.content_length or 0):,} characters, trust {item.trust_level}."
    else:
        summary = "No result content was reported."
    return title, summary


def _describe(event_type: str, payload: dict[str, Any], ref: dict[str, Any], item: Any,
              other: bool) -> tuple[str, str | None]:
    if event_type == "session.started":
        return "Session started", _meta_summary(payload.get("metadata"))
    if event_type == "session.ended":
        return "Session ended", _meta_summary(payload.get("metadata"))
    if event_type == "prompt.submitted":
        return "User prompt submitted", _preview(payload.get("content"))
    if event_type == "context.ingested":
        return _context_title(item, payload), _context_summary(item)
    if event_type == "agent.delegated":
        d = payload.get("delegation") or {}
        if other:
            parent = (payload.get("agent") or {}).get("name") or "another agent"
            return f"Task received from {parent}", _preview(d.get("task"))
        child = (d.get("child_agent") or {}).get("name") or "another agent"
        return f"Delegated to {child}", _preview(d.get("task"))
    if event_type == "agent.message":
        msg = payload.get("message") or {}
        return f"Message from {msg.get('from_agent') or 'another agent'}", _preview(msg.get("content"))
    if event_type == "mcp.server_connected":
        src = payload.get("source") or {}
        tools = (payload.get("metadata") or {}).get("tools")
        flagged = len(ref.get("poisoned_tool_ids") or [])
        summary = f"{len(tools)} tool(s) listed" if isinstance(tools, list) else None
        if flagged:
            summary = f"{summary or 'Tools listed'}; {flagged} tool description(s) flagged by detection"
        label = _clip(src.get("display_name") or src.get("identifier"), 60)
        return (f"Connected MCP server {label}" if label else "Connected MCP server"), summary
    return event_type.replace(".", " ").capitalize(), None


def _context_title(item: Any, payload: dict[str, Any]) -> str:
    src = payload.get("source") or {}
    source_type = item.source_type if item else str(src.get("type") or "other")
    identifier = item.identifier if item else str(src.get("identifier") or "")
    display = (item.display_name if item else src.get("display_name")) or identifier
    if source_type == "user_prompt":
        return "Received user prompt"
    if source_type in ("file", "repository", "user_upload", "document"):
        label = _basename(display or identifier)
    elif source_type in ("web", "browser", "api"):
        label = _url_label(identifier or display)
    else:
        label = _clip(display, 60) or "unnamed source"
    return _SOURCE_TITLES.get(source_type, "Ingested context from {}").format(label)


def _context_summary(item: Any) -> str | None:
    if item is None:
        return None
    text = f"{int(item.content_length or 0):,} characters, {item.sensitivity}."
    detection = item.detection_summary or {}
    cats = [str(c).replace("_", " ") for c in detection.get("categories") or []]
    if detection.get("max_severity") and cats:
        text += f" Detected: {', '.join(sorted(set(cats))[:3])} ({detection['max_severity']})."
    return text
