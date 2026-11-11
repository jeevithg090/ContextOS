"""Overview lists: riskiest agents, what needs attention, recently denied or paused tool calls,
integration health and recent audit activity.

Every query is filtered by the caller's organisation and bounded by a small ``LIMIT``. Text that
came from integrations (explanations, summaries, audit details) was redacted before it was stored
and is passed through the redaction engine again here, then truncated, before it is returned.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc
from app.domain.enums import (
    SEVERITY_RANK,
    ApprovalStatus,
    Decision,
    EnforcementMode,
    IncidentStatus,
    Severity,
)
from app.engines.redaction import redact_text, redact_value
from app.engines.risk.session import risk_level_for
from app.models import (
    Agent,
    AgentSession,
    ApiKey,
    Approval,
    AuditEvent,
    Destination,
    Incident,
    Integration,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
    User,
)
from app.services.approvals_present import describe_action
from app.services.findings import ACTIVE_STATUSES
from app.services.ingestion_state import ENFORCING_INTEGRATIONS
from app.services.integrations_health import is_stale

OPEN_INCIDENT_STATUSES = frozenset({
    IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value, IncidentStatus.CONTAINED.value,
})
RISKY_AGENTS = 5
_SESSION_CANDIDATES = 10
ATTENTION_ITEMS = 5
RECENT_FINDINGS = 6
BLOCKED_ITEMS = 8
INTEGRATION_ITEMS = 20
ACTIVITY_ITEMS = 10
_TEXT_LIMIT = 300
_DETAIL_KEYS = 8
_DETAIL_STRING = 160
_PAUSING = (Decision.DENY.value, Decision.REQUIRE_APPROVAL.value)
F, Inv = SecurityFinding, ToolInvocation
_ENFORCING_NOTES = {
    "claude_code": "The PreToolUse hook asks ContextOS before each tool call and Claude Code does not run denied calls.",
    "mcp_gateway": "The gateway asks ContextOS before forwarding each MCP tool call and refuses denied ones.",
    "python_sdk": "guard() asks ContextOS before each guarded function runs; code that bypasses the guard is not covered.",
}
_REPORT_ONLY_NOTE = ("This integration only reports events: decisions returned to it are advisory and ContextOS "
                     "cannot block its tool calls.")


def clean(value: str | None, limit: int = _TEXT_LIMIT) -> str | None:
    """Redact (defence in depth: stored text is already redacted) and clip to one line."""
    if not value:
        return None
    text = " ".join(redact_text(value).text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def severity_order(column: Any) -> Any:
    """SQL sort key: critical first."""
    return case({s.value: -SEVERITY_RANK[s.value] for s in Severity}, value=column, else_=1)


def sim_filter(model: Any, include_simulated: bool) -> list[Any]:
    return [] if include_simulated else [model.is_simulation.is_(False)]


def _agent_names(db: Session, org_id: str, ids: set[str | None]) -> dict[str, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return dict(db.execute(select(Agent.id, Agent.name).where(Agent.organization_id == org_id, Agent.id.in_(wanted))).tuples().all())


def _agent_ref(agent_id: str | None, names: dict[str, str]) -> dict[str, Any] | None:
    return {"id": agent_id, "name": names.get(agent_id)} if agent_id else None


# ----------------------------------------------------------------------------- riskiest agents


def _top_factor(state: dict[str, Any]) -> dict[str, Any] | None:
    factors = [f for f in (state.get("factors") or []) if isinstance(f, dict)]
    if not factors:
        return None
    return max(factors, key=lambda f: int(f.get("weight") or 0))


def risky_agents(db: Session, org_id: str, *, include_simulated: bool) -> list[dict[str, Any]]:
    """Agents by their current risk score (the highest score among their open sessions), with the
    largest factor of that session as the reason."""
    agents = list(db.scalars(
        select(Agent).where(Agent.organization_id == org_id, Agent.risk_score > 0, *sim_filter(Agent, include_simulated))
        .order_by(Agent.risk_score.desc(), Agent.last_seen_at.desc()).limit(RISKY_AGENTS)
    ))
    if not agents:
        return []
    ids = [a.id for a in agents]
    open_counts = dict(db.execute(
        select(SecurityFinding.agent_id, func.count(SecurityFinding.id)).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.agent_id.in_(ids),
            SecurityFinding.status.in_(ACTIVE_STATUSES), *sim_filter(SecurityFinding, include_simulated),
        ).group_by(SecurityFinding.agent_id)
    ).tuples().all())
    out: list[dict[str, Any]] = []
    for agent in agents:
        candidates = list(db.scalars(
            select(AgentSession).where(
                AgentSession.organization_id == org_id, AgentSession.agent_id == agent.id,
                AgentSession.status == "active", *sim_filter(AgentSession, include_simulated),
            ).order_by(AgentSession.risk_score.desc(), AgentSession.last_event_at.desc()).limit(_SESSION_CANDIDATES)
        ))
        # Equal scores (the score is capped at 100): prefer the session with the trifecta, then the newest.
        session = max(candidates, default=None,
                      key=lambda s: (int(s.risk_score or 0), bool((s.risk_state or {}).get("trifecta"))))
        state = (session.risk_state or {}) if session is not None else {}
        factor = _top_factor(state)
        score = int(agent.risk_score or 0)
        out.append({
            "id": agent.id, "name": agent.name, "environment": agent.environment, "framework": agent.framework,
            "status": agent.status, "risk_score": score,
            "risk_level": str(state.get("level") or risk_level_for(score)),
            "reason": clean(str(factor.get("label") or ""), 120) if factor else None,
            "reason_detail": clean(str(factor.get("explanation") or "")) if factor else None,
            "session_id": session.id if session is not None else None,
            "trifecta": bool(state.get("trifecta")),
            "open_findings": int(open_counts.get(agent.id, 0)),
            "last_seen_at": agent.last_seen_at, "is_simulation": bool(agent.is_simulation),
        })
    return out


# ----------------------------------------------------------------------------- findings / attention


def _finding_items(db: Session, org_id: str, rows: list[SecurityFinding]) -> list[dict[str, Any]]:
    names = _agent_names(db, org_id, {f.agent_id for f in rows})
    return [{
        "id": f.id, "title": clean(f.title, 200) or f.rule_id, "severity": f.severity, "category": f.category,
        "status": f.status, "rule_id": f.rule_id, "agent": _agent_ref(f.agent_id, names), "session_id": f.session_id,
        "incident_id": f.incident_id, "occurrence_count": int(f.occurrence_count or 1),
        "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at, "is_simulation": bool(f.is_simulation),
    } for f in rows]


def recent_findings(db: Session, org_id: str, since: datetime, *, include_simulated: bool) -> list[dict[str, Any]]:
    rows = list(db.scalars(
        select(F).where(F.organization_id == org_id, F.status.in_(ACTIVE_STATUSES), F.last_seen_at >= since,
                        *sim_filter(F, include_simulated))
        .order_by(F.last_seen_at.desc()).limit(RECENT_FINDINGS)
    ))
    return _finding_items(db, org_id, rows)


def attention(db: Session, org_id: str, now: datetime, *, include_simulated: bool) -> dict[str, Any]:
    critical = list(db.scalars(
        select(F).where(F.organization_id == org_id, F.status.in_(ACTIVE_STATUSES),
                        F.severity.in_([Severity.CRITICAL.value, Severity.HIGH.value]), *sim_filter(F, include_simulated))
        .order_by(severity_order(F.severity), F.last_seen_at.desc()).limit(ATTENTION_ITEMS)
    ))
    approvals = db.execute(
        select(Approval, Tool.name)
        .outerjoin(ToolInvocation, (ToolInvocation.id == Approval.tool_invocation_id)
                   & (ToolInvocation.organization_id == org_id))
        .outerjoin(Tool, (Tool.id == ToolInvocation.tool_id) & (Tool.organization_id == org_id))
        .where(*pending_approval_conditions(org_id, now), *sim_filter(Approval, include_simulated))
        .order_by(Approval.requested_at.asc()).limit(ATTENTION_ITEMS)
    ).all()
    incidents = list(db.scalars(
        select(Incident).where(Incident.organization_id == org_id, Incident.status.in_(OPEN_INCIDENT_STATUSES),
                               *sim_filter(Incident, include_simulated))
        .order_by(severity_order(Incident.severity), Incident.opened_at.desc()).limit(ATTENTION_ITEMS)
    ))
    names = _agent_names(db, org_id, {a.agent_id for a, _ in approvals} | {i.primary_agent_id for i in incidents})
    return {
        "critical_findings": _finding_items(db, org_id, critical),
        "pending_approvals": [{
            "id": a.id, "summary": clean(a.summary) or "Tool call waiting for approval",
            "agent": {"id": a.agent_id, "name": names.get(a.agent_id)}, "session_id": a.session_id,
            "tool_name": tool_name, "requested_at": a.requested_at, "expires_at": a.expires_at,
            "seconds_remaining": _seconds_left(a.expires_at, now),
            "is_simulation": bool(a.is_simulation),
        } for a, tool_name in approvals],
        "open_incidents": [{
            "id": i.id, "number": int(i.number or 0), "title": clean(i.title, 200) or f"Incident {i.number}",
            "severity": i.severity, "status": i.status, "opened_at": i.opened_at,
            "primary_agent": _agent_ref(i.primary_agent_id, names), "is_simulation": bool(i.is_simulation),
        } for i in incidents],
    }


def _seconds_left(deadline: datetime | None, now: datetime) -> int | None:
    deadline = ensure_utc(deadline)
    return None if deadline is None else max(0, int((deadline - now).total_seconds()))


def pending_approval_conditions(org_id: str, now: datetime) -> list[Any]:
    """Pending and not past the deadline (overdue ones are expired lazily by the Approval Centre)."""
    return [Approval.organization_id == org_id, Approval.status == ApprovalStatus.PENDING.value,
            or_(Approval.expires_at.is_(None), Approval.expires_at > now)]


# ----------------------------------------------------------------------------- denied / paused calls


def outcome_text(decision: str, enforcement: str, status: str) -> str:
    """What actually happened to the call — only says "blocked" when an enforcing boundary acted."""
    if enforcement == EnforcementMode.OBSERVED.value:
        verb = "denied it" if decision == Decision.DENY.value else "required approval"
        return f"Policy {verb}, but the call was reported after it ran; nothing was prevented"
    advisory = enforcement == EnforcementMode.ADVISORY.value
    if decision == Decision.DENY.value:
        return "Denied; this integration may not have honoured the decision" if advisory else "Blocked before it ran"
    if status == "pending_approval":
        return "Approval requested; this integration may not wait for it" if advisory else "Paused, waiting for a human"
    if status in ("rejected", "expired", "cancelled"):
        reason = {"rejected": "Rejected by a human", "expired": "Approval timed out", "cancelled": "Approval cancelled"}
        tail = "; this integration may not have honoured it" if advisory else "; it did not run"
        return reason[status] + tail
    if status in ("approved", "completed", "failed"):
        return "Approved by a human, then released"
    return "Paused for approval"


def blocked_or_paused(db: Session, org_id: str, since: datetime, *, include_simulated: bool) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Inv, Tool, Destination.identifier, PolicyDecision.explanation)
        .join(Tool, (Tool.id == Inv.tool_id) & (Tool.organization_id == org_id))
        .outerjoin(Destination, (Destination.id == Inv.destination_id) & (Destination.organization_id == org_id))
        .outerjoin(PolicyDecision, (PolicyDecision.id == Inv.policy_decision_id) & (PolicyDecision.organization_id == org_id))
        .where(Inv.organization_id == org_id, Inv.decision.in_(_PAUSING), Inv.requested_at >= since,
               *sim_filter(Inv, include_simulated))
        .order_by(Inv.requested_at.desc()).limit(BLOCKED_ITEMS)
    ).all()
    names = _agent_names(db, org_id, {inv.agent_id for inv, *_ in rows})
    out: list[dict[str, Any]] = []
    for inv, tool, destination, explanation in rows:
        target = destination or next(
            (str(r.get("id"))[:200] for r in (inv.resources or []) if isinstance(r, dict) and r.get("id")), None)
        action = describe_action(tool.name, tool.category, inv.arguments_redacted or {}, target, destination=destination)
        out.append({
            "invocation_id": inv.id, "session_id": inv.session_id,
            "agent": {"id": inv.agent_id, "name": names.get(inv.agent_id)},
            "tool": {"name": tool.name, "category": tool.category, "server": tool.server},
            "action": clean(action, 200) or f"use {tool.name}",
            "decision": inv.decision, "enforcement": inv.enforcement, "status": inv.status,
            "outcome": outcome_text(str(inv.decision), str(inv.enforcement), str(inv.status)),
            "reason": clean(explanation), "policy_decision_id": inv.policy_decision_id,
            "approval_id": inv.approval_id, "at": inv.requested_at, "is_simulation": bool(inv.is_simulation),
        })
    return out


# ----------------------------------------------------------------------------- integrations


def _health(row: Integration, now: datetime) -> tuple[str, str]:
    last = ensure_utc(row.last_event_at)
    if row.status == "error":
        return "error", "The integration reported an error."
    if last is None:
        return "never_seen", "Registered, but no event has arrived yet."
    if is_stale(last, now):
        return "stale", "No events in the last 24 hours."
    return "connected", "Sent events in the last 24 hours."


def integrations(db: Session, org_id: str, now: datetime) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Integration).where(Integration.organization_id == org_id)
        .order_by(Integration.last_event_at.is_(None), Integration.last_event_at.desc(), Integration.kind)
        .limit(INTEGRATION_ITEMS)
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        status, reason = _health(row, now)
        capable = row.kind in ENFORCING_INTEGRATIONS
        out.append({
            "id": row.id, "kind": row.kind, "name": row.name, "status": status, "status_reason": reason,
            "last_event_at": row.last_event_at, "event_count": int(row.event_count or 0),
            "decision_count": int(row.decision_count or 0), "enforcement_capable": capable,
            "enforcement_note": _ENFORCING_NOTES.get(row.kind, _REPORT_ONLY_NOTE) if capable else _REPORT_ONLY_NOTE,
            "last_error": clean(row.last_error),
        })
    return out


# ----------------------------------------------------------------------------- audit activity


def _bounded(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _DETAIL_STRING else value[: _DETAIL_STRING - 1] + "…"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 2:
        return f"[{len(value)} items]" if isinstance(value, (list, dict)) else str(value)[:_DETAIL_STRING]
    if isinstance(value, dict):
        return {str(k)[:64]: _bounded(v, depth + 1) for k, v in list(value.items())[:_DETAIL_KEYS]}
    if isinstance(value, list):
        return [_bounded(v, depth + 1) for v in value[:_DETAIL_KEYS]]
    return str(value)[:_DETAIL_STRING]


def recent_activity(db: Session, org_id: str) -> list[dict[str, Any]]:
    entries = list(db.scalars(
        select(AuditEvent).where(AuditEvent.organization_id == org_id).order_by(AuditEvent.seq.desc()).limit(ACTIVITY_ITEMS)
    ))
    user_ids = {e.actor_id for e in entries if e.actor_type == "user" and e.actor_id}
    key_ids = {e.actor_id for e in entries if e.actor_type == "api_key" and e.actor_id}
    users = dict(db.execute(select(User.id, User.name).where(User.id.in_(user_ids))).tuples().all()) if user_ids else {}
    keys = dict(db.execute(select(ApiKey.id, ApiKey.name).where(
        ApiKey.organization_id == org_id, ApiKey.id.in_(key_ids))).tuples().all()) if key_ids else {}

    def label(e: AuditEvent) -> str:
        if e.actor_type == "user":
            return users.get(e.actor_id or "", "Former member")
        if e.actor_type == "api_key":
            name = keys.get(e.actor_id or "")
            return f"API key “{name}”" if name else "Deleted API key"
        return "ContextOS"

    out: list[dict[str, Any]] = []
    for e in entries:
        details, _ = redact_value(e.details or {})
        out.append({
            "id": e.id, "seq": e.seq, "occurred_at": e.occurred_at, "actor_type": e.actor_type, "actor_id": e.actor_id,
            "actor_label": label(e), "action": e.action, "target_type": e.target_type, "target_id": e.target_id,
            "details": _bounded(details if isinstance(details, dict) else {"value": details}),
        })
    return out
