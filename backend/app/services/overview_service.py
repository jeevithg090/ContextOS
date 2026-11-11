"""Security command centre: the organisation's current posture and what changed in a time window.

Everything is computed from persisted rows of ONE organisation (``org_id`` filters every query) with
bounded aggregate queries; no number is estimated or hard-coded. ``include_simulated`` decides
whether Simulation Lab rows (``is_simulation``) are counted; they are labelled on every list item
and their volume is always reported under ``simulated`` so the screen can say what it includes.

Definitions (also shown to the user as one-line explanations):
- agents_active: agents that reported at least one event in the window.
- sessions_active: sessions not yet ended that had activity in the window.
- trifecta_sessions: sessions with activity in the window whose recorded risk state has sensitive data
  access, untrusted content and an outbound channel together (a risk condition, not proof of an attack).
- enforcement_coverage: share of the window's policy decisions returned at an enforcing boundary.
- blocked_actions: DENY decisions in the window that an enforcing integration acted on.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.domain.enums import Decision, EnforcementMode, FindingStatus, Severity, TrustLevel
from app.models import (
    Agent,
    AgentSession,
    ApiKey,
    Approval,
    ContextItem,
    ContextSource,
    Incident,
    IngestedEvent,
    PolicyDecision,
    SecurityFinding,
    SimulationRun,
)
from app.services import overview_service_lists as lists
from app.services.findings import ACTIVE_STATUSES
from app.services.overview_service_series import Window, bucketed, points, window_for

SEVERITIES = [s.value for s in Severity]
TRUST_LEVELS = [t.value for t in TrustLevel]
DECISIONS = [d.value for d in Decision]
MODES = [m.value for m in EnforcementMode]
sim = lists.sim_filter
D, E, F = PolicyDecision, IngestedEvent, SecurityFinding


def _count(db: Session, model: Any, *conditions: Any) -> int:
    return int(db.scalar(select(func.count(model.id)).where(*conditions)) or 0)


def _exists(db: Session, model: Any, *conditions: Any) -> bool:
    return db.scalar(select(model.id).where(*conditions).limit(1)) is not None


# ----------------------------------------------------------------------------- nav counts


def nav_counts(db: Session, org_id: str) -> dict[str, int]:
    """Sidebar badges: three indexed COUNT queries over real (non-simulated) rows."""
    now = utcnow()
    return {
        "pending_approvals": _count(db, Approval, *lists.pending_approval_conditions(org_id, now),
                                    Approval.is_simulation.is_(False)),
        "open_incidents": _count(db, Incident, Incident.organization_id == org_id,
                                 Incident.status.in_(lists.OPEN_INCIDENT_STATUSES), Incident.is_simulation.is_(False)),
        "open_findings": _count(db, SecurityFinding, SecurityFinding.organization_id == org_id,
                                SecurityFinding.status.in_(ACTIVE_STATUSES), SecurityFinding.is_simulation.is_(False)),
    }


# ----------------------------------------------------------------------------- posture


def _sources_by_trust(db: Session, org_id: str, include_simulated: bool) -> dict[str, int]:
    query = select(ContextSource.trust_level, func.count(ContextSource.id)).where(ContextSource.organization_id == org_id)
    if not include_simulated:
        # Sources only ever observed by Simulation Lab traffic are left out; sources with no context
        # items yet (e.g. a connected MCP server) are kept.
        items = select(ContextItem.id).where(ContextItem.organization_id == org_id,
                                             ContextItem.source_id == ContextSource.id)
        query = query.where(or_(exists(items.where(ContextItem.is_simulation.is_(False))), ~exists(items)))
    counts = dict.fromkeys(TRUST_LEVELS, 0)
    for level, n in db.execute(query.group_by(ContextSource.trust_level)).tuples():
        counts[str(level)] = counts.get(str(level), 0) + int(n)
    return counts


def _decisions(db: Session, org_id: str, w: Window, include_simulated: bool) -> tuple[dict[str, int], dict[str, int], int]:
    by_outcome = dict.fromkeys(DECISIONS, 0)
    by_mode = dict.fromkeys(MODES, 0)
    blocked = 0
    rows = db.execute(
        select(D.decision, D.enforcement, func.count(D.id))
        .where(D.organization_id == org_id, D.evaluated_at >= w.since, *sim(D, include_simulated))
        .group_by(D.decision, D.enforcement)
    ).all()
    for decision, mode, n in rows:
        by_outcome[str(decision)] = by_outcome.get(str(decision), 0) + int(n)
        by_mode[str(mode)] = by_mode.get(str(mode), 0) + int(n)
        if decision == Decision.DENY.value and mode == EnforcementMode.ENFORCED.value:
            blocked += int(n)
    return by_outcome, by_mode, blocked


def posture(db: Session, org_id: str, w: Window, now: datetime, include_simulated: bool) -> dict[str, Any]:
    recent = func.coalesce(AgentSession.last_event_at, AgentSession.started_at)
    session_base = [AgentSession.organization_id == org_id, recent >= w.since, *sim(AgentSession, include_simulated)]
    open_rows = db.execute(
        select(SecurityFinding.severity, func.count(SecurityFinding.id)).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.status.in_(ACTIVE_STATUSES),
            *sim(SecurityFinding, include_simulated),
        ).group_by(SecurityFinding.severity)
    ).tuples()
    open_by_severity = dict.fromkeys(SEVERITIES, 0)
    for severity, n in open_rows:
        if severity in open_by_severity:
            open_by_severity[severity] += int(n)
    by_outcome, by_mode, blocked = _decisions(db, org_id, w, include_simulated)
    total = sum(by_mode.values())
    return {
        "agents_total": _count(db, Agent, Agent.organization_id == org_id, *sim(Agent, include_simulated)),
        "agents_active": _count(db, Agent, Agent.organization_id == org_id, Agent.last_seen_at >= w.since,
                                *sim(Agent, include_simulated)),
        "sessions_active": _count(db, AgentSession, *session_base, AgentSession.status == "active"),
        "trifecta_sessions": _count(db, AgentSession, *session_base,
                                    AgentSession.risk_state["trifecta"].as_boolean().is_(True)),
        "sources_by_trust": _sources_by_trust(db, org_id, include_simulated),
        "open_findings_by_severity": open_by_severity,
        "open_findings_total": sum(open_by_severity.values()),
        "pending_approvals": _count(db, Approval, *lists.pending_approval_conditions(org_id, now),
                                    *sim(Approval, include_simulated)),
        "open_incidents": _count(db, Incident, Incident.organization_id == org_id,
                                 Incident.status.in_(lists.OPEN_INCIDENT_STATUSES), *sim(Incident, include_simulated)),
        "decisions_by_outcome": by_outcome,
        "decisions_total": total,
        "enforcement_coverage": {
            "total": total, **{mode: by_mode.get(mode, 0) for mode in MODES},
            "share": round(by_mode.get(EnforcementMode.ENFORCED.value, 0) / total, 4) if total else None,
        },
        "blocked_actions": blocked,
    }


# ----------------------------------------------------------------------------- series


def series(db: Session, org_id: str, w: Window, include_simulated: bool) -> dict[str, Any]:
    events = bucketed(db, E.received_at, [E.organization_id == org_id, *sim(E, include_simulated)], w,
                      group_by=E.is_simulation)
    findings = bucketed(db, F.first_seen_at, [F.organization_id == org_id, F.status != FindingStatus.FALSE_POSITIVE.value,
                                              *sim(F, include_simulated)], w, group_by=F.severity)
    decisions = bucketed(db, D.evaluated_at, [D.organization_id == org_id, *sim(D, include_simulated)], w,
                         group_by=D.decision)
    return {
        "bucket": w.bucket,
        "events": points(w, events, {"live": False, "simulated": True}),
        "findings_by_severity": points(w, findings, {s: s for s in SEVERITIES}),
        "decisions_by_outcome": points(w, decisions, {d: d for d in DECISIONS}),
    }


# ----------------------------------------------------------------------------- onboarding / simulated share


def onboarding(db: Session, org_id: str, now: datetime) -> dict[str, bool]:
    return {
        "has_agents": _exists(db, Agent, Agent.organization_id == org_id, Agent.is_simulation.is_(False)),
        "has_api_key": _exists(db, ApiKey, ApiKey.organization_id == org_id, ApiKey.revoked_at.is_(None),
                               or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > now)),
        "has_events": _exists(db, IngestedEvent, IngestedEvent.organization_id == org_id,
                              IngestedEvent.is_simulation.is_(False)),
        "has_simulations": _exists(db, SimulationRun, SimulationRun.organization_id == org_id),
    }


def simulated_share(db: Session, org_id: str, w: Window) -> dict[str, int]:
    return {
        "events": _count(db, IngestedEvent, IngestedEvent.organization_id == org_id, IngestedEvent.is_simulation.is_(True),
                         IngestedEvent.received_at >= w.since),
        "findings": _count(db, SecurityFinding, SecurityFinding.organization_id == org_id,
                           SecurityFinding.is_simulation.is_(True), SecurityFinding.first_seen_at >= w.since),
        "decisions": _count(db, PolicyDecision, PolicyDecision.organization_id == org_id,
                            PolicyDecision.is_simulation.is_(True), PolicyDecision.evaluated_at >= w.since),
    }


# ----------------------------------------------------------------------------- overview


def overview(db: Session, org_id: str, *, window: str = "24h", include_simulated: bool = False) -> dict[str, Any]:
    now = utcnow()
    w = window_for(window, now)
    return {
        "window": w.key, "bucket": w.bucket, "since": w.since, "until": w.until, "generated_at": now,
        "include_simulated": include_simulated,
        "posture": posture(db, org_id, w, now, include_simulated),
        "series": series(db, org_id, w, include_simulated),
        "top_risky_agents": lists.risky_agents(db, org_id, include_simulated=include_simulated),
        "recent_findings": lists.recent_findings(db, org_id, w.since, include_simulated=include_simulated),
        "attention": lists.attention(db, org_id, now, include_simulated=include_simulated),
        "recent_blocked_or_paused": lists.blocked_or_paused(db, org_id, w.since, include_simulated=include_simulated),
        "integrations": lists.integrations(db, org_id, now),
        "recent_activity": lists.recent_activity(db, org_id),
        "onboarding": onboarding(db, org_id, now),
        "simulated": simulated_share(db, org_id, w),
    }
