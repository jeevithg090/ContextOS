"""Replay Lab: a session's recorded events as replayable steps, and counterfactual policy replay.

    session_replay(db, org_id, session_id, *, limit, offset, decision_id=None) -> dict
        Steps from ``IngestedEvent`` in server sequence order (the same events as the session
        timeline), each with its redacted title/summary, references, the recorded outcome
        (decision, enforcement, approval status), the findings it raised and ``risk_after``:
        session risk recomputed over the prefix of recorded signals (see replay_service_risk).

    counterfactual(db, org_id, body) -> dict        (replay_service_counterfactual)
        A SIMULATION: every recorded policy decision of the session re-evaluated against its stored
        ``input_snapshot`` under a hypothetical policy set. Nothing is persisted.

Everything is read from the caller's organisation (404 for other organisations' sessions) and from
rows that were redacted before they were stored; nothing here reconstructs missing history.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc, utcnow
from app.domain.enums import ApprovalStatus
from app.models import Agent, AgentSession, Approval, IngestedEvent, PolicyDecision, SecurityFinding
from app.services.replay_service_counterfactual import counterfactual
from app.services.replay_service_risk import RISK_NOTE, TimelinePoint, risk_brief, risk_progression
from app.services.scoping import get_scoped, scoped
from app.services.sessions_service import _entries as timeline_entries  # noqa: PLC2701 - shared timeline wording
from app.services.sessions_service import agent_ref, risk_flags, timeline_query

__all__ = ["BASIS", "counterfactual", "session_replay"]

BASIS = (
    "Steps are this session's recorded events (IngestedEvent) in server sequence order — the order ContextOS "
    "received them — including events recorded in another session that delivered content into this one. "
    "Content is shown only in its redacted form. Decisions, enforcement modes, approvals and findings are the "
    "recorded outcomes; risk after each step is recomputed from recorded events."
)


def _session_meta(session: AgentSession, agent: Agent) -> dict[str, Any]:
    flags = risk_flags(session)
    return {
        "id": session.id, "external_session_id": session.external_session_id, "agent": agent_ref(agent),
        "parent_session_id": session.parent_session_id, "status": session.status,
        "started_at": session.started_at, "ended_at": session.ended_at, "last_event_at": session.last_event_at,
        "event_count": session.event_count or 0, "risk_score": flags["risk_score"],
        "risk_level": flags["risk_level"], "trifecta": flags["trifecta"], "is_simulation": session.is_simulation,
    }


def _points(db: Session, org_id: str, session: AgentSession, agent: Agent) -> list[TimelinePoint]:
    query = timeline_query(org_id, session, agent.name).with_only_columns(
        IngestedEvent.id, IngestedEvent.received_at, IngestedEvent.refs
    ).order_by(IngestedEvent.sequence)
    return [TimelinePoint(id=r.id, received_at=r.received_at, refs=r.refs or {}) for r in db.execute(query).all()]


def _focus_position(db: Session, org_id: str, session: AgentSession, decision_id: str | None,
                    points: list[TimelinePoint]) -> int | None:
    if not decision_id:
        return None
    event_id = db.scalar(select(PolicyDecision.event_id).where(
        PolicyDecision.organization_id == org_id, PolicyDecision.id == decision_id,
        PolicyDecision.session_id == session.id))
    if not event_id:
        return None
    return next((i for i, p in enumerate(points) if p.id == event_id), None)


def _approval_status(row: Any) -> str:
    """Display status without side effects: a pending approval past its deadline reads as expired."""
    expires = ensure_utc(row.expires_at)
    if row.status == ApprovalStatus.PENDING and expires is not None and expires <= utcnow():
        return ApprovalStatus.EXPIRED.value
    return str(row.status)


def _outcomes(db: Session, org_id: str, decision_ids: set[str]) -> dict[str, dict[str, Any]]:
    if not decision_ids:
        return {}
    decisions = db.execute(
        select(PolicyDecision.id, PolicyDecision.decision, PolicyDecision.enforcement, PolicyDecision.explanation,
               PolicyDecision.matched_policies)
        .where(PolicyDecision.organization_id == org_id, PolicyDecision.id.in_(decision_ids))
    ).all()
    approvals = {a.policy_decision_id: a for a in db.execute(
        select(Approval.id, Approval.policy_decision_id, Approval.status, Approval.expires_at)
        .where(Approval.organization_id == org_id, Approval.policy_decision_id.in_(decision_ids))
    ).all()}
    out: dict[str, dict[str, Any]] = {}
    for d in decisions:
        approval = approvals.get(d.id)
        matched = [str(m.get("name")) for m in (d.matched_policies or []) if isinstance(m, dict) and m.get("name")]
        out[d.id] = {
            "policy_decision_id": d.id, "decision": d.decision, "enforcement": d.enforcement,
            "explanation": d.explanation or "", "matched_policies": matched,
            "approval_id": approval.id if approval else None,
            "approval_status": _approval_status(approval) if approval else None,
        }
    return out


def _findings(db: Session, org_id: str, ids: set[str]) -> dict[str, dict[str, Any]]:
    if not ids:
        return {}
    return {f.id: {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category, "status": f.status}
            for f in db.execute(
                select(SecurityFinding.id, SecurityFinding.title, SecurityFinding.severity, SecurityFinding.category,
                       SecurityFinding.status)
                .where(SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(ids))
            ).all()}


def _recorded_risk(refs: dict[str, Any]) -> dict[str, Any] | None:
    risk = refs.get("risk")
    if not isinstance(risk, dict) or not isinstance(risk.get("score"), int):
        return None
    return {"score": risk["score"], "level": str(risk.get("level") or "low"), "trifecta": bool(risk.get("trifecta"))}


def session_replay(db: Session, org_id: str, session_id: str, *, limit: int, offset: int,
                   decision_id: str | None = None) -> dict[str, Any]:
    """One window of the session's recorded steps. With ``decision_id`` the window that contains that
    decision's event is returned (``offset`` is ignored) and ``focus_index`` points at it."""
    session = get_scoped(db, AgentSession, session_id, org_id, label="Session")
    agent = get_scoped(db, Agent, session.agent_id, org_id, label="Agent")
    points = _points(db, org_id, session, agent)
    focus = _focus_position(db, org_id, session, decision_id, points)
    if focus is not None:
        offset = (focus // limit) * limit
    window_ids = [p.id for p in points[offset:offset + limit]]
    rows_by_id = {r.id: r for r in db.scalars(scoped(IngestedEvent, org_id).where(IngestedEvent.id.in_(window_ids)))}
    rows = [rows_by_id[i] for i in window_ids if i in rows_by_id]
    risks = risk_progression(db, org_id, session, agent, points, upto=offset + len(rows))
    entries = timeline_entries(db, org_id, session, rows)

    outcomes = _outcomes(db, org_id, {str(e["refs"]["policy_decision_id"]) for e in entries
                                      if e["refs"].get("policy_decision_id")})
    findings = _findings(db, org_id, {str(f) for e in entries for f in e["refs"].get("finding_ids") or []})
    steps = []
    for k, (row, entry) in enumerate(zip(rows, entries, strict=True)):
        index = offset + k
        refs = row.refs or {}
        decision = entry["refs"].get("policy_decision_id")
        steps.append({
            "index": index, "sequence": entry["sequence"], "event_id": entry["id"], "event_type": entry["event_type"],
            "received_at": entry["received_at"], "occurred_at": entry["occurred_at"], "title": entry["title"],
            "summary": entry["summary"], "processing_status": entry["processing_status"],
            "from_other_session": entry["from_other_session"], "trust_level": entry["trust_level"],
            "tool": entry["tool"], "refs": entry["refs"],
            "outcome": outcomes.get(str(decision)) if decision else None,
            "findings": [findings[str(f)] for f in entry["refs"].get("finding_ids") or [] if str(f) in findings],
            "risk_after": risk_brief(risks[index], risks[index - 1] if index > 0 else None),
            "recorded_risk": _recorded_risk(refs) if decision else None,
        })
    decision_steps = sum(1 for p in points if p.refs.get("policy_decision_id"))
    return {
        "session": _session_meta(session, agent), "basis": BASIS, "risk_note": RISK_NOTE,
        "total_steps": len(points), "decision_steps": decision_steps, "offset": offset, "limit": limit,
        "truncated": offset + len(rows) < len(points), "focus_index": focus, "steps": steps,
    }
