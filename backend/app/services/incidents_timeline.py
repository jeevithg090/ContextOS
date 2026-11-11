"""The investigation timeline: one chronological view of everything recorded around an incident.

Entries are merged from the involved sessions' recorded events (redacted summaries), the incident's
findings, policy decisions, approvals and the incident's own activity feed. All timestamps are
ContextOS server times (client-reported times are untrusted). The order is the observed sequence;
it does not show that one entry caused the next.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.domain.enums import Decision
from app.models import (
    Approval,
    Incident,
    IncidentActivity,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.services.incidents_query import actor_ref, clip, involvement, user_names
from app.services.scoping import get_scoped, scoped
from app.services.sessions_service import session_timeline

ENTRY_TYPES = ("event", "finding", "policy_decision", "approval", "activity")
EVENTS_PER_SESSION = 1000
TIMELINE_NOTE = (
    "Entries are ordered by ContextOS server time. This is the observed sequence of what was recorded; it does "
    "not show that an earlier entry caused a later one."
)
_TYPE_ORDER = {t: i for i, t in enumerate(("event", "policy_decision", "approval", "finding", "activity"))}
_ACTIVITY_TITLES = {
    "created": "Incident opened", "note": "Note added", "status_change": "Status changed",
    "severity_change": "Severity changed", "assigned": "Assignment changed", "finding_linked": "Finding linked",
    "finding_status": "Finding triaged", "resolution_updated": "Resolution updated",
    "exported": "Evidence bundle exported",
}
_APPROVAL_WORDS = {"approved": "approved", "rejected": "rejected", "expired": "expired without a decision",
                   "cancelled": "cancelled"}


def _refs(**values: Any) -> dict[str, Any]:
    base: dict[str, Any] = {k: None for k in ("event_id", "session_id", "context_item_id", "tool_invocation_id",
                                              "policy_decision_id", "approval_id", "source_id", "destination_id",
                                              "finding_id")}
    base["finding_ids"] = []
    base.update({k: v for k, v in values.items() if v is not None})
    return base


def _entry(entry_id: str, type_: str, at: datetime, title: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": entry_id, "type": type_, "occurred_at": at, "title": title,
        "summary": fields.pop("summary", None), "severity": fields.pop("severity", None),
        "status": fields.pop("status", None), "decision": fields.pop("decision", None),
        "enforcement": fields.pop("enforcement", None), "trust_level": fields.pop("trust_level", None),
        "event_type": fields.pop("event_type", None), "sequence": fields.pop("sequence", None),
        "session_id": fields.pop("session_id", None), "agent_id": fields.pop("agent_id", None),
        "actor": fields.pop("actor", None), "tool_name": fields.pop("tool_name", None),
        "from_other_session": fields.pop("from_other_session", False), "refs": fields.pop("refs", _refs()),
    }


def _events(db: Session, org_id: str, session_ids: list[str]) -> tuple[list[dict[str, Any]], int, bool]:
    out: dict[str, dict[str, Any]] = {}
    total, truncated = 0, False
    for sid in session_ids:
        page = session_timeline(db, org_id, sid, limit=EVENTS_PER_SESSION, offset=0)
        total += int(page["total"])
        truncated = truncated or page["total"] > len(page["items"])
        for e in page["items"]:
            if e["id"] in out:  # a delegation event appears in both the parent's and the child's timeline
                continue
            r = e.get("refs") or {}
            tool = e.get("tool") or {}
            out[e["id"]] = _entry(
                f"event:{e['id']}", "event", e["received_at"], clip(e["title"], 300) or e["event_type"],
                summary=clip(e.get("summary"), 600), severity=e.get("severity"), decision=e.get("decision"),
                enforcement=e.get("enforcement"), trust_level=e.get("trust_level"), event_type=e["event_type"],
                sequence=e["sequence"], session_id=sid, tool_name=tool.get("name"),
                status=e.get("processing_status") if e.get("processing_status") == "error" else None,
                from_other_session=bool(e.get("from_other_session")),
                refs=_refs(event_id=e["id"], session_id=sid, context_item_id=r.get("context_item_id"),
                           tool_invocation_id=r.get("tool_invocation_id"),
                           policy_decision_id=r.get("policy_decision_id"), approval_id=r.get("approval_id"),
                           source_id=r.get("source_id"), destination_id=r.get("destination_id"),
                           finding_ids=[str(f) for f in r.get("finding_ids") or []]),
            )
    return list(out.values()), total, truncated


def _findings(findings: list[SecurityFinding]) -> list[dict[str, Any]]:
    return [_entry(
        f"finding:{f.id}", "finding", f.first_seen_at, f"Finding raised: {clip(f.title, 300)}",
        summary=clip(f.explanation, 600), severity=f.severity, status=f.status, session_id=f.session_id,
        agent_id=f.agent_id,
        refs=_refs(finding_id=f.id, session_id=f.session_id, context_item_id=f.context_item_id,
                   tool_invocation_id=f.tool_invocation_id, policy_decision_id=f.policy_decision_id,
                   source_id=f.source_id, destination_id=f.destination_id, finding_ids=[f.id]),
    ) for f in findings]


def decisions_for(db: Session, org_id: str, session_ids: list[str], extra_ids: set[str]) -> list[PolicyDecision]:
    """Policy decisions in the involved sessions plus any referenced by the incident's findings."""
    options = []
    if session_ids:
        options.append(PolicyDecision.session_id.in_(session_ids))
    if extra_ids:
        options.append(PolicyDecision.id.in_(extra_ids))
    if not options:
        return []
    return list(db.scalars(scoped(PolicyDecision, org_id).where(or_(*options))
                           .order_by(PolicyDecision.evaluated_at, PolicyDecision.id)))


def _tool_names(db: Session, org_id: str, invocation_ids: set[str]) -> dict[str, str]:
    if not invocation_ids:
        return {}
    rows = db.execute(select(ToolInvocation.id, Tool.name).join(Tool, Tool.id == ToolInvocation.tool_id).where(
        ToolInvocation.organization_id == org_id, ToolInvocation.id.in_(invocation_ids)))
    return {inv_id: name for inv_id, name in rows}


def _decisions(decisions: list[PolicyDecision], referenced: set[str], tools: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for d in decisions:
        # ALLOW decisions are already visible on their tool events; keep the ones that changed the outcome,
        # matched a monitor-mode policy, or are cited by a finding.
        if d.decision == Decision.ALLOW.value and not d.monitor_matches and d.id not in referenced:
            continue
        tool = tools.get(d.tool_invocation_id or "")
        names = [str(m.get("name")) for m in d.matched_policies or [] if isinstance(m, dict) and m.get("name")]
        title = f"Policy decision {d.decision.replace('_', ' ').lower()}" + (f" for {tool}" if tool else "")
        summary = clip(d.explanation, 600) or ""
        if names:
            summary = f"{summary} Matched: {', '.join(names[:5])}.".strip()
        out.append(_entry(
            f"policy_decision:{d.id}", "policy_decision", d.evaluated_at, title, summary=summary,
            decision=d.decision, enforcement=d.enforcement, session_id=d.session_id, agent_id=d.agent_id,
            tool_name=tool,
            refs=_refs(policy_decision_id=d.id, session_id=d.session_id, tool_invocation_id=d.tool_invocation_id,
                       event_id=d.event_id),
        ))
    return out


def _approvals(db: Session, org_id: str, session_ids: list[str], names: dict[str, str]) -> list[dict[str, Any]]:
    if not session_ids:
        return []
    rows = list(db.scalars(scoped(Approval, org_id).where(Approval.session_id.in_(session_ids))))
    names.update(user_names(db, org_id, {a.decided_by_user_id for a in rows if a.decided_by_user_id} - set(names)))
    out = []
    for a in rows:
        refs = _refs(approval_id=a.id, session_id=a.session_id, policy_decision_id=a.policy_decision_id,
                     tool_invocation_id=a.tool_invocation_id)
        out.append(_entry(f"approval:{a.id}:requested", "approval", a.requested_at, "Approval requested",
                          summary=clip(a.summary, 600), status="pending", session_id=a.session_id,
                          agent_id=a.agent_id, refs=refs))
        if a.status != "pending" and a.decided_at is not None:
            who = actor_ref(a.decided_by_user_id, names) if a.decided_by_user_id else None
            by = f" by {who['name']}" if who else ""
            out.append(_entry(f"approval:{a.id}:decided", "approval", a.decided_at,
                              f"Approval {_APPROVAL_WORDS.get(a.status, a.status)}{by}",
                              summary=clip(a.decision_note, 600), status=a.status, session_id=a.session_id,
                              agent_id=a.agent_id, actor=who, refs=refs))
    return out


def _activity(db: Session, org_id: str, incident: Incident, names: dict[str, str]) -> list[dict[str, Any]]:
    rows = list(db.scalars(scoped(IncidentActivity, org_id).where(IncidentActivity.incident_id == incident.id)))
    names.update(user_names(db, org_id, {r.actor for r in rows} - set(names)))
    out = []
    for r in rows:
        details = r.details or {}
        fid = details.get("finding_id")
        out.append(_entry(
            f"activity:{r.id}", "activity", r.created_at, _ACTIVITY_TITLES.get(r.kind, r.kind.replace("_", " ")),
            summary=clip(r.body, 600), actor=actor_ref(r.actor, names),
            status=str(details.get("to")) if r.kind in ("status_change", "finding_status") and details.get("to") else None,
            refs=_refs(finding_id=str(fid) if fid else None, finding_ids=[str(fid)] if fid else []),
        ))
    return out


def _sort_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (entry["occurred_at"], _TYPE_ORDER.get(entry["type"], 9), entry["sequence"] or 0, entry["id"])


def incident_timeline(db: Session, org_id: str, incident_id: str, *, types: list[str] | None = None,
                      limit: int = 500) -> dict[str, Any]:
    incident = get_scoped(db, Incident, incident_id, org_id, label="Incident")
    inv = involvement(db, org_id, incident)
    session_ids = inv.session_ids
    names: dict[str, str] = {}
    events, event_total, events_truncated = _events(db, org_id, session_ids)
    decisions = decisions_for(db, org_id, session_ids, inv.policy_decisions)
    tools = _tool_names(db, org_id, {d.tool_invocation_id for d in decisions if d.tool_invocation_id})
    entries = (events + _findings(inv.findings) + _decisions(decisions, inv.policy_decisions, tools)
               + _approvals(db, org_id, session_ids, names) + _activity(db, org_id, incident, names))
    counts = {t: 0 for t in ENTRY_TYPES}
    for e in entries:
        counts[e["type"]] += 1
    wanted = set(types or ENTRY_TYPES)
    selected = sorted((e for e in entries if e["type"] in wanted), key=_sort_key)
    return {
        "incident_id": incident.id,
        "items": selected[:limit],
        "total": len(selected),
        "truncated": len(selected) > limit or events_truncated,
        "counts": counts,
        "session_ids": session_ids,
        "recorded_event_count": event_total,
        "note": TIMELINE_NOTE,
    }
