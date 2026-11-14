"""Session risk progression for the Replay Lab: ``risk.compute_session_risk`` over each prefix of a
session's recorded events.

The value at step *k* is RECOMPUTED from what was recorded up to and including that step — it is not
the value the pipeline held at the time, and is always labelled "recomputed from recorded events":

* context items count from the event that recorded them, with the trust recorded on the item when it
  was received (later source reclassification is not applied);
* tool calls count from their request event, with the status they had at that step (initial status
  from the recorded decision and enforcement, the approval outcome once the approval was decided, the
  final completed/failed status from the result event on);
* a destination's classification is the one recorded in the decision's input snapshot when present;
* findings count as open from the first step that raised them (later triage is not applied);
* the agent's declared tools are its current declaration; risk inherited from related sessions is
  not included.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc
from app.domain.enums import TRUST_RANK, ApprovalStatus, Decision, TrustLevel
from app.engines.risk import SessionRisk, SessionSignals, classify_tool, compute_session_risk
from app.models import (
    Agent,
    AgentSession,
    Approval,
    ContextItem,
    ContextSource,
    Destination,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
)

RISK_NOTE = (
    "Recomputed with the current risk engine from what was recorded up to each step: context trust as "
    "recorded when each item was received, tool-call status as of that step, destination classification "
    "from the recorded decision input, findings counted as open from the step that raised them, and the "
    "agent's current declared tools. Risk inherited from related sessions and later triage are not "
    "applied, so values can differ from the live score shown for the session."
)

# Mirrors the ingestion pipeline (services/ingestion_tools.py and services/approvals.py).
_STATUS_BY_DECISION = {
    Decision.ALLOW.value: "allowed",
    Decision.AUDIT.value: "allowed",
    Decision.RESTRICT.value: "restricted",
    Decision.DENY.value: "denied",
    Decision.REQUIRE_APPROVAL.value: "pending_approval",
}
_STATUS_BY_APPROVAL = {
    ApprovalStatus.APPROVED.value: "approved",
    ApprovalStatus.REJECTED.value: "rejected",
    ApprovalStatus.EXPIRED.value: "expired",
}


@dataclass
class TimelinePoint:
    """The minimum of one recorded event needed to rebuild signals at that step."""

    id: str
    received_at: datetime
    refs: dict[str, Any]


@dataclass
class _Inv:
    id: str
    signal: dict[str, Any]  # SessionSignals.tool_invocations entry; "status" is updated per step
    final_status: str
    initial_status: str
    req_pos: int
    res_pos: int | None
    approval_status: str | None
    approval_decided_at: datetime | None

    def status_at(self, pos: int, at: datetime) -> str:
        if self.res_pos is not None and self.res_pos <= pos:
            return self.final_status
        if (
            self.approval_status in _STATUS_BY_APPROVAL
            and self.approval_decided_at
            and self.approval_decided_at <= at
        ):
            return _STATUS_BY_APPROVAL[self.approval_status]
        return self.initial_status


def _items_by_pos(
    db: Session, org_id: str, session_id: str, positions: dict[str, int]
) -> dict[int, list[dict[str, Any]]]:
    rows = db.execute(
        select(
            ContextItem.id,
            ContextItem.event_id,
            ContextItem.trust_level,
            ContextItem.source_id,
            ContextItem.contains_secrets,
            ContextItem.sensitivity,
            ContextItem.detection_summary,
            ContextSource.source_type,
        )
        .join(ContextSource, ContextSource.id == ContextItem.source_id)
        .where(ContextItem.organization_id == org_id, ContextItem.session_id == session_id)
    ).all()
    out: dict[int, list[dict[str, Any]]] = {}
    for r in rows:
        pos = positions.get(r.event_id)
        if pos is None:
            continue
        summary = r.detection_summary or {}
        level = r.trust_level if r.trust_level in TRUST_RANK else TrustLevel.UNKNOWN.value
        out.setdefault(pos, []).append(
            {
                "id": r.id,
                "trust_level": level,
                "source_type": r.source_type,
                "source_id": r.source_id,
                "contains_secrets": bool(r.contains_secrets),
                "sensitivity": r.sensitivity,
                "detection_max_severity": summary.get("max_severity"),
                "detection_categories": list(summary.get("categories") or []),
            }
        )
    return out


def _invocations(db: Session, org_id: str, session_id: str, positions: dict[str, int]) -> list[_Inv]:
    rows = db.execute(
        select(
            ToolInvocation.id,
            ToolInvocation.request_event_id,
            ToolInvocation.result_event_id,
            ToolInvocation.status,
            ToolInvocation.decision,
            ToolInvocation.enforcement,
            ToolInvocation.resources,
            ToolInvocation.destination_id,
            ToolInvocation.sensitive_data_detected,
            ToolInvocation.matched_session_fingerprints,
            ToolInvocation.arguments_redacted,
            ToolInvocation.policy_decision_id,
            ToolInvocation.approval_id,
            Tool.name.label("tool_name"),
            Tool.category,
            Tool.provider,
            Tool.server,
            Destination.classification.label("destination_classification"),
        )
        .join(Tool, Tool.id == ToolInvocation.tool_id)
        .outerjoin(Destination, Destination.id == ToolInvocation.destination_id)
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.session_id == session_id)
    ).all()
    decision_ids = [r.policy_decision_id for r in rows if r.policy_decision_id]
    recorded_dest: dict[str, Any] = {}
    if decision_ids:
        recorded_dest = dict(
            db.execute(
                select(
                    PolicyDecision.id,
                    PolicyDecision.input_snapshot["destination"]["classification"].as_string(),
                ).where(PolicyDecision.organization_id == org_id, PolicyDecision.id.in_(decision_ids))
            ).all()
        )
    approval_ids = [r.approval_id for r in rows if r.approval_id]
    approvals: dict[str, tuple[str, datetime | None]] = {}
    if approval_ids:
        approvals = {
            a.id: (a.status, ensure_utc(a.decided_at))
            for a in db.execute(
                select(Approval.id, Approval.status, Approval.decided_at).where(
                    Approval.organization_id == org_id, Approval.id.in_(approval_ids)
                )
            ).all()
        }

    out: list[_Inv] = []
    for r in rows:
        req_pos = positions.get(r.request_event_id or "")
        res_pos = positions.get(r.result_event_id or "")
        if req_pos is None:
            req_pos = res_pos
        if req_pos is None:
            continue
        outbound = (
            bool(r.destination_id)
            or classify_tool(
                r.tool_name, r.provider, server=r.server, arguments=r.arguments_redacted or {}
            ).outbound
        )
        initial = (
            "requested"
            if r.enforcement == "observed"
            else _STATUS_BY_DECISION.get(str(r.decision), "allowed")
        )
        approval = approvals.get(r.approval_id or "", (None, None))
        signal = {
            "id": r.id,
            "tool_name": r.tool_name,
            "category": r.category,
            "status": initial,
            "decision": r.decision,
            "sensitive_resources": [
                x.get("id") for x in (r.resources or []) if isinstance(x, dict) and x.get("sensitive")
            ],
            "destination_classification": recorded_dest.get(r.policy_decision_id or "")
            or r.destination_classification,
            "outbound": outbound,
            "sensitive_data_detected": bool(r.sensitive_data_detected),
            "matched_session_fingerprints": list(r.matched_session_fingerprints or []),
        }
        out.append(
            _Inv(
                id=r.id,
                signal=signal,
                final_status=r.status,
                initial_status=initial,
                req_pos=req_pos,
                res_pos=res_pos,
                approval_status=approval[0],
                approval_decided_at=approval[1],
            )
        )
    return out


def _findings_by_pos(
    db: Session, org_id: str, session_id: str, points: list[TimelinePoint]
) -> dict[int, list[dict[str, Any]]]:
    first_pos: dict[str, int] = {}
    for pos, point in enumerate(points):
        for fid in point.refs.get("finding_ids") or []:
            first_pos.setdefault(str(fid), pos)
    if not first_pos:
        return {}
    rows = db.execute(
        select(SecurityFinding.id, SecurityFinding.category, SecurityFinding.severity).where(
            SecurityFinding.organization_id == org_id,
            SecurityFinding.session_id == session_id,
            SecurityFinding.id.in_(list(first_pos)),
        )
    ).all()
    out: dict[int, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(first_pos[r.id], []).append(
            {"id": r.id, "category": r.category, "severity": r.severity, "status": "open"}
        )
    return out


def risk_progression(
    db: Session, org_id: str, session: AgentSession, agent: Agent, points: list[TimelinePoint], *, upto: int
) -> list[SessionRisk]:
    """Recomputed session risk after each of the first ``upto`` recorded events (in order)."""
    upto = min(upto, len(points))
    if upto <= 0:
        return []
    positions = {p.id: i for i, p in enumerate(points)}
    items_at = _items_by_pos(db, org_id, session.id, positions)
    invocations = _invocations(db, org_id, session.id, positions)
    findings_at = _findings_by_pos(db, org_id, session.id, points)
    declared = [t for t in ((agent.declared_capabilities or {}).get("tools") or []) if isinstance(t, dict)]
    decided_at = sorted(i.approval_decided_at for i in invocations if i.approval_decided_at)

    items: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    active: list[_Inv] = []
    results: list[SessionRisk] = []
    previous_at: datetime | None = None
    risk: SessionRisk | None = None
    for pos in range(upto):
        at = ensure_utc(points[pos].received_at) or points[pos].received_at
        dirty = risk is None
        if pos in items_at:
            items = items_at[pos] + items
            dirty = True
        if pos in findings_at:
            findings = findings + findings_at[pos]
            dirty = True
        started = [i for i in invocations if i.req_pos == pos]
        if started:
            active = started + active
            dirty = True
        if any(i.res_pos == pos for i in active):
            dirty = True
        if any((previous_at is None or d > previous_at) and d <= at for d in decided_at):
            dirty = True
        if dirty:
            calls = []
            for inv in active:
                inv.signal["status"] = inv.status_at(pos, at)
                calls.append(dict(inv.signal))
            risk = compute_session_risk(
                SessionSignals(
                    context_items=list(items),
                    tool_invocations=calls,
                    declared_tools=declared,
                    findings=list(findings),
                )
            )
        assert risk is not None
        results.append(risk)
        previous_at = at
    return results


def risk_brief(risk: SessionRisk, previous: SessionRisk | None) -> dict[str, Any]:
    return {
        "score": risk.score,
        "level": risk.level,
        "delta": risk.score - (previous.score if previous else 0),
        "trifecta": risk.trifecta,
        "sensitive_access": risk.sensitive_access,
        "untrusted_exposure": risk.untrusted_exposure,
        "outbound_channel": risk.outbound_channel,
        "summary": risk.summary,
        "factors": [{"key": f.key, "label": f.label, "weight": f.weight} for f in risk.factors],
    }
