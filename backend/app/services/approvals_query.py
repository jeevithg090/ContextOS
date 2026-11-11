"""Read side of the Approval Centre: the queue, history and the evidence behind one approval.

Every query is scoped to the caller's organisation (other organisations' ids are "not found"); an
API key bound to one agent only sees that agent's approvals. Everything returned comes from
persisted rows: the approval, its tool invocation (already redacted at ingestion), the policy
decision and its recorded input snapshot, and the session's recorded risk state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.core.timeutil import utcnow
from app.domain.enums import SEVERITY_RANK, ApprovalStatus, TrustLevel
from app.models import (
    Agent,
    AgentSession,
    Approval,
    AuditEvent,
    ContextItem,
    ContextSource,
    Destination,
    PolicyDecision,
    SecurityFinding,
    SecurityPolicy,
    Tool,
    ToolInvocation,
    User,
)
from app.services.approvals_present import (
    describe_action,
    enforcement_note,
    matched_policy,
    risk_summary,
    session_risk,
)

RISKY_DESTINATIONS = {TrustLevel.SUSPICIOUS.value, TrustLevel.BLOCKED.value}
_TARGET_KINDS = ("file", "url", "command", "email", "channel", "table", "agent")
LIST_RESOURCES = 5
RECENT_CONTEXT = 12
RELATED_FINDINGS = 20
PREVIEW_CHARS = 280


@dataclass
class ApprovalFilters:
    statuses: list[str]
    include_simulated: bool = False
    agent_id: str | None = None
    session_id: str | None = None
    bound_agent_id: str | None = None


def _query(org_id: str) -> Select[Any]:
    return (
        select(Approval, Agent, AgentSession, ToolInvocation, Tool, PolicyDecision, Destination, User)
        .outerjoin(Agent, and_(Agent.id == Approval.agent_id, Agent.organization_id == org_id))
        .outerjoin(AgentSession, and_(AgentSession.id == Approval.session_id, AgentSession.organization_id == org_id))
        .outerjoin(ToolInvocation, and_(ToolInvocation.id == Approval.tool_invocation_id,
                                        ToolInvocation.organization_id == org_id))
        .outerjoin(Tool, and_(Tool.id == ToolInvocation.tool_id, Tool.organization_id == org_id))
        .outerjoin(PolicyDecision, and_(PolicyDecision.id == Approval.policy_decision_id,
                                        PolicyDecision.organization_id == org_id))
        .outerjoin(Destination, and_(Destination.id == ToolInvocation.destination_id,
                                     Destination.organization_id == org_id))
        .outerjoin(User, User.id == Approval.decided_by_user_id)
        .where(Approval.organization_id == org_id)
    )


def _conditions(org_id: str, f: ApprovalFilters) -> list[Any]:
    conds: list[Any] = [Approval.organization_id == org_id]
    if f.statuses:
        conds.append(Approval.status.in_(f.statuses))
    if not f.include_simulated:
        conds.append(Approval.is_simulation.is_(False))
    if f.agent_id:
        conds.append(Approval.agent_id == f.agent_id)
    if f.session_id:
        conds.append(Approval.session_id == f.session_id)
    if f.bound_agent_id:
        conds.append(Approval.agent_id == f.bound_agent_id)
    return conds


def list_approvals(
    db: Session, org_id: str, filters: ApprovalFilters, *, sort: str | None, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    """The queue (pending, oldest first: closest to timing out) or the history (latest decision first)."""
    conds = _conditions(org_id, filters)
    total = int(db.scalar(select(func.count()).select_from(Approval).where(*conds)) or 0)
    if sort is None:
        sort = "oldest" if set(filters.statuses) == {ApprovalStatus.PENDING.value} else "recently_decided"
    if sort == "oldest":
        order = (Approval.requested_at.asc(), Approval.id.asc())
    elif sort == "newest":
        order = (Approval.requested_at.desc(), Approval.id.desc())
    else:
        order = (func.coalesce(Approval.decided_at, Approval.requested_at).desc(), Approval.id.desc())
    rows = db.execute(_query(org_id).where(*conds[1:]).order_by(*order).limit(limit).offset(offset)).all()
    now = utcnow()
    return [_item(row, now) for row in rows], total


def _resource(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or raw.get("id") is None:
        return None
    return {"kind": str(raw.get("kind") or "other"), "id": str(raw["id"])[:2048],
            "sensitive": bool(raw.get("sensitive")), "reason": raw.get("reason")}


def _resources(inv: ToolInvocation | None) -> list[dict[str, Any]]:
    if inv is None:
        return []
    return [r for r in (_resource(x) for x in (inv.resources or [])) if r is not None]


def _primary_target(dest: Destination | None, resources: list[dict[str, Any]]) -> str | None:
    if dest is not None:
        return dest.identifier
    for res in resources:
        if res["kind"] in _TARGET_KINDS:
            return res["id"][:200]
    return resources[0]["id"][:200] if resources else None


def _confirmation(approval_risk: dict[str, Any], dest: dict[str, Any] | None) -> list[str]:
    reasons: list[str] = []
    if dest is not None:
        levels = {dest["classification"], dest.get("classification_at_decision")} & RISKY_DESTINATIONS
        if levels:
            reasons.append(f"The destination {dest['identifier']} is classified {sorted(levels)[0]}.")
    if approval_risk["secrets_in_arguments"]:
        n = approval_risk["secrets_in_arguments"]
        reasons.append(f"The arguments contain {n} credential{'s' if n != 1 else ''} (shown redacted here; "
                       "the agent would send the real value).")
    if approval_risk["session_secret_matches"]:
        reasons.append("A credential in the arguments was previously seen in this session's context, so approving "
                       "may let it leave the environment.")
    return reasons


def _item(row: Any, now: datetime) -> dict[str, Any]:
    approval: Approval = row[0]
    agent, session, inv, tool, decision, dest, user = row[1:]
    snapshot = (decision.input_snapshot or {}) if decision is not None else {}
    snap_tool = snapshot.get("tool") or {}
    resources = _resources(inv)
    risk = risk_summary(approval.risk_summary or {})
    destination = None
    if dest is not None:
        destination = {"id": dest.id, "kind": dest.kind, "identifier": dest.identifier,
                       "classification": dest.classification,
                       "classification_at_decision": (snapshot.get("destination") or {}).get("classification")
                       or risk["destination_classification"]}
    primary = _primary_target(dest, resources)
    tool_name = tool.name if tool is not None else snap_tool.get("name")
    category = (tool.category if tool is not None else None) or snap_tool.get("category") or risk["tool_category"]
    matched = [matched_policy(m) for m in (decision.matched_policies or [])] if decision is not None else []
    reasons = _confirmation(risk, destination)
    remaining = None
    if approval.status == ApprovalStatus.PENDING and approval.expires_at is not None:
        remaining = max(0, int((approval.expires_at - now).total_seconds()))
    return {
        "id": approval.id, "status": approval.status, "summary": approval.summary,
        "action": describe_action(tool_name, category, inv.arguments_redacted if inv is not None else {}, primary,
                                  destination=dest.identifier if dest is not None else None),
        "agent": {"id": approval.agent_id, "name": agent.name if agent else None,
                  "environment": agent.environment if agent else None},
        "session": {"id": approval.session_id, "external_session_id": session.external_session_id if session else None,
                    "status": session.status if session else None},
        "tool": {"name": tool_name, "category": category,
                 "provider": tool.provider if tool is not None else snap_tool.get("provider"),
                 "server": tool.server if tool is not None else snap_tool.get("server"),
                 "risk_level": snap_tool.get("risk_level") or (tool.risk_level if tool is not None else None)},
        "tool_invocation_id": approval.tool_invocation_id,
        "tool_invocation_status": inv.status if inv is not None else None,
        "target": {"primary": primary, "destination": destination, "resources": resources[:LIST_RESOURCES],
                   "resource_count": len(resources),
                   "sensitive_resource_count": sum(1 for r in resources if r["sensitive"])},
        "policy_decision": None if decision is None else {
            "id": decision.id, "decision": decision.decision, "enforcement": decision.enforcement,
            "explanation": decision.explanation, "evaluated_at": decision.evaluated_at,
            "deciding_policy": matched[0] if matched else None, "matched_policies": matched,
        },
        "risk": risk,
        "requires_confirmation": bool(reasons), "confirmation_reasons": reasons,
        "requested_at": approval.requested_at, "expires_at": approval.expires_at, "seconds_remaining": remaining,
        "decided_at": approval.decided_at,
        "decided_by": {"id": user.id, "name": user.name, "email": user.email} if user is not None else None,
        "decision_note": approval.decision_note, "is_simulation": bool(approval.is_simulation),
    }


# -- detail ----------------------------------------------------------------------------------------


def load_approval(db: Session, org_id: str, approval_id: str, *, bound_agent_id: str | None = None) -> Approval:
    approval = db.scalar(select(Approval).where(Approval.organization_id == org_id, Approval.id == approval_id))
    if approval is None or (bound_agent_id and approval.agent_id != bound_agent_id):
        raise NotFoundError(f"Approval '{approval_id}' not found")
    return approval


def approval_detail(db: Session, org_id: str, approval_id: str, *, bound_agent_id: str | None = None) -> dict[str, Any]:
    row = db.execute(_query(org_id).where(Approval.id == approval_id)).first()
    if row is None or (bound_agent_id and row[0].agent_id != bound_agent_id):
        raise NotFoundError(f"Approval '{approval_id}' not found")
    approval: Approval = row[0]
    session: AgentSession | None = row[2]
    inv: ToolInvocation | None = row[3]
    decision: PolicyDecision | None = row[5]
    dest: Destination | None = row[6]
    out = _item(row, utcnow())
    snapshot = (decision.input_snapshot or {}) if decision is not None else {}

    policies = _policy_rows(db, org_id, decision)
    for match in ([out["policy_decision"]["deciding_policy"]] if out["policy_decision"] else []) + (
            out["policy_decision"]["matched_policies"] if out["policy_decision"] else []):
        if match is not None:
            _annotate(match, policies)
    monitor = [matched_policy(m) for m in (decision.monitor_matches or [])] if decision is not None else []
    for match in monitor:
        _annotate(match, policies)

    resources = _resources(inv)
    out.update(
        arguments=(inv.arguments_redacted or {}) if inv is not None else {},
        argument_hash=inv.argument_hash if inv is not None else None,
        resources=resources,
        destination=_destination_detail(dest, out["target"]["destination"]),
        secrets={
            "in_arguments": [{"type": str(s.get("type") or "secret")} for s in snapshot.get("secrets_in_arguments") or []
                             if isinstance(s, dict)],
            "from_session_context": [
                {"type": str(m.get("type") or "secret"), "context_item_id": m.get("context_item_id")}
                for m in ((inv.matched_session_fingerprints or []) if inv is not None else []) if isinstance(m, dict)],
        },
        detection={"rule_ids": list((snapshot.get("detection") or {}).get("rule_ids") or []),
                   "max_severity": (snapshot.get("detection") or {}).get("max_severity"),
                   "categories": list((snapshot.get("detection") or {}).get("categories") or [])},
        monitor_matches=monitor,
        session_risk=session_risk(snapshot, session.risk_state if session is not None else None,
                                  session.risk_score if session is not None else 0),
        enforcement_note=enforcement_note(
            status=approval.status, enforcement=decision.enforcement if decision is not None else None,
            integration=(snapshot.get("integration") or {}).get("kind"),
            invocation_status=inv.status if inv is not None else None,
            ran_before_decision=bool(inv is not None and inv.completed_at is not None and approval.decided_at is not None
                                     and inv.completed_at < approval.decided_at)),
        activity=_activity(db, org_id, approval),
    )
    out["recent_context"], out["context_total"] = _recent_context(db, org_id, approval)
    out["related_findings"] = _related_findings(db, org_id, approval, decision)
    return out


def _policy_rows(db: Session, org_id: str, decision: PolicyDecision | None) -> dict[str, SecurityPolicy]:
    if decision is None:
        return {}
    ids = {str(m.get("policy_id")) for m in [*(decision.matched_policies or []), *(decision.monitor_matches or [])]
           if isinstance(m, dict) and m.get("policy_id")}
    if not ids:
        return {}
    rows = db.scalars(select(SecurityPolicy).where(SecurityPolicy.organization_id == org_id,
                                                   SecurityPolicy.id.in_(ids)))
    return {p.id: p for p in rows}


def _annotate(match: dict[str, Any], policies: dict[str, SecurityPolicy]) -> None:
    policy = policies.get(match["policy_id"])
    match["exists"] = policy is not None
    match["description"] = policy.description if policy is not None else None


def _destination_detail(dest: Destination | None, ref: dict[str, Any] | None) -> dict[str, Any] | None:
    if dest is None or ref is None:
        return None
    checks = [{"check": str(c.get("check") or "check"), "result": str(c.get("result") or "unknown"),
               "detail": c.get("detail")} for c in (dest.verification or []) if isinstance(c, dict)]
    return {**ref, "display_name": dest.display_name, "checks": checks, "transfer_count": dest.transfer_count or 0,
            "blocked_count": dest.blocked_count or 0, "sensitive_transfer_count": dest.sensitive_transfer_count or 0,
            "first_seen_at": dest.first_seen_at}


def _recent_context(db: Session, org_id: str, approval: Approval) -> tuple[list[dict[str, Any]], int]:
    """Context the agent had received when it asked (items up to the request time), newest first."""
    conds = (ContextItem.organization_id == org_id, ContextItem.session_id == approval.session_id,
             ContextItem.received_at <= approval.requested_at)
    total = int(db.scalar(select(func.count()).select_from(ContextItem).where(*conds)) or 0)
    rows = db.execute(
        select(ContextItem, ContextSource)
        .outerjoin(ContextSource, and_(ContextSource.id == ContextItem.source_id,
                                       ContextSource.organization_id == org_id))
        .where(*conds).order_by(ContextItem.received_at.desc(), ContextItem.id.desc()).limit(RECENT_CONTEXT)
    ).all()
    items = []
    for item, source in rows:
        summary = item.detection_summary or {}
        preview = item.redacted_preview
        if preview and len(preview) > PREVIEW_CHARS:
            preview = preview[: PREVIEW_CHARS - 1] + "…"
        items.append({
            "id": item.id, "source_id": item.source_id,
            "source_identifier": source.identifier if source else None,
            "source_display_name": source.display_name if source else None,
            "source_type": source.source_type if source else None,
            "source_trust_level": source.trust_level if source else None,
            "trust_level": item.trust_level, "collected_via": item.collected_via, "received_at": item.received_at,
            "sensitivity": item.sensitivity, "contains_secrets": bool(item.contains_secrets),
            "detection_max_severity": summary.get("max_severity"),
            "detection_hit_count": int(summary.get("hit_count") or 0), "preview": preview,
            "tool_invocation_id": item.tool_invocation_id,
        })
    return items, total


def _related_findings(db: Session, org_id: str, approval: Approval, decision: PolicyDecision | None) -> list[dict[str, Any]]:
    linked_conds = []
    if approval.tool_invocation_id:
        linked_conds.append(SecurityFinding.tool_invocation_id == approval.tool_invocation_id)
    if decision is not None:
        linked_conds.append(SecurityFinding.policy_decision_id == decision.id)
    linked = or_(*linked_conds) if linked_conds else None
    severity = case({k: v for k, v in SEVERITY_RANK.items()}, value=SecurityFinding.severity, else_=0)
    query = select(SecurityFinding).where(SecurityFinding.organization_id == org_id,
                                          SecurityFinding.session_id == approval.session_id)
    order = [severity.desc(), SecurityFinding.last_seen_at.desc()]
    if linked is not None:
        order.insert(0, case((linked, 1), else_=0).desc())
    rows = db.scalars(query.order_by(*order).limit(RELATED_FINDINGS)).all()
    decision_id = decision.id if decision is not None else None
    return [{
        "id": f.id, "title": f.title, "category": f.category, "severity": f.severity, "status": f.status,
        "last_seen_at": f.last_seen_at,
        "linked_to_this_call": bool((approval.tool_invocation_id and f.tool_invocation_id == approval.tool_invocation_id)
                                    or (decision_id and f.policy_decision_id == decision_id)),
    } for f in rows]


def _activity(db: Session, org_id: str, approval: Approval) -> list[dict[str, Any]]:
    """Audit entries for this approval: the pause, then the human decision or the expiry."""
    targets = [and_(AuditEvent.target_type == "approval", AuditEvent.target_id == approval.id)]
    if approval.tool_invocation_id:
        targets.append(and_(AuditEvent.target_type == "tool_invocation",
                            AuditEvent.target_id == approval.tool_invocation_id,
                            AuditEvent.action == "tool.approval_required"))
    rows = db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org_id, or_(*targets))
                      .order_by(AuditEvent.seq)).all()
    user_ids = {r.actor_id for r in rows if r.actor_type == "user" and r.actor_id}
    names = dict(db.execute(select(User.id, User.name).where(User.id.in_(user_ids))).all()) if user_ids else {}
    return [{"id": r.id, "seq": r.seq, "occurred_at": r.occurred_at, "action": r.action, "actor_type": r.actor_type,
             "actor_id": r.actor_id, "actor_name": names.get(r.actor_id) if r.actor_id else None,
             "details": r.details or {}} for r in rows]
