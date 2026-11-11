"""Agent registry: inventory summaries, registration, profile edits (including quarantine), observed
tools, explainable security posture and the identity/delegation graph.

Every query filters on the caller's organisation. Tool categories and risk levels always come from
``risk.classify_tool``. Quarantine sets ``status="quarantined"`` plus the reserved label
``quarantined``; it is enforced only by policies that match ``agent.labels`` at an enforcing
integration, and ``quarantine_state`` says plainly whether such a policy exists.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, PermissionDeniedError
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.domain.enums import SEVERITY_RANK, UNTRUSTED_LEVELS, Decision
from app.engines.redaction import redact_text
from app.engines.risk import PostureInputs, classify_tool, compute_agent_posture
from app.engines.risk.policy_refs import condition_refs
from app.engines.risk.session import risk_level_for
from app.models import (
    Agent,
    AgentRelationship,
    AgentSession,
    ContextItem,
    ContextSource,
    Integration,
    PolicyDecision,
    SecurityFinding,
    Tool,
    ToolInvocation,
    TrustRule,
)
from app.services.audit import append_audit
from app.services.ingestion_state import ENFORCING_INTEGRATIONS
from app.services.loaders import load_policy_specs
from app.services.notify import notify
from app.services.scoping import find_scoped, paginate, scoped
from app.services.sessions_service import UNRESOLVED, finding_brief

QUARANTINE_LABEL = "quarantined"  # == app.schemas.agents.QUARANTINE_LABEL
POLICY_FIELDS = ("environment", "labels", "status")
MAX_GRAPH_NODES = 500
MAX_RELATIONSHIPS = 200
RECENT_FINDINGS = 10
_UNTRUSTED = [str(t) for t in UNTRUSTED_LEVELS]
_GATING = {Decision.DENY.value, Decision.REQUIRE_APPROVAL.value}
_LABEL_OPS = {"contains", "in", "any_glob"}
SUGGESTED_QUARANTINE_POLICY: dict[str, Any] = {
    "name": "Deny tool calls from quarantined agents",
    "description": "Blocks every tool call of an agent whose status is quarantined (reserved label 'quarantined').",
    "outcome": "DENY", "mode": "enforce", "enabled": True, "priority": 10000, "severity": "high",
    "conditions": {"field": "agent.labels", "op": "contains", "value": QUARANTINE_LABEL}, "tags": ["quarantine"],
}


@dataclass(frozen=True)
class Actor:
    type: str  # "user" | "api_key" | "system"
    id: str | None


def _redact(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    text = " ".join(redact_text(value).text.split()) if limit <= 200 else redact_text(value).text.strip()
    return text[:limit] or None


# ----------------------------------------------------------------------------- summaries


def summaries(db: Session, org_id: str, agents: list[Agent]) -> list[dict[str, Any]]:
    ids = [a.id for a in agents]
    if not ids:
        return []
    sessions = {r.agent_id: (int(r.total), int(r.active or 0)) for r in db.execute(
        select(AgentSession.agent_id, func.count().label("total"),
               func.sum(case((AgentSession.status == "active", 1), else_=0)).label("active"))
        .where(AgentSession.organization_id == org_id, AgentSession.agent_id.in_(ids)).group_by(AgentSession.agent_id))}
    findings: dict[str, Counter[str]] = {}
    for agent_id, severity, n in db.execute(
        select(SecurityFinding.agent_id, SecurityFinding.severity, func.count()).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.agent_id.in_(ids),
            SecurityFinding.status.in_(UNRESOLVED)).group_by(SecurityFinding.agent_id, SecurityFinding.severity)
    ):
        findings.setdefault(agent_id, Counter())[severity] += int(n)
    tools = dict(db.execute(
        select(ToolInvocation.agent_id, func.count(distinct(ToolInvocation.tool_id))).where(
            ToolInvocation.organization_id == org_id, ToolInvocation.agent_id.in_(ids)).group_by(ToolInvocation.agent_id)
    ).all())
    integration_ids = {a.integration_id for a in agents if a.integration_id}
    kinds = dict(db.execute(select(Integration.id, Integration.kind).where(
        Integration.organization_id == org_id, Integration.id.in_(integration_ids))).all()) if integration_ids else {}
    out = []
    for a in agents:
        total, active = sessions.get(a.id, (0, 0))
        sev = findings.get(a.id, Counter())
        out.append({
            "id": a.id, "name": a.name, "description": a.description, "framework": a.framework, "version": a.version,
            "owner": a.owner, "environment": a.environment, "labels": [str(x) for x in a.labels or []],
            "status": a.status, "is_simulation": a.is_simulation, "created_at": a.created_at,
            "last_seen_at": a.last_seen_at, "risk_score": int(a.risk_score or 0),
            "risk_level": risk_level_for(int(a.risk_score or 0)), "session_count": total,
            "active_session_count": active, "open_findings": sum(sev.values()),
            "max_open_severity": max(sev, key=lambda s: SEVERITY_RANK.get(s, 0)) if sev else None,
            "declared_tool_count": len(declared_tools(a)), "observed_tool_count": int(tools.get(a.id, 0)),
            "integration_kind": kinds.get(a.integration_id) if a.integration_id else None,
        })
    return out


def list_agents(
    db: Session, org_id: str, *, q: str | None, environment: str | None, framework: str | None,
    status: str | None, include_simulated: bool, sort: str, limit: int, offset: int,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    query = scoped(Agent, org_id)
    if not include_simulated:
        query = query.where(Agent.is_simulation.is_(False))
    if q and q.strip():
        term = q.strip()
        query = query.where(or_(Agent.name.icontains(term, autoescape=True), Agent.owner.icontains(term, autoescape=True),
                                Agent.description.icontains(term, autoescape=True)))
    for column, value in ((Agent.environment, environment), (Agent.framework, framework), (Agent.status, status)):
        if value:
            query = query.where(column == value)
    seen = Agent.last_seen_at.desc().nulls_last()
    order = {"risk": [Agent.risk_score.desc(), seen], "name": [Agent.name.asc()], "created": [Agent.created_at.desc()]}
    rows, total = paginate(db, query.order_by(*order.get(sort, [seen]), Agent.id), limit=limit, offset=offset)
    return summaries(db, org_id, rows), total, facets(db, org_id, include_simulated=include_simulated)


def facets(db: Session, org_id: str, *, include_simulated: bool) -> dict[str, Any]:
    conds = [Agent.organization_id == org_id] + ([] if include_simulated else [Agent.is_simulation.is_(False)])

    def group(column: Any) -> list[dict[str, Any]]:
        rows = db.execute(select(column, func.count()).where(*conds).group_by(column)).all()
        return [{"value": str(v), "count": int(n)} for v, n in sorted(rows, key=lambda r: (-r[1], str(r[0]))) if v]

    simulated = db.scalar(select(func.count()).select_from(Agent).where(
        Agent.organization_id == org_id, Agent.is_simulation.is_(True))) or 0
    return {"frameworks": group(Agent.framework), "environments": group(Agent.environment),
            "statuses": group(Agent.status), "simulated": int(simulated)}


# ----------------------------------------------------------------------------- registration & edits


def declared_tools(agent: Agent) -> list[dict[str, Any]]:
    tools = (agent.declared_capabilities or {}).get("tools") or []
    return [t for t in tools if isinstance(t, dict) and t.get("name")]


def build_declared_capabilities(spec: dict[str, Any]) -> dict[str, Any]:
    """Declared configuration with server-side categories; a client category is kept only as a hint."""
    tools = []
    for t in spec.get("tools") or []:
        hint = str(t["category"]) if t.get("category") else None
        cls = classify_tool(str(t["name"]), "declared", category_hint=hint)
        entry: dict[str, Any] = {"name": str(t["name"]), "category": cls.category, "risk_level": cls.risk_level}
        if hint:
            entry["category_hint"] = hint
        tools.append(entry)
    clean = lambda values: [v for v in (_redact(str(x), 200) for x in values or []) if v]  # noqa: E731
    return {"tools": tools, "permissions": clean(spec.get("permissions")), "mcp_servers": clean(spec.get("mcp_servers"))}


def _labels(labels: list[str], status: str) -> list[str]:
    out = [v for v in (_redact(str(x), 64) for x in labels) if v and v != QUARANTINE_LABEL]
    return list(dict.fromkeys(out)) + ([QUARANTINE_LABEL] if status == "quarantined" else [])


def create_agent(db: Session, org_id: str, actor: Actor, data: dict[str, Any]) -> Agent:
    name = data["name"]
    existing = db.scalar(scoped(Agent, org_id).where(Agent.name == name))
    if existing is not None:
        raise ConflictError(f"An agent named '{name}' is already registered", details={"agent_id": existing.id})
    agent = Agent(
        id=new_id("agent"), organization_id=org_id, name=name, description=_redact(data.get("description"), 4000),
        framework=data.get("framework") or "custom", version=_redact(data.get("version"), 64),
        owner=_redact(data.get("owner"), 200), environment=data.get("environment") or "development",
        labels=_labels(data.get("labels") or [], "active"), status="active", is_simulation=False, risk_score=0,
        declared_capabilities=build_declared_capabilities(data.get("declared_capabilities") or {}),
    )
    db.add(agent)
    try:
        db.flush()
    except IntegrityError as exc:
        raise ConflictError(f"An agent named '{name}' is already registered") from exc
    append_audit(db, org_id, action="agent.registered", actor_type=actor.type, actor_id=actor.id, target_type="agent",
                 target_id=agent.id, details={"name": name, "environment": agent.environment,
                                              "framework": agent.framework, "declared_tools": len(declared_tools(agent))})
    notify(db, org_id, "agent.updated", id=agent.id, change="registered")
    return agent


def _capability_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    names = lambda caps: {str(t.get("name")) for t in caps.get("tools") or [] if isinstance(t, dict)}  # noqa: E731
    diff: dict[str, Any] = {"tools_added": sorted(names(new) - names(old)), "tools_removed": sorted(names(old) - names(new))}
    for key in ("permissions", "mcp_servers"):
        if list(old.get(key) or []) != list(new.get(key) or []):
            diff[key] = {"from": list(old.get(key) or []), "to": list(new.get(key) or [])}
    return diff


def update_agent(db: Session, org_id: str, actor: Actor, agent: Agent, changes: dict[str, Any], *,
                 may_manage_policy: bool) -> Agent:
    """Apply a PATCH. Changing a field that policies evaluate requires ``policy:manage``."""
    targets: dict[str, Any] = {}
    for key, limit in (("description", 4000), ("owner", 200)):
        if key in changes:
            targets[key] = _redact(changes[key], limit)
    for key in ("environment", "status"):
        if changes.get(key) is not None:
            targets[key] = changes[key]
    status_after = targets.get("status", agent.status)
    current = [str(x) for x in agent.labels or []]
    base = changes["labels"] if changes.get("labels") is not None else current
    targets["labels"] = _labels(base, status_after)
    if changes.get("declared_capabilities") is not None:
        targets["declared_capabilities"] = build_declared_capabilities(changes["declared_capabilities"])

    diff: dict[str, Any] = {}
    for key, value in targets.items():
        old = getattr(agent, key)
        if old == value or (key == "labels" and current == value):
            continue
        if key == "description":
            diff[key] = {"changed": True}
        elif key == "declared_capabilities":
            diff[key] = _capability_diff(old or {}, value)
        else:
            diff[key] = {"from": old, "to": value}
    if not diff:
        return agent
    guarded = [k for k in POLICY_FIELDS if k in diff]
    if guarded and not may_manage_policy:
        raise PermissionDeniedError(
            f"Changing {', '.join(guarded)} requires the 'policy:manage' permission: policies evaluate these fields.")
    for key in diff:
        setattr(agent, key, targets[key])
    action = "agent.updated"
    if "status" in diff:
        action = ("agent.quarantined" if status_after == "quarantined" else
                  "agent.quarantine_released" if diff["status"]["from"] == "quarantined" else "agent.updated")
    db.flush()
    append_audit(db, org_id, action=action, actor_type=actor.type, actor_id=actor.id, target_type="agent",
                 target_id=agent.id, details={"name": agent.name, "changes": diff})
    notify(db, org_id, "agent.updated", id=agent.id, change=action.split(".", 1)[1])
    return agent


# ----------------------------------------------------------------------------- detail


def decisions_by_enforcement(db: Session, org_id: str, agent_id: str) -> dict[str, int]:
    rows = db.execute(select(PolicyDecision.enforcement, func.count()).where(
        PolicyDecision.organization_id == org_id, PolicyDecision.agent_id == agent_id).group_by(PolicyDecision.enforcement))
    return {str(k): int(n) for k, n in rows if k}


def enforcement_support(row: Integration, counts: dict[str, int]) -> tuple[bool, str]:
    total = sum(counts.values())
    if row.kind not in ENFORCING_INTEGRATIONS:
        return False, f"The {row.kind} integration reports events only; ContextOS cannot block its tool calls."
    if total:
        enforced = counts.get("enforced", 0)
        if enforced:
            return True, f"{enforced} of {total} recorded decisions for this agent were returned at an enforcing boundary."
        return False, (f"None of the {total} recorded decisions for this agent were enforced: its tool calls were "
                       "reported after they ran.")
    if row.decision_count:
        return True, f"The {row.kind} integration requests decisions before tools run; this agent has none recorded yet."
    return False, f"The {row.kind} integration can enforce decisions but has not requested one yet."


def _leaf_targets_quarantine(leaf: Any) -> bool:
    for ref in condition_refs(leaf):
        if ref.negated or ref.field != "agent.labels" or ref.op not in _LABEL_OPS:
            continue
        values = ref.value if isinstance(ref.value, list) else [ref.value]
        if any(fnmatchcase(QUARANTINE_LABEL, str(v).lower()) if ref.op == "any_glob" else str(v).lower() == QUARANTINE_LABEL
               for v in values):
            return True
    return False


def quarantine_scope(conditions: Any) -> str | None:
    """"all_calls" when a quarantined agent alone satisfies the conditions, "some_calls" when other
    conditions must also hold, None when the policy does not target the quarantine label."""
    if not isinstance(conditions, dict) or not _leaf_targets_quarantine(conditions):
        return None
    if "field" in conditions:
        return "all_calls"
    if set(conditions) == {"any"} and any(isinstance(c, dict) and "field" in c and _leaf_targets_quarantine(c)
                                          for c in conditions["any"] or []):
        return "all_calls"
    if set(conditions) == {"all"} and len(conditions["all"] or []) == 1:
        return quarantine_scope(conditions["all"][0])
    return "some_calls"


def quarantine_state(db: Session, org_id: str, agent: Agent) -> dict[str, Any]:
    policies = []
    for spec in load_policy_specs(db, org_id):
        scope = quarantine_scope(spec.conditions) if spec.mode == "enforce" and spec.outcome in _GATING else None
        if scope:
            policies.append({"id": spec.id, "name": spec.name, "outcome": spec.outcome, "scope": scope})
    full = [p for p in policies if p["scope"] == "all_calls"]
    active = agent.status == "quarantined"
    if active and full:
        verb = "denied" if full[0]["outcome"] == Decision.DENY.value else "held for approval"
        text = (f"Tool calls from this agent are {verb} by '{full[0]['name']}' wherever the integration enforces "
                "decisions (Claude Code PreToolUse hook, MCP gateway, SDK guard()). Events reported after the fact are "
                "still recorded but cannot be prevented.")
    elif active:
        text = ("This agent is marked quarantined, but no enabled enforce-mode policy denies every call matching "
                f"agent.labels contains '{QUARANTINE_LABEL}', so its tool calls are still decided by your other "
                "policies. Create the suggested policy to enforce the quarantine.")
        if policies:
            text += f" Matching policies that only cover some calls: {', '.join(p['name'] for p in policies)}."
    else:
        text = (f"Quarantining sets the status to quarantined and adds the reserved label '{QUARANTINE_LABEL}'. "
                + (f"'{full[0]['name']}' would then deny or gate every tool call at enforcing integrations." if full else
                   "No enabled enforce-mode policy matches that label yet, so quarantine would only mark the agent "
                   "until such a policy exists."))
    return {"active": active, "label": QUARANTINE_LABEL, "enforced": active and bool(full), "policies": policies,
            "explanation": text, "suggested_policy": SUGGESTED_QUARANTINE_POLICY}


def agent_detail(db: Session, org_id: str, agent: Agent) -> dict[str, Any]:
    base = summaries(db, org_id, [agent])[0]
    open_rows = db.scalars(scoped(SecurityFinding, org_id).where(
        SecurityFinding.agent_id == agent.id, SecurityFinding.status.in_(UNRESOLVED))
        .order_by(SecurityFinding.last_seen_at.desc()).limit(500)).all()
    recent = sorted(open_rows, key=lambda f: -SEVERITY_RANK.get(f.severity, 0))[:RECENT_FINDINGS]
    by_severity = dict(db.execute(select(SecurityFinding.severity, func.count()).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.agent_id == agent.id,
        SecurityFinding.status.in_(UNRESOLVED)).group_by(SecurityFinding.severity)).all())
    enforcement = decisions_by_enforcement(db, org_id, agent.id)
    integration = find_scoped(db, Integration, agent.integration_id, org_id)
    integration_out = None
    if integration is not None:
        supports, basis = enforcement_support(integration, enforcement)
        integration_out = {"id": integration.id, "kind": integration.kind, "name": integration.name,
                           "status": integration.status, "last_event_at": integration.last_event_at,
                           "supports_enforcement": supports, "enforcement_basis": basis}
    caps = agent.declared_capabilities or {}
    return {
        **base,
        "declared_capabilities": {
            "tools": [{"name": t["name"], "category": t.get("category") or "other",
                       "risk_level": t.get("risk_level") or classify_tool(t["name"], "declared").risk_level,
                       "category_hint": t.get("category_hint")} for t in declared_tools(agent)],
            "permissions": [str(x) for x in caps.get("permissions") or []],
            "mcp_servers": [str(x) for x in caps.get("mcp_servers") or []],
        },
        "integration": integration_out,
        "findings_by_severity": {str(k): int(v) for k, v in by_severity.items()},
        "recent_findings": [finding_brief(f) for f in recent],
        "relationships": relationships(db, org_id, agent.id),
        "decisions_by_enforcement": enforcement,
        "quarantine": quarantine_state(db, org_id, agent),
    }


def relationships(db: Session, org_id: str, agent_id: str) -> list[dict[str, Any]]:
    rels = list(db.scalars(scoped(AgentRelationship, org_id).where(or_(
        AgentRelationship.parent_agent_id == agent_id, AgentRelationship.child_agent_id == agent_id))
        .order_by(AgentRelationship.last_seen_at.desc()).limit(MAX_RELATIONSHIPS)))
    others = {r.child_agent_id if r.parent_agent_id == agent_id else r.parent_agent_id for r in rels}
    agents = {a.id: a for a in db.scalars(scoped(Agent, org_id).where(Agent.id.in_(others)))} if others else {}
    out = []
    for r in rels:
        outgoing = r.parent_agent_id == agent_id
        other = agents.get(r.child_agent_id if outgoing else r.parent_agent_id)
        if other is None:
            continue
        out.append({
            "id": r.id, "direction": "outgoing" if outgoing else "incoming", "relationship_type": r.relationship_type,
            "other_agent": {"id": other.id, "name": other.name, "framework": other.framework,
                            "environment": other.environment, "status": other.status,
                            "risk_score": int(other.risk_score or 0), "risk_level": risk_level_for(int(other.risk_score or 0))},
            "event_count": r.event_count or 0, "crosses_trust_boundary": bool(r.crosses_trust_boundary),
            "first_seen_at": r.first_seen_at, "last_seen_at": r.last_seen_at,
            "last_parent_session_id": r.last_parent_session_id, "last_child_session_id": r.last_child_session_id,
        })
    return out


# ----------------------------------------------------------------------------- tools & posture


def agent_tools(db: Session, org_id: str, agent: Agent) -> list[dict[str, Any]]:
    """Observed tools with usage and decision breakdowns, plus declared tools never observed."""
    agg: dict[str, dict[str, Any]] = {}
    for r in db.execute(
        select(ToolInvocation.tool_id, ToolInvocation.decision, ToolInvocation.status, ToolInvocation.enforcement,
               func.count().label("n"), func.min(ToolInvocation.requested_at).label("first"),
               func.max(ToolInvocation.requested_at).label("last"),
               func.sum(case((ToolInvocation.sensitive_data_detected.is_(True), 1), else_=0)).label("cred"))
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.agent_id == agent.id)
        .group_by(ToolInvocation.tool_id, ToolInvocation.decision, ToolInvocation.status, ToolInvocation.enforcement)
    ):
        a = agg.setdefault(r.tool_id, {"n": 0, "first": None, "last": None, "cred": 0, "decisions": Counter(),
                                       "statuses": Counter(), "enforcement": Counter()})
        a["n"] += int(r.n)
        a["cred"] += int(r.cred or 0)
        a["first"] = min(x for x in (a["first"], r.first) if x is not None)
        a["last"] = max(x for x in (a["last"], r.last) if x is not None)
        for key, value in (("decisions", r.decision), ("statuses", r.status), ("enforcement", r.enforcement)):
            if value:
                a[key][str(value)] += int(r.n)
    tools = {t.id: t for t in db.scalars(scoped(Tool, org_id).where(Tool.id.in_(list(agg))))} if agg else {}
    declared = {t["name"]: t for t in declared_tools(agent)}
    matched: set[str] = set()
    out = []
    for tool_id, a in agg.items():
        tool = tools.get(tool_id)
        if tool is None:
            continue
        key = declared_key(tool.name, tool.server, set(declared))
        if key:
            matched.add(key)
        out.append({
            "tool_id": tool.id, "name": tool.name, "provider": tool.provider, "server": tool.server,
            "category": tool.category, "risk_level": tool.risk_level,
            "classification_reason": (tool.tool_metadata or {}).get("classification_reason"),
            "declared": key is not None, "observed": True, "invocation_count": a["n"], "first_used_at": a["first"],
            "last_used_at": a["last"], "decisions": dict(a["decisions"]), "statuses": dict(a["statuses"]),
            "enforcement": dict(a["enforcement"]), "credential_calls": a["cred"],
        })
    out.sort(key=lambda t: (-t["invocation_count"], t["name"]))
    for name, d in sorted(declared.items()):
        if name in matched:
            continue
        cls = classify_tool(name, "declared", category_hint=d.get("category_hint") or d.get("category"))
        out.append({"tool_id": None, "name": name, "provider": None, "server": None, "category": cls.category,
                    "risk_level": cls.risk_level, "classification_reason": cls.reason, "declared": True,
                    "observed": False, "invocation_count": 0, "first_used_at": None, "last_used_at": None,
                    "decisions": {}, "statuses": {}, "enforcement": {}, "credential_calls": 0})
    return out


def declared_key(name: str, server: str | None, declared: set[str]) -> str | None:
    """The declared tool name an observed tool corresponds to (MCP tools may be declared qualified or bare)."""
    qualified = f"mcp__{server}__{name}" if server else name
    if qualified in declared:
        return qualified
    return name if name in declared else None


def agent_posture(db: Session, org_id: str, agent: Agent) -> dict[str, Any]:
    """Assemble ``PostureInputs`` from persisted rows and run the risk engine's posture assessment."""
    declared = declared_tools(agent)
    names = {t["name"] for t in declared}
    observed = []
    for t in agent_tools(db, org_id, agent):
        if t["observed"]:
            name = declared_key(t["name"], t["server"], names) or (
                f"mcp__{t['server']}__{t['name']}" if t["server"] else t["name"])
            observed.append({"name": name, "category": t["category"], "risk_level": t["risk_level"],
                             "count": t["invocation_count"], "provider": t["provider"], "server": t["server"]})
    specs = load_policy_specs(db, org_id)
    policies = [{"id": p.id, "name": p.name, "outcome": p.outcome, "mode": p.mode, "conditions": p.conditions,
                 "enabled": p.enabled} for p in specs]
    trust_rules = int(db.scalar(select(func.count()).select_from(TrustRule).where(
        TrustRule.organization_id == org_id, TrustRule.enabled.is_(True))) or 0)
    untrusted = int(db.scalar(
        select(func.count(distinct(ContextItem.source_id))).join(ContextSource, ContextSource.id == ContextItem.source_id)
        .where(ContextItem.organization_id == org_id, ContextItem.agent_id == agent.id,
               or_(ContextSource.trust_level.in_(_UNTRUSTED), ContextItem.trust_level.in_(_UNTRUSTED)))) or 0)
    findings = [{"id": r.id, "severity": r.severity, "category": r.category} for r in db.execute(
        select(SecurityFinding.id, SecurityFinding.severity, SecurityFinding.category).where(
            SecurityFinding.organization_id == org_id, SecurityFinding.agent_id == agent.id,
            SecurityFinding.status.in_(UNRESOLVED)).limit(5000))]
    enforcement = decisions_by_enforcement(db, org_id, agent.id)
    row = find_scoped(db, Integration, agent.integration_id, org_id)
    supports = enforcement_support(row, enforcement)[0] if row else False
    integration = {"kind": row.kind, "supports_enforcement": supports, "status": row.status} if row else {}
    session_conds = [AgentSession.organization_id == org_id, AgentSession.agent_id == agent.id]
    total = int(db.scalar(select(func.count()).select_from(AgentSession).where(*session_conds)) or 0)
    trifecta = int(db.scalar(select(func.count()).select_from(AgentSession).where(
        *session_conds, AgentSession.risk_state["trifecta"].as_boolean().is_(True))) or 0)
    approvals = sum(1 for p in specs if p.outcome == Decision.REQUIRE_APPROVAL.value)
    assessment = compute_agent_posture(PostureInputs(
        agent={"id": agent.id, "name": agent.name, "environment": agent.environment, "framework": agent.framework,
               "status": agent.status},
        declared_tools=declared, observed_tools=observed, policies=policies, trust_rule_count=trust_rules,
        untrusted_source_count=untrusted, open_findings=findings, integration=integration,
        approval_policy_count=approvals, sessions_with_trifecta=trifecta, total_sessions=total,
    ))
    return {
        "agent_id": agent.id, **assessment.to_dict(), "computed_at": utcnow(),
        "basis": {"declared_tool_count": len(declared), "observed_tool_count": len(observed),
                  "enabled_policy_count": len(specs), "approval_policy_count": approvals, "trust_rule_count": trust_rules,
                  "untrusted_source_count": untrusted, "open_finding_count": len(findings),
                  "sessions_with_trifecta": trifecta, "total_sessions": total,
                  "integration_kind": row.kind if row else None, "supports_enforcement": supports,
                  "decisions_by_enforcement": enforcement},
    }


# ----------------------------------------------------------------------------- graph


def agent_graph(db: Session, org_id: str, *, include_simulated: bool) -> dict[str, Any]:
    query = scoped(Agent, org_id)
    if not include_simulated:
        query = query.where(Agent.is_simulation.is_(False))
    agents = list(db.scalars(query.order_by(Agent.last_seen_at.desc().nulls_last(), Agent.id).limit(MAX_GRAPH_NODES + 1)))
    truncated = len(agents) > MAX_GRAPH_NODES
    agents = agents[:MAX_GRAPH_NODES]
    ids = [a.id for a in agents]
    rels = list(db.scalars(scoped(AgentRelationship, org_id).where(
        AgentRelationship.parent_agent_id.in_(ids), AgentRelationship.child_agent_id.in_(ids)))) if ids else []
    nodes = [{key: s[key] for key in ("id", "name", "owner", "framework", "environment", "status", "risk_score",
                                       "risk_level", "is_simulation", "session_count", "open_findings")}
             for s in summaries(db, org_id, agents)]
    edges = [{"id": r.id, "source": r.parent_agent_id, "target": r.child_agent_id, "relationship_type": r.relationship_type,
              "event_count": r.event_count or 0, "crosses_trust_boundary": bool(r.crosses_trust_boundary),
              "first_seen_at": r.first_seen_at, "last_seen_at": r.last_seen_at,
              "last_parent_session_id": r.last_parent_session_id, "last_child_session_id": r.last_child_session_id}
             for r in rels]
    return {"nodes": nodes, "edges": edges, "truncated": truncated}
