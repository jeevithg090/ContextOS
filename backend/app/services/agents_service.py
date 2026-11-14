"""Agent registry: inventory summaries, registration, profile edits (including quarantine), detail
and the identity/delegation graph. Observed tools and the explainable security posture live in
``agents_posture`` and are re-exported here.

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
from app.domain.enums import SEVERITY_RANK, Decision
from app.engines.redaction import redact_text
from app.engines.risk import classify_tool
from app.engines.risk.policy_refs import condition_refs
from app.engines.risk.session import risk_level_for
from app.models import (
    Agent,
    AgentRelationship,
    AgentSession,
    Integration,
    SecurityFinding,
    ToolInvocation,
)
from app.services.agents_posture import (
    agent_posture,
    agent_tools,
    decisions_by_enforcement,
    declared_key,
    declared_tools,
    enforcement_support,
    posture_policies,
)
from app.services.audit import append_audit
from app.services.loaders import load_policy_specs
from app.services.notify import notify
from app.services.scoping import find_scoped, paginate, scoped
from app.services.sessions_service import UNRESOLVED, finding_brief

__all__ = [
    "Actor",
    "QUARANTINE_LABEL",
    "SUGGESTED_QUARANTINE_POLICY",
    "agent_detail",
    "agent_graph",
    "agent_posture",
    "agent_tools",
    "build_declared_capabilities",
    "create_agent",
    "declared_key",
    "declared_tools",
    "decisions_by_enforcement",
    "enforcement_support",
    "facets",
    "list_agents",
    "posture_policies",
    "quarantine_scope",
    "quarantine_state",
    "relationships",
    "summaries",
    "update_agent",
]

QUARANTINE_LABEL = "quarantined"  # == app.schemas.agents.QUARANTINE_LABEL
POLICY_FIELDS = ("environment", "labels", "status")
MAX_GRAPH_NODES = 500
MAX_RELATIONSHIPS = 200
RECENT_FINDINGS = 10
_GATING = {Decision.DENY.value, Decision.REQUIRE_APPROVAL.value}
_LABEL_OPS = {"contains", "in", "any_glob"}
SUGGESTED_QUARANTINE_POLICY: dict[str, Any] = {
    "name": "Deny tool calls from quarantined agents",
    "description": "Blocks every tool call of an agent whose status is quarantined (reserved label 'quarantined').",
    "outcome": "DENY",
    "mode": "enforce",
    "enabled": True,
    "priority": 10000,
    "severity": "high",
    "conditions": {"field": "agent.labels", "op": "contains", "value": QUARANTINE_LABEL},
    "tags": ["quarantine"],
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
    sessions = {
        r.agent_id: (int(r.total), int(r.active or 0))
        for r in db.execute(
            select(
                AgentSession.agent_id,
                func.count().label("total"),
                func.sum(case((AgentSession.status == "active", 1), else_=0)).label("active"),
            )
            .where(AgentSession.organization_id == org_id, AgentSession.agent_id.in_(ids))
            .group_by(AgentSession.agent_id)
        )
    }
    findings: dict[str, Counter[str]] = {}
    for agent_id, severity, n in db.execute(
        select(SecurityFinding.agent_id, SecurityFinding.severity, func.count())
        .where(
            SecurityFinding.organization_id == org_id,
            SecurityFinding.agent_id.in_(ids),
            SecurityFinding.status.in_(UNRESOLVED),
        )
        .group_by(SecurityFinding.agent_id, SecurityFinding.severity)
    ):
        findings.setdefault(agent_id, Counter())[severity] += int(n)
    tools = dict(
        db.execute(
            select(ToolInvocation.agent_id, func.count(distinct(ToolInvocation.tool_id)))
            .where(ToolInvocation.organization_id == org_id, ToolInvocation.agent_id.in_(ids))
            .group_by(ToolInvocation.agent_id)
        ).all()
    )
    integration_ids = {a.integration_id for a in agents if a.integration_id}
    kinds = (
        dict(
            db.execute(
                select(Integration.id, Integration.kind).where(
                    Integration.organization_id == org_id, Integration.id.in_(integration_ids)
                )
            ).all()
        )
        if integration_ids
        else {}
    )
    out = []
    for a in agents:
        total, active = sessions.get(a.id, (0, 0))
        sev = findings.get(a.id, Counter())
        out.append(
            {
                "id": a.id,
                "name": a.name,
                "description": a.description,
                "framework": a.framework,
                "version": a.version,
                "owner": a.owner,
                "environment": a.environment,
                "labels": [str(x) for x in a.labels or []],
                "status": a.status,
                "is_simulation": a.is_simulation,
                "created_at": a.created_at,
                "last_seen_at": a.last_seen_at,
                "risk_score": int(a.risk_score or 0),
                "risk_level": risk_level_for(int(a.risk_score or 0)),
                "session_count": total,
                "active_session_count": active,
                "open_findings": sum(sev.values()),
                "max_open_severity": max(sev, key=lambda s: SEVERITY_RANK.get(s, 0)) if sev else None,
                "declared_tool_count": len(declared_tools(a)),
                "observed_tool_count": int(tools.get(a.id, 0)),
                "integration_kind": kinds.get(a.integration_id) if a.integration_id else None,
            }
        )
    return out


def list_agents(
    db: Session,
    org_id: str,
    *,
    q: str | None,
    environment: str | None,
    framework: str | None,
    status: str | None,
    include_simulated: bool,
    sort: str,
    limit: int,
    offset: int,
    only_agent_id: str | None = None,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """``only_agent_id`` (an agent-bound API key) restricts the list and its facets to that agent."""
    query = scoped(Agent, org_id)
    if only_agent_id:
        query = query.where(Agent.id == only_agent_id)
    if not include_simulated:
        query = query.where(Agent.is_simulation.is_(False))
    if q and q.strip():
        term = q.strip()
        query = query.where(
            or_(
                Agent.name.icontains(term, autoescape=True),
                Agent.owner.icontains(term, autoescape=True),
                Agent.description.icontains(term, autoescape=True),
            )
        )
    for column, value in (
        (Agent.environment, environment),
        (Agent.framework, framework),
        (Agent.status, status),
    ):
        if value:
            query = query.where(column == value)
    seen = Agent.last_seen_at.desc().nulls_last()
    order = {
        "risk": [Agent.risk_score.desc(), seen],
        "name": [Agent.name.asc()],
        "created": [Agent.created_at.desc()],
    }
    rows, total = paginate(db, query.order_by(*order.get(sort, [seen]), Agent.id), limit=limit, offset=offset)
    return (
        summaries(db, org_id, rows),
        total,
        facets(db, org_id, include_simulated=include_simulated, only_agent_id=only_agent_id),
    )


def facets(
    db: Session, org_id: str, *, include_simulated: bool, only_agent_id: str | None = None
) -> dict[str, Any]:
    scope = [Agent.organization_id == org_id] + ([Agent.id == only_agent_id] if only_agent_id else [])
    conds = scope + ([] if include_simulated else [Agent.is_simulation.is_(False)])

    def group(column: Any) -> list[dict[str, Any]]:
        rows = db.execute(select(column, func.count()).where(*conds).group_by(column)).all()
        return [
            {"value": str(v), "count": int(n)} for v, n in sorted(rows, key=lambda r: (-r[1], str(r[0]))) if v
        ]

    simulated = (
        db.scalar(select(func.count()).select_from(Agent).where(*scope, Agent.is_simulation.is_(True))) or 0
    )
    return {
        "frameworks": group(Agent.framework),
        "environments": group(Agent.environment),
        "statuses": group(Agent.status),
        "simulated": int(simulated),
    }


# ----------------------------------------------------------------------------- registration & edits


def build_declared_capabilities(spec: dict[str, Any]) -> dict[str, Any]:
    """Declared configuration with server-side categories; a client category is kept only as a hint."""
    tools = []
    for t in spec.get("tools") or []:
        hint = str(t["category"]) if t.get("category") else None
        name = redact_text(str(t["name"])).text  # same deterministic form the pipeline stores tool names in
        cls = classify_tool(name, "declared", category_hint=hint)
        entry: dict[str, Any] = {"name": name, "category": cls.category, "risk_level": cls.risk_level}
        if hint:
            entry["category_hint"] = hint
        tools.append(entry)
    clean = lambda values: [v for v in (_redact(str(x), 200) for x in values or []) if v]  # noqa: E731
    return {
        "tools": tools,
        "permissions": clean(spec.get("permissions")),
        "mcp_servers": clean(spec.get("mcp_servers")),
    }


def _labels(labels: list[str], status: str) -> list[str]:
    out = [v for v in (_redact(str(x), 64) for x in labels) if v and v != QUARANTINE_LABEL]
    return list(dict.fromkeys(out)) + ([QUARANTINE_LABEL] if status == "quarantined" else [])


def create_agent(db: Session, org_id: str, actor: Actor, data: dict[str, Any]) -> Agent:
    # Redacted exactly as the ingestion pipeline redacts reported agent names, so they still match.
    name = redact_text(data["name"]).text
    existing = db.scalar(scoped(Agent, org_id).where(Agent.name == name))
    if existing is not None:
        raise ConflictError(
            f"An agent named '{name}' is already registered", details={"agent_id": existing.id}
        )
    agent = Agent(
        id=new_id("agent"),
        organization_id=org_id,
        name=name,
        description=_redact(data.get("description"), 4000),
        framework=_redact(data.get("framework"), 64) or "custom",
        version=_redact(data.get("version"), 64),
        owner=_redact(data.get("owner"), 200),
        environment=data.get("environment") or "development",
        labels=_labels(data.get("labels") or [], "active"),
        status="active",
        is_simulation=False,
        risk_score=0,
        declared_capabilities=build_declared_capabilities(data.get("declared_capabilities") or {}),
    )
    db.add(agent)
    try:
        db.flush()
    except IntegrityError as exc:
        raise ConflictError(f"An agent named '{name}' is already registered") from exc
    append_audit(
        db,
        org_id,
        action="agent.registered",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="agent",
        target_id=agent.id,
        details={
            "name": name,
            "environment": agent.environment,
            "framework": agent.framework,
            "declared_tools": len(declared_tools(agent)),
        },
    )
    notify(db, org_id, "agent.updated", id=agent.id, change="registered")
    return agent


def _capability_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    names = lambda caps: {str(t.get("name")) for t in caps.get("tools") or [] if isinstance(t, dict)}  # noqa: E731
    diff: dict[str, Any] = {
        "tools_added": sorted(names(new) - names(old)),
        "tools_removed": sorted(names(old) - names(new)),
    }
    for key in ("permissions", "mcp_servers"):
        if list(old.get(key) or []) != list(new.get(key) or []):
            diff[key] = {"from": list(old.get(key) or []), "to": list(new.get(key) or [])}
    return diff


def update_agent(
    db: Session, org_id: str, actor: Actor, agent: Agent, changes: dict[str, Any], *, may_manage_policy: bool
) -> Agent:
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
            f"Changing {', '.join(guarded)} requires the 'policy:manage' permission: policies evaluate these fields."
        )
    for key in diff:
        setattr(agent, key, targets[key])
    action = "agent.updated"
    if "status" in diff:
        action = (
            "agent.quarantined"
            if status_after == "quarantined"
            else "agent.quarantine_released"
            if diff["status"]["from"] == "quarantined"
            else "agent.updated"
        )
    db.flush()
    append_audit(
        db,
        org_id,
        action=action,
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="agent",
        target_id=agent.id,
        details={"name": agent.name, "changes": diff},
    )
    notify(db, org_id, "agent.updated", id=agent.id, change=action.split(".", 1)[1])
    return agent


# ----------------------------------------------------------------------------- detail


def _leaf_targets_quarantine(leaf: Any) -> bool:
    for ref in condition_refs(leaf):
        if ref.negated or ref.field != "agent.labels" or ref.op not in _LABEL_OPS:
            continue
        values = ref.value if isinstance(ref.value, list) else [ref.value]
        if any(
            fnmatchcase(QUARANTINE_LABEL, str(v).lower())
            if ref.op == "any_glob"
            else str(v).lower() == QUARANTINE_LABEL
            for v in values
        ):
            return True
    return False


def quarantine_scope(conditions: Any) -> str | None:
    """ "all_calls" when a quarantined agent alone satisfies the conditions, "some_calls" when other
    conditions must also hold, None when the policy does not target the quarantine label."""
    if not isinstance(conditions, dict) or not _leaf_targets_quarantine(conditions):
        return None
    if "field" in conditions:
        return "all_calls"
    if set(conditions) == {"any"} and any(
        isinstance(c, dict) and "field" in c and _leaf_targets_quarantine(c) for c in conditions["any"] or []
    ):
        return "all_calls"
    if set(conditions) == {"all"} and len(conditions["all"] or []) == 1:
        return quarantine_scope(conditions["all"][0])
    return "some_calls"


def quarantine_state(db: Session, org_id: str, agent: Agent) -> dict[str, Any]:
    policies = []
    for spec in load_policy_specs(db, org_id):
        scope = (
            quarantine_scope(spec.conditions) if spec.mode == "enforce" and spec.outcome in _GATING else None
        )
        if scope:
            policies.append({"id": spec.id, "name": spec.name, "outcome": spec.outcome, "scope": scope})
    full = [p for p in policies if p["scope"] == "all_calls"]
    active = agent.status == "quarantined"
    if active and full:
        verb = "denied" if full[0]["outcome"] == Decision.DENY.value else "held for approval"
        text = (
            f"Tool calls from this agent are {verb} by '{full[0]['name']}' wherever the integration enforces "
            "decisions (Claude Code PreToolUse hook, MCP gateway, SDK guard()). Events reported after the fact are "
            "still recorded but cannot be prevented."
        )
    elif active:
        text = (
            "This agent is marked quarantined, but no enabled enforce-mode policy denies every call matching "
            f"agent.labels contains '{QUARANTINE_LABEL}', so its tool calls are still decided by your other "
            "policies. Create the suggested policy to enforce the quarantine."
        )
        if policies:
            text += (
                f" Matching policies that only cover some calls: {', '.join(p['name'] for p in policies)}."
            )
    else:
        text = (
            f"Quarantining sets the status to quarantined and adds the reserved label '{QUARANTINE_LABEL}'. "
            + (
                f"'{full[0]['name']}' would then deny or gate every tool call at enforcing integrations."
                if full
                else "No enabled enforce-mode policy matches that label yet, so quarantine would only mark the agent "
                "until such a policy exists."
            )
        )
    return {
        "active": active,
        "label": QUARANTINE_LABEL,
        "enforced": active and bool(full),
        "policies": policies,
        "explanation": text,
        "suggested_policy": SUGGESTED_QUARANTINE_POLICY,
    }


def agent_detail(db: Session, org_id: str, agent: Agent) -> dict[str, Any]:
    base = summaries(db, org_id, [agent])[0]
    open_rows = db.scalars(
        scoped(SecurityFinding, org_id)
        .where(SecurityFinding.agent_id == agent.id, SecurityFinding.status.in_(UNRESOLVED))
        .order_by(SecurityFinding.last_seen_at.desc())
        .limit(500)
    ).all()
    recent = sorted(open_rows, key=lambda f: -SEVERITY_RANK.get(f.severity, 0))[:RECENT_FINDINGS]
    by_severity = dict(
        db.execute(
            select(SecurityFinding.severity, func.count())
            .where(
                SecurityFinding.organization_id == org_id,
                SecurityFinding.agent_id == agent.id,
                SecurityFinding.status.in_(UNRESOLVED),
            )
            .group_by(SecurityFinding.severity)
        ).all()
    )
    enforcement = decisions_by_enforcement(db, org_id, agent.id)
    integration = find_scoped(db, Integration, agent.integration_id, org_id)
    integration_out = None
    if integration is not None:
        supports, basis = enforcement_support(integration, enforcement)
        integration_out = {
            "id": integration.id,
            "kind": integration.kind,
            "name": integration.name,
            "status": integration.status,
            "last_event_at": integration.last_event_at,
            "supports_enforcement": supports,
            "enforcement_basis": basis,
        }
    caps = agent.declared_capabilities or {}
    return {
        **base,
        "declared_capabilities": {
            "tools": [
                {
                    "name": t["name"],
                    "category": t.get("category") or "other",
                    "risk_level": t.get("risk_level") or classify_tool(t["name"], "declared").risk_level,
                    "category_hint": t.get("category_hint"),
                }
                for t in declared_tools(agent)
            ],
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
    rels = list(
        db.scalars(
            scoped(AgentRelationship, org_id)
            .where(
                or_(
                    AgentRelationship.parent_agent_id == agent_id,
                    AgentRelationship.child_agent_id == agent_id,
                )
            )
            .order_by(AgentRelationship.last_seen_at.desc())
            .limit(MAX_RELATIONSHIPS)
        )
    )
    others = {r.child_agent_id if r.parent_agent_id == agent_id else r.parent_agent_id for r in rels}
    agents = (
        {a.id: a for a in db.scalars(scoped(Agent, org_id).where(Agent.id.in_(others)))} if others else {}
    )
    out = []
    for r in rels:
        outgoing = r.parent_agent_id == agent_id
        other = agents.get(r.child_agent_id if outgoing else r.parent_agent_id)
        if other is None:
            continue
        out.append(
            {
                "id": r.id,
                "direction": "outgoing" if outgoing else "incoming",
                "relationship_type": r.relationship_type,
                "other_agent": {
                    "id": other.id,
                    "name": other.name,
                    "framework": other.framework,
                    "environment": other.environment,
                    "status": other.status,
                    "risk_score": int(other.risk_score or 0),
                    "risk_level": risk_level_for(int(other.risk_score or 0)),
                },
                "event_count": r.event_count or 0,
                "crosses_trust_boundary": bool(r.crosses_trust_boundary),
                "first_seen_at": r.first_seen_at,
                "last_seen_at": r.last_seen_at,
                "last_parent_session_id": r.last_parent_session_id,
                "last_child_session_id": r.last_child_session_id,
            }
        )
    return out


# ----------------------------------------------------------------------------- graph


def agent_graph(db: Session, org_id: str, *, include_simulated: bool) -> dict[str, Any]:
    query = scoped(Agent, org_id)
    if not include_simulated:
        query = query.where(Agent.is_simulation.is_(False))
    agents = list(
        db.scalars(
            query.order_by(Agent.last_seen_at.desc().nulls_last(), Agent.id).limit(MAX_GRAPH_NODES + 1)
        )
    )
    truncated = len(agents) > MAX_GRAPH_NODES
    agents = agents[:MAX_GRAPH_NODES]
    ids = [a.id for a in agents]
    rels = (
        list(
            db.scalars(
                scoped(AgentRelationship, org_id).where(
                    AgentRelationship.parent_agent_id.in_(ids), AgentRelationship.child_agent_id.in_(ids)
                )
            )
        )
        if ids
        else []
    )
    nodes = [
        {
            key: s[key]
            for key in (
                "id",
                "name",
                "owner",
                "framework",
                "environment",
                "status",
                "risk_score",
                "risk_level",
                "is_simulation",
                "session_count",
                "open_findings",
            )
        }
        for s in summaries(db, org_id, agents)
    ]
    edges = [
        {
            "id": r.id,
            "source": r.parent_agent_id,
            "target": r.child_agent_id,
            "relationship_type": r.relationship_type,
            "event_count": r.event_count or 0,
            "crosses_trust_boundary": bool(r.crosses_trust_boundary),
            "first_seen_at": r.first_seen_at,
            "last_seen_at": r.last_seen_at,
            "last_parent_session_id": r.last_parent_session_id,
            "last_child_session_id": r.last_child_session_id,
        }
        for r in rels
    ]
    return {"nodes": nodes, "edges": edges, "truncated": truncated}
