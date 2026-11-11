"""Agent tools and explainable security posture, assembled from persisted rows.

``agent_tools`` lists observed tools (usage and decision breakdowns) and declared tools never
observed; ``agent_posture`` builds ``PostureInputs`` for the risk engine's posture assessment.
Policies are passed as ``{"id", "name", "outcome", "mode", "conditions", "enabled"}``. The
integration status given to the engine is the shared health rule (``integrations_health``): a
stale or never-seen integration is not counted as healthy, whatever its stored status says.
Every query filters on the caller's organisation.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.domain.enums import UNTRUSTED_LEVELS, Decision
from app.engines.risk import PostureInputs, classify_tool, compute_agent_posture
from app.models import (
    Agent,
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
from app.services.ingestion_state import ENFORCING_INTEGRATIONS
from app.services.integrations_health import integration_health
from app.services.loaders import load_policy_specs
from app.services.scoping import find_scoped, scoped
from app.services.sessions_service import UNRESOLVED

_UNTRUSTED = [str(t) for t in UNTRUSTED_LEVELS]

__all__ = ["agent_posture", "agent_tools", "declared_key", "declared_tools", "decisions_by_enforcement",
           "enforcement_support", "posture_policies"]


def declared_tools(agent: Agent) -> list[dict[str, Any]]:
    tools = (agent.declared_capabilities or {}).get("tools") or []
    return [t for t in tools if isinstance(t, dict) and t.get("name")]


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


def posture_policies(specs: list[Any]) -> list[dict[str, Any]]:
    """Policies in the shape the posture engine reads (``{id,name,outcome,mode,conditions,enabled}``)."""
    return [{"id": p.id, "name": p.name, "outcome": p.outcome, "mode": p.mode, "conditions": p.conditions,
             "enabled": p.enabled} for p in specs]


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
    policies = posture_policies(specs)
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
    now = utcnow()
    health = integration_health(row.last_event_at, now, status=row.status) if row else None
    integration = {"kind": row.kind, "supports_enforcement": supports, "status": health} if row else {}
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
        "agent_id": agent.id, **assessment.to_dict(), "computed_at": now,
        "basis": {"declared_tool_count": len(declared), "observed_tool_count": len(observed),
                  "enabled_policy_count": len(specs), "approval_policy_count": approvals, "trust_rule_count": trust_rules,
                  "untrusted_source_count": untrusted, "open_finding_count": len(findings),
                  "sessions_with_trifecta": trifecta, "total_sessions": total,
                  "integration_kind": row.kind if row else None, "integration_health": health,
                  "supports_enforcement": supports,
                  "decisions_by_enforcement": enforcement},
    }
