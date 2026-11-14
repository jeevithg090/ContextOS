"""Context sources: where context came from, how much each delivered and what it triggered.

Counts are computed from persisted items and findings. Simulation Lab data is excluded unless
requested, and a simulation-only source (``ContextSource.is_simulation``: no real traffic has
observed it) is hidden from the list but still reachable by id. Agent-bound API keys see only
sources their agent received content from.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, and_, case, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.engines.redaction import redact_value
from app.models import Agent, ContextItem, ContextSource, SecurityFinding, TrustRule
from app.services.context_service_common import (
    OPEN_STATUSES,
    ItemFilters,
    clean,
    conditions,
    finding_ref,
    hit_count,
    list_items,
    source_ref,
)


def _source_stats(org_id: str, include_simulated: bool, bound_agent_id: str | None) -> tuple[Any, Any]:
    item_conds: list[Any] = [ContextItem.organization_id == org_id]
    finding_conds: list[Any] = [
        SecurityFinding.organization_id == org_id,
        SecurityFinding.source_id.is_not(None),
    ]
    if not include_simulated:
        item_conds.append(ContextItem.is_simulation.is_(False))
        finding_conds.append(SecurityFinding.is_simulation.is_(False))
    if bound_agent_id:
        item_conds.append(ContextItem.agent_id == bound_agent_id)
        finding_conds.append(SecurityFinding.agent_id == bound_agent_id)
    items = (
        select(
            ContextItem.source_id.label("sid"),
            func.count(ContextItem.id).label("n_items"),
            func.count(distinct(ContextItem.agent_id)).label("n_agents"),
            func.count(distinct(ContextItem.session_id)).label("n_sessions"),
            func.sum(case((hit_count() > 0, 1), else_=0)).label("n_detected"),
        )
        .where(*item_conds)
        .group_by(ContextItem.source_id)
        .subquery()
    )
    findings = (
        select(
            SecurityFinding.source_id.label("sid"),
            func.count(SecurityFinding.id).label("n_findings"),
            func.sum(case((SecurityFinding.status.in_(OPEN_STATUSES), 1), else_=0)).label("n_open"),
        )
        .where(*finding_conds)
        .group_by(SecurityFinding.source_id)
        .subquery()
    )
    return items, findings


def _source_select(
    org_id: str, include_simulated: bool, bound_agent_id: str | None, *, hide_simulation_only: bool = True
) -> tuple[Select[Any], dict[str, Any], Any]:
    items, findings = _source_stats(org_id, include_simulated, bound_agent_id)
    any_items = select(ContextItem.source_id).where(ContextItem.organization_id == org_id)
    if bound_agent_id:
        any_items = any_items.where(ContextItem.agent_id == bound_agent_id)
    item_count, finding_count = func.coalesce(items.c.n_items, 0), func.coalesce(findings.c.n_findings, 0)
    query = (
        select(
            ContextSource,
            item_count,
            func.coalesce(items.c.n_agents, 0),
            func.coalesce(items.c.n_sessions, 0),
            func.coalesce(items.c.n_detected, 0),
            finding_count,
            func.coalesce(findings.c.n_open, 0),
        )
        .outerjoin(items, items.c.sid == ContextSource.id)
        .outerjoin(findings, findings.c.sid == ContextSource.id)
        .where(ContextSource.organization_id == org_id)
    )
    if bound_agent_id:
        query = query.where(ContextSource.id.in_(any_items))
    elif hide_simulation_only and not include_simulated:  # sources observed only by simulations
        query = query.where(ContextSource.is_simulation.is_(False))
    sorts = {"last_seen": ContextSource.last_seen_at, "items": item_count, "findings": finding_count}
    return query, sorts, finding_count


def _source_summary(row: Any) -> dict[str, Any]:
    s: ContextSource = row[0]
    return {
        **source_ref(s),
        "owner": clean(s.owner),
        "trust_capabilities": list(s.trust_capabilities or []),
        "manually_classified": bool(s.manually_classified),
        "first_seen_at": s.first_seen_at,
        "last_seen_at": s.last_seen_at,
        "observation_count": s.observation_count or 0,
        "item_count": int(row[1]),
        "agent_count": int(row[2]),
        "session_count": int(row[3]),
        "items_with_detections": int(row[4]),
        "finding_count": int(row[5]),
        "open_finding_count": int(row[6]),
        "max_finding_severity": s.max_finding_severity,
        "is_simulation": bool(s.is_simulation),
    }


def list_sources(
    db: Session,
    org_id: str,
    *,
    q: str | None = None,
    source_type: str | None = None,
    trust_level: str | None = None,
    has_findings: bool | None = None,
    include_simulated: bool = False,
    sort: str = "last_seen",
    bound_agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    query, sorts, finding_count = _source_select(org_id, include_simulated, bound_agent_id)
    if q and q.strip():
        term = q.strip()
        query = query.where(
            or_(
                ContextSource.identifier.icontains(term, autoescape=True),
                ContextSource.display_name.icontains(term, autoescape=True),
                ContextSource.domain.icontains(term, autoescape=True),
            )
        )
    if source_type:
        query = query.where(ContextSource.source_type == source_type)
    if trust_level:
        query = query.where(ContextSource.trust_level == trust_level)
    if has_findings is not None:
        query = query.where(finding_count > 0 if has_findings else finding_count == 0)
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    order = sorts.get(sort, ContextSource.last_seen_at)
    rows = db.execute(
        query.order_by(order.desc(), ContextSource.last_seen_at.desc(), ContextSource.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return [_source_summary(r) for r in rows], int(total)


def get_source(
    db: Session,
    org_id: str,
    source_id: str,
    *,
    include_simulated: bool = False,
    bound_agent_id: str | None = None,
) -> dict[str, Any]:
    # A source seen only by simulations is still reachable by id (e.g. from a simulated item).
    query, _sorts, _count = _source_select(
        org_id, include_simulated, bound_agent_id, hide_simulation_only=False
    )
    row = db.execute(query.where(ContextSource.id == source_id)).first()
    if row is None:
        raise NotFoundError(f"Context source '{source_id}' not found")
    source: ContextSource = row[0]
    rule = (
        db.scalar(
            select(TrustRule).where(TrustRule.organization_id == org_id, TrustRule.id == source.trust_rule_id)
        )
        if source.trust_rule_id
        else None
    )
    items, _ = list_items(
        db,
        org_id,
        ItemFilters(source_id=source.id, include_simulated=include_simulated),
        bound_agent_id=bound_agent_id,
        limit=20,
    )
    finding_q = select(SecurityFinding).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.source_id == source.id
    )
    if not include_simulated:
        finding_q = finding_q.where(SecurityFinding.is_simulation.is_(False))
    if bound_agent_id:
        finding_q = finding_q.where(SecurityFinding.agent_id == bound_agent_id)
    findings = db.scalars(finding_q.order_by(SecurityFinding.last_seen_at.desc()).limit(25))
    consumer_conds = conditions(org_id, ItemFilters(include_simulated=include_simulated), bound_agent_id)
    consumers = db.execute(
        select(
            ContextItem.agent_id,
            Agent.name,
            func.count(ContextItem.id),
            func.count(distinct(ContextItem.session_id)),
            func.max(ContextItem.received_at),
        )
        .outerjoin(Agent, and_(Agent.id == ContextItem.agent_id, Agent.organization_id == org_id))
        .where(*consumer_conds, ContextItem.source_id == source.id)
        .group_by(ContextItem.agent_id, Agent.name)
        .order_by(func.max(ContextItem.received_at).desc())
        .limit(20)
    ).all()
    metadata, _ = redact_value(source.source_metadata or {})
    return {
        **_source_summary(row),
        "trust_reasons": [r for r in (clean(str(x), 1000) for x in source.trust_reasons or []) if r],
        "trust_rule": {
            "id": rule.id,
            "name": rule.name,
            "pattern": rule.pattern,
            "trust_level": rule.trust_level,
            "enabled": rule.enabled,
        }
        if rule
        else None,
        "source_metadata": metadata if isinstance(metadata, dict) else {},
        "recent_items": items,
        "findings": [finding_ref(f) for f in findings],
        "consumers": [
            {
                "agent": {"id": a, "name": n},
                "item_count": int(c),
                "session_count": int(s),
                "last_received_at": t,
            }
            for a, n, c, s, t in consumers
        ],
    }
