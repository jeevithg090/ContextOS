"""Load persisted configuration into pure-engine specs. Shared by ingestion, replay, simulations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines.policy import PolicySpec
from app.engines.trust import TrustRuleSpec
from app.models import SecurityPolicy, TrustRule


def policy_to_spec(row: SecurityPolicy) -> PolicySpec:
    return PolicySpec(
        id=row.id,
        name=row.name,
        outcome=row.outcome,
        conditions=row.conditions or {},
        version=row.version,
        enabled=row.enabled,
        mode=row.mode,
        priority=row.priority,
        severity=row.severity,
        restrictions=row.restrictions or {},
        description=row.description,
    )


def load_policy_specs(db: Session, org_id: str, *, include_disabled: bool = False) -> list[PolicySpec]:
    query = select(SecurityPolicy).where(SecurityPolicy.organization_id == org_id)
    if not include_disabled:
        query = query.where(SecurityPolicy.enabled.is_(True))
    rows = db.scalars(query.order_by(SecurityPolicy.priority.desc(), SecurityPolicy.name)).all()
    return [policy_to_spec(r) for r in rows]


def trust_rule_to_spec(row: TrustRule) -> TrustRuleSpec:
    return TrustRuleSpec(
        id=row.id,
        name=row.name,
        pattern=row.pattern,
        trust_level=row.trust_level,
        capabilities=tuple(row.capabilities or ()),
        source_type=row.source_type,
        match_field=row.match_field,
        applies_to=row.applies_to,
        priority=row.priority,
        enabled=row.enabled,
    )


def load_trust_rule_specs(db: Session, org_id: str, *, applies_to: str | None = None) -> list[TrustRuleSpec]:
    query = select(TrustRule).where(TrustRule.organization_id == org_id, TrustRule.enabled.is_(True))
    rows = db.scalars(query.order_by(TrustRule.priority.desc(), TrustRule.created_at)).all()
    specs = [trust_rule_to_spec(r) for r in rows]
    if applies_to:
        specs = [s for s in specs if s.applies_to in (applies_to, "both")]
    return specs
