"""Seed security defaults (built-in policy pack + default trust rules) for an organisation.

Idempotent: built-in policies are keyed by ``builtin_key``; trust rules by (name, pattern).
Data comes from the engines:
- ``app.engines.policy.builtin.BUILTIN_POLICIES``: list of dicts with keys
  builtin_key, name, description, outcome, mode, priority, severity, conditions, restrictions, tags
- ``app.engines.trust.defaults.DEFAULT_TRUST_RULES``: list of dicts with keys
  name, description, applies_to, source_type, match_field, pattern, trust_level, capabilities, priority
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.models import SecurityPolicy, TrustRule


def seed_security_defaults(db: Session, org_id: str) -> dict[str, int]:
    from app.engines.policy.builtin import BUILTIN_POLICIES
    from app.engines.trust.defaults import DEFAULT_TRUST_RULES

    existing_keys = set(
        db.scalars(select(SecurityPolicy.builtin_key).where(SecurityPolicy.organization_id == org_id)).all()
    )
    policies = 0
    for spec in BUILTIN_POLICIES:
        if spec["builtin_key"] in existing_keys:
            continue
        db.add(
            SecurityPolicy(
                id=new_id("policy"),
                organization_id=org_id,
                name=spec["name"],
                description=spec.get("description"),
                enabled=spec.get("enabled", True),
                mode=spec.get("mode", "enforce"),
                priority=spec.get("priority", 100),
                outcome=spec["outcome"],
                conditions=spec["conditions"],
                restrictions=spec.get("restrictions", {}),
                severity=spec.get("severity", "medium"),
                tags=spec.get("tags", []),
                is_builtin=True,
                builtin_key=spec["builtin_key"],
            )
        )
        policies += 1

    existing_rules = set(
        db.execute(select(TrustRule.name, TrustRule.pattern).where(TrustRule.organization_id == org_id)).all()
    )
    rules = 0
    for spec in DEFAULT_TRUST_RULES:
        if (spec["name"], spec["pattern"]) in existing_rules:
            continue
        db.add(
            TrustRule(
                id=new_id("trust_rule"),
                organization_id=org_id,
                name=spec["name"],
                description=spec.get("description"),
                applies_to=spec.get("applies_to", "source"),
                source_type=spec.get("source_type"),
                match_field=spec.get("match_field", "identifier"),
                pattern=spec["pattern"],
                trust_level=spec["trust_level"],
                capabilities=list(spec.get("capabilities", [])),
                priority=spec.get("priority", 100),
                enabled=spec.get("enabled", True),
            )
        )
        rules += 1
    db.flush()
    return {"policies": policies, "trust_rules": rules}
