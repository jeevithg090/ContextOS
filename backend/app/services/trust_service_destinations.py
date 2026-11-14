"""Trust Centre: destination inventory, detail and manual classification.

Destinations have no manual flag of their own: classifying one creates (or updates) an exact-match
destination trust rule with a priority above every other rule that matches it, so the decision
persists through every later assessment by the pipeline and is visible and removable in the Rules
tab like any other rule.

Destination checks look at the name/address only. Nothing here resolves DNS, connects to the
destination or verifies who operates it; responses state that explicitly (``not_verified``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailedError
from app.core.ids import new_id
from app.engines.trust.destinations import parse_destination
from app.models import Agent, Destination, PolicyDecision, SecurityFinding, Tool, ToolInvocation, TrustRule
from app.schemas.trust import PRIORITY_MAX
from app.services.audit import append_audit
from app.services.loaders import load_trust_rule_specs
from app.services.notify import notify
from app.services.scoping import get_scoped, paginate, scoped
from app.services.trust_service_assess import (
    assess_destination_row,
    matching_destination_rules,
    not_verified,
    redact_line,
    store_destination_assessment,
)
from app.services.trust_service_common import (
    ALLOW_LEVELS,
    OVERRIDE_MIN_PRIORITY,
    OVERRIDE_PREFIX,
    Actor,
    is_exact_destination_rule,
    rule_ref,
    rules_by_id,
)
from app.services.trust_service_history import DESTINATION_TARGET
from app.services.trust_service_simulation import real_destination_filter, simulation_only_destinations
from app.services.trust_service_sources import finding_ref

INVOCATIONS_SHOWN = 20
FINDINGS_SHOWN = 20
SORTS: dict[str, Any] = {
    "last_seen": Destination.last_seen_at,
    "first_seen": Destination.first_seen_at,
    "transfers": Destination.transfer_count,
    "blocked": Destination.blocked_count,
    "sensitive": Destination.sensitive_transfer_count,
    "identifier": Destination.identifier,
}


def _like(value: str) -> str:
    escaped = value.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_destinations(
    db: Session,
    org_id: str,
    *,
    classifications: list[str] | None = None,
    kind: str | None = None,
    q: str | None = None,
    has_blocked: bool | None = None,
    include_simulated: bool = False,
    sort: str = "-last_seen",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Destination], int]:
    """Destinations of the organisation; ones only simulated calls were sent to are left out unless
    ``include_simulated``."""
    stmt = scoped(Destination, org_id)
    if not include_simulated:
        stmt = stmt.where(real_destination_filter(org_id))
    if classifications:
        stmt = stmt.where(Destination.classification.in_(classifications))
    if kind:
        stmt = stmt.where(Destination.kind == kind)
    if q and q.strip():
        needle = _like(q)
        stmt = stmt.where(
            or_(
                func.lower(Destination.identifier).like(needle, escape="\\"),
                func.lower(Destination.display_name).like(needle, escape="\\"),
            )
        )
    if has_blocked is not None:
        stmt = stmt.where(Destination.blocked_count > 0 if has_blocked else Destination.blocked_count == 0)
    descending = sort.startswith("-")
    column = SORTS.get(sort.lstrip("-"), Destination.last_seen_at)
    stmt = stmt.order_by(column.desc() if descending else column.asc(), Destination.id)
    return paginate(db, stmt, limit=limit, offset=offset)


def _verification_summary(checks: list[Any]) -> dict[str, int]:
    out = {"passed": 0, "warned": 0, "failed": 0, "unknown": 0}
    key = {"pass": "passed", "warn": "warned", "fail": "failed"}
    for check in checks or []:
        if isinstance(check, dict):
            out[key.get(str(check.get("result")), "unknown")] += 1
    return out


def destination_out(
    row: Destination, rules: dict[str, TrustRule], *, simulation_only: bool = False
) -> dict[str, Any]:
    rule = rules.get(row.trust_rule_id or "")
    return {
        "id": row.id,
        "kind": row.kind,
        "identifier": row.identifier,
        "display_name": row.display_name,
        "classification": row.classification,
        "trust_rule_id": row.trust_rule_id,
        "trust_rule_name": rule.name if rule else None,
        "override_rule_id": rule.id if is_exact_destination_rule(rule, row.identifier) else None,
        "transfer_count": row.transfer_count or 0,
        "blocked_count": row.blocked_count or 0,
        "sensitive_transfer_count": row.sensitive_transfer_count or 0,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "verification": _verification_summary(row.verification or []),
        "is_simulation": simulation_only,
    }


def destinations_out(db: Session, org_id: str, rows: list[Destination]) -> list[dict[str, Any]]:
    rules = rules_by_id(db, org_id, [r.trust_rule_id for r in rows])
    simulated = simulation_only_destinations(db, org_id, [r.id for r in rows])
    return [destination_out(r, rules, simulation_only=r.id in simulated) for r in rows]


def get_destination(db: Session, org_id: str, destination_id: str) -> Destination:
    return get_scoped(db, Destination, destination_id, org_id, label="Destination")


def destination_assessment_out(
    assessment: Any, rules: list[Any], kind: str, identifier: str
) -> dict[str, Any]:
    matching = matching_destination_rules(rules, kind, identifier)
    deciding = next((r for r in matching if r.id == assessment.matched_rule_id), None)
    target = parse_destination(kind, identifier)
    has_host = target.host is not None and target.kind != "email"
    return {
        "scope": "destination",
        "level": assessment.classification,
        "capabilities": ["send"] if assessment.classification in ALLOW_LEVELS else [],
        "reasons": list(assessment.reasons),
        "canonical_identifier": assessment.canonical_identifier,
        "domain": None,
        "kind": assessment.kind,
        "matched_rule": rule_ref(deciding) if deciding else None,
        "matching_rules": [rule_ref(r) for r in matching],
        "checks": [dict(c) for c in assessment.checks],
        "not_verified": not_verified(assessment.kind, has_host, assessment.checks),
    }


def _invocations(db: Session, org_id: str, row: Destination) -> tuple[list[dict[str, Any]], int]:
    base = scoped(ToolInvocation, org_id).where(ToolInvocation.destination_id == row.id)
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    result = db.execute(
        select(ToolInvocation, Tool.name, Agent.name, PolicyDecision.explanation)
        .outerjoin(Tool, (Tool.id == ToolInvocation.tool_id) & (Tool.organization_id == org_id))
        .outerjoin(Agent, (Agent.id == ToolInvocation.agent_id) & (Agent.organization_id == org_id))
        .outerjoin(
            PolicyDecision,
            (PolicyDecision.id == ToolInvocation.policy_decision_id)
            & (PolicyDecision.organization_id == org_id),
        )
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.destination_id == row.id)
        .order_by(ToolInvocation.requested_at.desc(), ToolInvocation.id.desc())
        .limit(INVOCATIONS_SHOWN)
    )
    items = [
        {
            "id": inv.id,
            "session_id": inv.session_id,
            "agent_id": inv.agent_id,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "status": inv.status,
            "decision": inv.decision,
            "enforcement": inv.enforcement,
            "policy_decision_id": inv.policy_decision_id,
            "decision_explanation": (explanation or None) and explanation[:1000],
            "requested_at": inv.requested_at,
            "sensitive_data_detected": bool(inv.sensitive_data_detected),
            "is_simulation": bool(inv.is_simulation),
        }
        for inv, tool_name, agent_name, explanation in result
    ]
    return items, total


def _counts(db: Session, org_id: str, row: Destination, column: Any) -> dict[str, int]:
    rows = db.execute(
        select(column, func.count())
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.destination_id == row.id)
        .group_by(column)
    )
    return {str(value or "none"): int(count) for value, count in rows}


def destination_detail(db: Session, org_id: str, row: Destination) -> dict[str, Any]:
    rules = load_trust_rule_specs(db, org_id, applies_to="destination")
    assessment = assess_destination_row(row, rules)
    invocations, total = _invocations(db, org_id, row)
    findings = list(
        db.scalars(
            scoped(SecurityFinding, org_id)
            .where(SecurityFinding.destination_id == row.id)
            .order_by(SecurityFinding.last_seen_at.desc())
            .limit(FINDINGS_SHOWN)
        )
    )
    return {
        **destination_out(
            row,
            rules_by_id(db, org_id, [row.trust_rule_id]),
            simulation_only=row.id in simulation_only_destinations(db, org_id, [row.id]),
        ),
        "checks": [dict(c) for c in (row.verification or []) if isinstance(c, dict)],
        "assessment": destination_assessment_out(assessment, rules, row.kind, row.identifier),
        "stale": assessment.classification != row.classification,
        "invocations": invocations,
        "invocations_total": total,
        "decision_counts": _counts(db, org_id, row, ToolInvocation.decision),
        "enforcement_counts": _counts(db, org_id, row, ToolInvocation.enforcement),
        "findings": [finding_ref(f) for f in findings],
    }


# ----------------------------------------------------------------------------- classification


def _override_rule(db: Session, org_id: str, identifier: str) -> TrustRule | None:
    rows = db.scalars(
        scoped(TrustRule, org_id)
        .where(
            TrustRule.applies_to == "destination",
            TrustRule.match_field == "identifier",
            func.lower(TrustRule.pattern) == identifier.strip().lower(),
        )
        .order_by(TrustRule.priority.desc(), TrustRule.created_at)
    )
    return next(iter(rows), None)


def _override_name(db: Session, org_id: str, row: Destination, exclude_id: str | None) -> str:
    name = f"{OVERRIDE_PREFIX}{row.identifier}"[:200]
    stmt = scoped(TrustRule, org_id).where(func.lower(TrustRule.name) == name.lower())
    if exclude_id:
        stmt = stmt.where(TrustRule.id != exclude_id)
    if db.scalar(stmt) is None:
        return name
    suffix = f" ({row.id[-6:]})"
    return name[: 200 - len(suffix)] + suffix


def classify_destination(
    db: Session,
    org_id: str,
    actor: Actor,
    row: Destination,
    *,
    classification: str,
    note: str,
) -> tuple[Destination, TrustRule, bool]:
    """Pin a destination's classification with an exact-match rule. Returns (row, rule, created)."""
    identifier = row.identifier.strip()
    if not identifier or any(ch in identifier for ch in "*?"):
        raise ValidationFailedError(
            "This destination cannot be pinned with an exact-match rule",
            details={
                "errors": [
                    "identifier: contains '*' or '?', which trust-rule patterns treat as wildcards; "
                    "create a rule in the Rules tab instead"
                ]
            },
        )
    note_text = redact_line(note, 1000) or ""
    description = redact_line(f"Manually classified by {actor.label}: {note_text}", 2000)
    rule = _override_rule(db, org_id, identifier)
    created = rule is None
    others = [
        r
        for r in load_trust_rule_specs(db, org_id, applies_to="destination")
        if rule is None or r.id != rule.id
    ]
    competing = [r.priority for r in matching_destination_rules(others, row.kind, identifier)]
    priority = min(PRIORITY_MAX, max([OVERRIDE_MIN_PRIORITY - 1, *competing]) + 1)
    capabilities = ["send"] if classification in ALLOW_LEVELS else []
    previous_rule = None
    if rule is None:
        rule = TrustRule(
            id=new_id("trust_rule"),
            organization_id=org_id,
            applies_to="destination",
            source_type=None,
            match_field="identifier",
            pattern=identifier,
            created_by=actor.id if actor.type == "user" else None,
            name=_override_name(db, org_id, row, None),
            enabled=True,
            description=description,
            trust_level=classification,
            capabilities=capabilities,
            priority=priority,
        )
        db.add(rule)
    else:
        previous_rule = {"trust_level": rule.trust_level, "priority": rule.priority, "enabled": rule.enabled}
        rule.trust_level, rule.capabilities, rule.priority = classification, capabilities, priority
        rule.enabled, rule.description = True, description
    db.flush()

    rules = load_trust_rule_specs(db, org_id, applies_to="destination")
    prior = row.classification
    affected = list(
        db.scalars(
            scoped(Destination, org_id).where(func.lower(Destination.identifier) == identifier.lower())
        )
    )
    for dest in affected or [row]:
        before = dest.classification
        store_destination_assessment(dest, assess_destination_row(dest, rules))
        if dest.id != row.id and before != dest.classification:
            append_audit(
                db,
                org_id,
                action="trust.destination_reclassified",
                actor_type=actor.type,
                actor_id=actor.id,
                target_type=DESTINATION_TARGET,
                target_id=dest.id,
                details={
                    "from": before,
                    "to": dest.classification,
                    "rule_id": rule.id,
                    "cause": "trust.destination_classified",
                },
            )
    db.flush()
    append_audit(
        db,
        org_id,
        action="trust_rule.created" if created else "trust_rule.updated",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="trust_rule",
        target_id=rule.id,
        details={
            "name": rule.name,
            "applies_to": "destination",
            "match_field": "identifier",
            "pattern": rule.pattern,
            "trust_level": classification,
            "priority": priority,
            "override_for": row.id,
            **({"previous": previous_rule} if previous_rule else {}),
        },
    )
    append_audit(
        db,
        org_id,
        action="trust.destination_classified",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type=DESTINATION_TARGET,
        target_id=row.id,
        details={
            "from": prior,
            "to": row.classification,
            "requested": classification,
            "rule_id": rule.id,
            "rule_created": created,
            "note": note_text,
        },
    )
    notify(db, org_id, "trust.updated", id=row.id, kind="destination")
    return row, rule, created
