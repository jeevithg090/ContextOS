"""Trust Centre service: trust rules (validated, audited, notified) and bulk re-assessment.

A trust rule classifies sources and/or destinations whose identifier or domain matches a glob
(semantics in ``app.engines.trust.matching``). Rules decide in priority order; on a tie the more
restrictive level wins. After any rule change, stored sources (except manually classified ones)
and destinations are re-assessed with the new rule set, most recently seen first and bounded to
``MAX_REASSESS`` rows each, so the inventory reflects the change immediately; the pipeline applies
the new rules to everything it observes from then on.

Validation refuses rules that could silently over-trust:
- a pattern that matches everything (``*``) or a whole top-level domain (``*.com``) may not grant
  TRUSTED/APPROVED, unless it is a source rule limited to one source type;
- domain patterns are host names only; capabilities must suit the level and scope;
- names, descriptions and patterns must not contain credentials (they are shown in plain text).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ValidationFailedError
from app.core.ids import new_id
from app.engines.redaction import detect_secrets
from app.engines.trust.domains import PUBLIC_SUFFIXES
from app.engines.trust.matching import normalise_pattern
from app.models import ContextSource, Destination, TrustRule
from app.services.audit import append_audit
from app.services.loaders import load_trust_rule_specs
from app.services.notify import notify
from app.services.scoping import get_scoped, scoped
from app.services.trust_service_assess import (
    Evidence,
    assess_destination_row,
    assess_source_row,
    finding_evidence,
    mcp_server_levels,
    source_context,
    store_destination_assessment,
    store_source_assessment,
)
from app.services.trust_service_common import (
    ALLOW_LEVELS,
    OVERRIDE_PREFIX,
    Actor,
    capability_errors,
    is_default_rule,
    is_exact_destination_rule,
    normalise_capabilities,
    rule_sort_key,
    scope_includes,
)
from app.services.trust_service_history import DESTINATION_TARGET, SOURCE_TARGET

MAX_REASSESS = 5000
MAX_AUDITED_CHANGES = 200
EDITABLE_FIELDS = (
    "name",
    "description",
    "applies_to",
    "source_type",
    "match_field",
    "pattern",
    "trust_level",
    "capabilities",
    "priority",
    "enabled",
)
_NOT_NULLABLE = frozenset(EDITABLE_FIELDS) - {"description", "source_type", "capabilities"}
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.*?_")


# ----------------------------------------------------------------------------- validation


def _host_part(pattern: str, match_field: str) -> str:
    text = normalise_pattern(pattern)
    if match_field == "identifier":
        text = text.split("/", 1)[0].rpartition("@")[2]
    return text


def _too_broad(pattern: str, match_field: str) -> str | None:
    text = normalise_pattern(pattern)
    if text in ("*", "**"):
        return "matches every identifier"
    host = _host_part(pattern, match_field)
    if host.startswith("*."):
        rest = host[2:]
        if rest and not any(ch in rest for ch in "*?") and ("." not in rest or rest in PUBLIC_SUFFIXES):
            return f"matches every domain under '.{rest}'"
    return None


def _secret_errors(field: str, value: str | None) -> list[str]:
    if not value:
        return []
    matches = detect_secrets(value)
    if not matches:
        return []
    kinds = ", ".join(sorted({m.secret_type for m in matches}))
    return [f"{field}: looks like a credential ({kinds}); trust rules are shown in plain text, so remove it"]


def rule_errors(data: dict[str, Any]) -> list[str]:
    """Every reason this rule definition cannot be saved (``[]`` = valid)."""
    errors: list[str] = []
    level, applies, field = data["trust_level"], data["applies_to"], data["match_field"]
    pattern = (data.get("pattern") or "").strip()
    normalised = normalise_pattern(pattern)
    if not normalised:
        errors.append("pattern: must not be empty")
    elif field == "domain":
        if any(ch.isspace() for ch in pattern) or any(ch in normalised for ch in "/@:"):
            errors.append(
                "pattern: a domain pattern matches host names only (for example 'docs.acme.com' or "
                "'*.acme.com'); use the identifier field to match URLs, paths or repositories"
            )
        elif not set(normalised) <= _DOMAIN_CHARS:
            errors.append("pattern: a domain pattern may contain only letters, digits, '-', '.', '*' and '?'")
    if applies == "destination" and data.get("source_type"):
        errors.append("source_type: only source rules can be limited to a source type")
    broad = _too_broad(pattern, field) if normalised else None
    if broad and level in ALLOW_LEVELS and not (applies == "source" and data.get("source_type")):
        errors.append(
            f"pattern: '{pattern}' {broad}, so it cannot grant {level}. A rule that broad may only classify as "
            "EXTERNAL, UNKNOWN, SUSPICIOUS or BLOCKED, unless it is a source rule limited to one source type"
        )
    errors += capability_errors(level, applies, data.get("capabilities") or [])
    for key in ("name", "description", "pattern"):
        errors += _secret_errors(key, data.get(key))
    return errors


def _raise_if_invalid(errors: list[str]) -> None:
    if errors:
        raise ValidationFailedError("The trust rule is invalid", details={"errors": errors})


def _ensure_unique_name(db: Session, org_id: str, name: str, *, exclude_id: str | None = None) -> None:
    stmt = scoped(TrustRule, org_id).where(func.lower(TrustRule.name) == name.lower())
    if exclude_id:
        stmt = stmt.where(TrustRule.id != exclude_id)
    if db.scalar(stmt) is not None:
        raise ConflictError(f'A trust rule named "{name}" already exists')


# ----------------------------------------------------------------------------- queries


def list_rules(
    db: Session,
    org_id: str,
    *,
    applies_to: str | None = None,
    enabled: bool | None = None,
    q: str | None = None,
) -> list[TrustRule]:
    stmt = scoped(TrustRule, org_id)
    if applies_to:
        stmt = stmt.where(TrustRule.applies_to.in_([applies_to, "both"]))
    if enabled is not None:
        stmt = stmt.where(TrustRule.enabled.is_(enabled))
    if q and q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(TrustRule.name).like(needle),
                func.lower(TrustRule.pattern).like(needle),
                func.lower(TrustRule.description).like(needle),
            )
        )
    return sorted(db.scalars(stmt), key=rule_sort_key)


def get_rule(db: Session, org_id: str, rule_id: str) -> TrustRule:
    return get_scoped(db, TrustRule, rule_id, org_id, label="Trust rule")


def rule_usage(db: Session, org_id: str) -> dict[str, tuple[int, int]]:
    """Rule id -> (sources, destinations) currently classified by that rule."""
    usage: dict[str, list[int]] = {}
    for model, idx in ((ContextSource, 0), (Destination, 1)):
        rows = db.execute(
            select(model.trust_rule_id, func.count())
            .where(model.organization_id == org_id, model.trust_rule_id.is_not(None))
            .group_by(model.trust_rule_id)
        )
        for rule_id, count in rows:
            usage.setdefault(rule_id, [0, 0])[idx] = int(count)
    return {k: (v[0], v[1]) for k, v in usage.items()}


def rule_out(
    row: TrustRule, usage: dict[str, tuple[int, int]], reassessment: dict[str, Any] | None = None
) -> dict[str, Any]:
    sources, destinations = usage.get(row.id, (0, 0))
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "applies_to": row.applies_to,
        "source_type": row.source_type,
        "match_field": row.match_field,
        "pattern": row.pattern,
        "trust_level": row.trust_level,
        "capabilities": [str(c) for c in (row.capabilities or [])],
        "priority": row.priority,
        "enabled": row.enabled,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "is_default": is_default_rule(row),
        "is_override": is_exact_destination_rule(row) and row.name.startswith(OVERRIDE_PREFIX),
        "classified_sources": sources,
        "classified_destinations": destinations,
        "reassessment": reassessment,
    }


def _summary(row: TrustRule) -> dict[str, Any]:
    return {f: getattr(row, f) for f in EDITABLE_FIELDS if f != "description"}


# ----------------------------------------------------------------------------- mutations


def _scopes(*applies: str | None) -> tuple[bool, bool]:
    return (
        any(scope_includes(a, "source") for a in applies),
        any(scope_includes(a, "destination") for a in applies),
    )


def create_rule(
    db: Session, org_id: str, actor: Actor, data: dict[str, Any]
) -> tuple[TrustRule, dict[str, Any]]:
    data = dict(data)
    data["capabilities"] = normalise_capabilities(
        data.get("capabilities"), data["trust_level"], data["applies_to"]
    )
    _raise_if_invalid(rule_errors(data))
    _ensure_unique_name(db, org_id, data["name"])
    row = TrustRule(
        id=new_id("trust_rule"),
        organization_id=org_id,
        name=data["name"],
        description=data.get("description"),
        applies_to=data["applies_to"],
        source_type=data.get("source_type"),
        match_field=data["match_field"],
        pattern=data["pattern"],
        trust_level=data["trust_level"],
        capabilities=data["capabilities"],
        priority=data.get("priority", 100),
        enabled=data.get("enabled", True),
        created_by=actor.id if actor.type == "user" else None,
    )
    db.add(row)
    db.flush()
    sources, destinations = _scopes(row.applies_to)
    result = reassess_all(
        db,
        org_id,
        actor,
        sources=sources,
        destinations=destinations,
        cause={"cause": "trust_rule.created", "rule_id": row.id},
    )
    append_audit(
        db,
        org_id,
        action="trust_rule.created",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="trust_rule",
        target_id=row.id,
        details={**_summary(row), "reassessment": result},
    )
    notify(db, org_id, "trust.updated", id=row.id, kind="trust_rule", change="created")
    return row, result


def update_rule(
    db: Session, org_id: str, actor: Actor, row: TrustRule, changes: dict[str, Any]
) -> tuple[TrustRule, dict[str, Any] | None]:
    """Apply a partial update. Returns ``(rule, None)`` without writing anything if nothing differs."""
    nulls = sorted(f for f, v in changes.items() if v is None and f in _NOT_NULLABLE)
    if nulls:
        raise ValidationFailedError(
            "These fields cannot be cleared", details={"errors": [f"{f}: may not be null" for f in nulls]}
        )
    merged = {f: getattr(row, f) for f in EDITABLE_FIELDS}
    merged.update({f: v for f, v in changes.items() if f in EDITABLE_FIELDS})
    level_or_scope_changed = (
        merged["trust_level"] != row.trust_level or merged["applies_to"] != row.applies_to
    )
    if "capabilities" not in changes and level_or_scope_changed:
        merged["capabilities"] = None  # re-derive the defaults for the new level/scope
    merged["capabilities"] = normalise_capabilities(
        merged["capabilities"], merged["trust_level"], merged["applies_to"]
    )
    if merged["applies_to"] == "destination" and "source_type" not in changes:
        merged["source_type"] = None
    changed = {f: merged[f] for f in EDITABLE_FIELDS if merged[f] != getattr(row, f)}
    if not changed:
        return row, None
    if set(changed) != {"enabled"} or changed.get("enabled") is True:  # disabling is always possible
        _raise_if_invalid(rule_errors(merged))
    if "name" in changed:
        _ensure_unique_name(db, org_id, changed["name"], exclude_id=row.id)
    old_applies = row.applies_to
    diff = {
        f: {"from": getattr(row, f) if f != "description" else None, "to": v if f != "description" else None}
        for f, v in changed.items()
    }
    for f, v in changed.items():
        setattr(row, f, v)
    db.flush()
    evaluation_fields = set(changed) - {"name", "description"}
    result = None
    if evaluation_fields:
        sources, destinations = _scopes(old_applies, row.applies_to)
        result = reassess_all(
            db,
            org_id,
            actor,
            sources=sources,
            destinations=destinations,
            cause={"cause": "trust_rule.updated", "rule_id": row.id},
        )
    append_audit(
        db,
        org_id,
        action="trust_rule.updated",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="trust_rule",
        target_id=row.id,
        details={"name": row.name, "changes": diff, "reassessment": result},
    )
    notify(db, org_id, "trust.updated", id=row.id, kind="trust_rule", change="updated")
    return row, result


def delete_rule(db: Session, org_id: str, actor: Actor, row: TrustRule) -> dict[str, Any]:
    details = _summary(row)
    rule_id, applies = row.id, row.applies_to
    db.delete(row)
    db.flush()
    sources, destinations = _scopes(applies)
    result = reassess_all(
        db,
        org_id,
        actor,
        sources=sources,
        destinations=destinations,
        cause={"cause": "trust_rule.deleted", "rule_id": rule_id},
    )
    append_audit(
        db,
        org_id,
        action="trust_rule.deleted",
        actor_type=actor.type,
        actor_id=actor.id,
        target_type="trust_rule",
        target_id=rule_id,
        details={**details, "reassessment": result},
    )
    notify(db, org_id, "trust.updated", id=rule_id, kind="trust_rule", change="deleted")
    return result


# ----------------------------------------------------------------------------- bulk re-assessment


def reassess_all(
    db: Session,
    org_id: str,
    actor: Actor,
    *,
    sources: bool,
    destinations: bool,
    cause: dict[str, Any],
) -> dict[str, Any]:
    """Re-assess stored sources (not manually classified) and destinations with the current rules.

    Each class is bounded to ``MAX_REASSESS`` rows, most recently seen first. The first
    ``MAX_AUDITED_CHANGES`` reclassifications get their own audit entry; the counts are returned
    (and recorded on the rule change's own audit entry).
    """
    db.flush()
    out = {
        "sources_checked": 0,
        "sources_changed": 0,
        "destinations_checked": 0,
        "destinations_changed": 0,
        "truncated": False,
        "limit": MAX_REASSESS,
    }
    audited = 0

    def audit_change(
        target_type: str, target_id: str, action: str, old: str, new: str, reason: str | None
    ) -> None:
        nonlocal audited
        if audited >= MAX_AUDITED_CHANGES:
            return
        audited += 1
        append_audit(
            db,
            org_id,
            action=action,
            actor_type=actor.type,
            actor_id=actor.id,
            target_type=target_type,
            target_id=target_id,
            details={"from": old, "to": new, **cause, "reason": reason},
        )

    if sources:
        rows = list(
            db.scalars(
                scoped(ContextSource, org_id)
                .where(ContextSource.manually_classified.is_(False))
                .order_by(ContextSource.last_seen_at.desc(), ContextSource.id)
                .limit(MAX_REASSESS + 1)
            )
        )
        out["truncated"] = len(rows) > MAX_REASSESS
        rows = rows[:MAX_REASSESS]
        rows.sort(key=lambda r: r.source_type != "mcp_server")  # servers first: they cap their tools' output
        rules = load_trust_rule_specs(db, org_id, applies_to="source")
        evidence = finding_evidence(db, org_id, [r.id for r in rows])
        server_levels = mcp_server_levels(db, org_id)
        for row in rows:
            ctx = source_context(
                db, org_id, row, server_levels=server_levels, evidence=evidence.get(row.id, Evidence())
            )
            prior = store_source_assessment(row, assess_source_row(row, rules, ctx), ctx)
            if row.source_type == "mcp_server":
                server_levels[row.identifier] = row.trust_level
            out["sources_checked"] += 1
            if prior != row.trust_level:
                out["sources_changed"] += 1
                audit_change(
                    SOURCE_TARGET,
                    row.id,
                    "trust.source_reclassified",
                    prior,
                    row.trust_level,
                    row.trust_reasons[-1] if row.trust_reasons else None,
                )

    if destinations:
        dest_rows = list(
            db.scalars(
                scoped(Destination, org_id)
                .order_by(Destination.last_seen_at.desc(), Destination.id)
                .limit(MAX_REASSESS + 1)
            )
        )
        out["truncated"] = bool(out["truncated"] or len(dest_rows) > MAX_REASSESS)
        rules = load_trust_rule_specs(db, org_id, applies_to="destination")
        for dest in dest_rows[:MAX_REASSESS]:
            assessment = assess_destination_row(dest, rules)
            prior = store_destination_assessment(dest, assessment)
            out["destinations_checked"] += 1
            if prior != dest.classification:
                out["destinations_changed"] += 1
                audit_change(
                    DESTINATION_TARGET,
                    dest.id,
                    "trust.destination_reclassified",
                    prior,
                    dest.classification,
                    assessment.reasons[0] if assessment.reasons else None,
                )
    db.flush()
    if out["sources_changed"] or out["destinations_changed"]:
        notify(db, org_id, "trust.updated", id=cause.get("rule_id"), kind="reassessment")
    return out
