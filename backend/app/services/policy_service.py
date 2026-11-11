"""Policy Studio service: policy CRUD (validated, audited, notified), match statistics over recorded
decisions and recorded-decision lookups. Dry-run evaluation lives in ``policy_testing`` (re-exported
here as ``run_policy_test``).

Rules enforced here:
- A policy is saved only if its conditions pass ``validate_conditions``, its restrictions pass
  ``validate_restrictions`` for its outcome, and no value looks like a credential (policies are
  stored and displayed in plain text, so embedding a secret would leak it).
- ``version`` increases whenever a field that changes evaluation results changes
  (``EVALUATION_FIELDS``), so recorded ``PolicyMatch.version`` values identify what was evaluated.
- Built-in policies may be edited and disabled but not deleted.
- Dry-run tests never persist anything; results are simulations, not historical outcomes. A
  recorded decision is re-evaluated against its stored, redacted ``input_snapshot`` only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import ensure_utc, utcnow
from app.domain.enums import DECISION_PRECEDENCE
from app.engines.policy import (
    explain_conditions,
    validate_conditions,
    validate_restrictions,
)
from app.engines.policy.restrictions import describe_restrictions
from app.engines.redaction import detect_secrets
from app.models import PolicyDecision, SecurityPolicy
from app.services.audit import append_audit
from app.services.notify import notify
from app.services.scoping import get_scoped, paginate, scoped

STATS_WINDOW_DAYS = 7
EDITABLE_FIELDS = (
    "name", "description", "outcome", "mode", "enabled", "priority", "severity", "conditions", "restrictions", "tags",
)
# Every PolicySpec field that can change an evaluation result (or the recorded match).
EVALUATION_FIELDS = frozenset({"conditions", "outcome", "mode", "enabled", "restrictions", "priority", "severity"})
_NOT_NULLABLE = frozenset(EDITABLE_FIELDS) - {"description"}


@dataclass(frozen=True)
class Actor:
    type: str  # "user" | "api_key" | "system"
    id: str | None


# ----------------------------------------------------------------------------- validation


def _secret_errors(value: Any, loc: str) -> list[str]:
    if isinstance(value, str):
        matches = detect_secrets(value)
        if not matches:
            return []
        kinds = ", ".join(sorted({m.secret_type for m in matches}))
        return [f"{loc}: looks like a credential ({kinds}). Policies are stored and shown in plain text, so they "
                "must not contain secrets; match on secrets_in_arguments[*].type instead"]
    if isinstance(value, dict):
        return [e for k, v in value.items() for e in _secret_errors(v, f"{loc}.{k}")]
    if isinstance(value, list):
        return [e for i, v in enumerate(value) for e in _secret_errors(v, f"{loc}[{i}]")]
    return []


def definition_errors(
    *, outcome: str | None, conditions: Any, restrictions: Any, name: str | None = None, description: str | None = None
) -> list[str]:
    """Every reason this policy definition cannot be saved (``[]`` = valid)."""
    errors = list(validate_conditions(conditions))
    errors += validate_restrictions(restrictions if restrictions is not None else {}, outcome=outcome)
    errors += _secret_errors(conditions, "conditions") + _secret_errors(restrictions, "restrictions")
    errors += _secret_errors(name, "name") + _secret_errors(description, "description")
    return errors


def validate_draft(conditions: Any, *, outcome: str | None = None, restrictions: Any = None) -> dict[str, Any]:
    errors = list(validate_conditions(conditions)) + _secret_errors(conditions, "conditions")
    if outcome is not None or restrictions is not None:
        errors += validate_restrictions(restrictions if restrictions is not None else {}, outcome=outcome)
        errors += _secret_errors(restrictions, "restrictions")
    explanation = explain_conditions(conditions) if not errors and isinstance(conditions, dict) else None
    return {"valid": not errors, "errors": errors, "explanation": explanation}


def _raise_if_invalid(errors: list[str], message: str) -> None:
    if errors:
        raise ValidationFailedError(message, details={"errors": errors})


# ----------------------------------------------------------------------------- queries


def _sort_key(row: SecurityPolicy) -> tuple[int, int, str, str]:
    precedence = DECISION_PRECEDENCE.get(str(row.outcome).upper(), -1)
    return (-precedence, -int(row.priority or 0), row.name.casefold(), row.id)


def list_policies(
    db: Session,
    org_id: str,
    *,
    enabled: bool | None = None,
    mode: str | None = None,
    outcome: str | None = None,
    builtin: bool | None = None,
    q: str | None = None,
) -> list[SecurityPolicy]:
    """Org policies ordered as the engine ranks them: outcome precedence, then priority, then name."""
    stmt = scoped(SecurityPolicy, org_id)
    if enabled is not None:
        stmt = stmt.where(SecurityPolicy.enabled.is_(enabled))
    if mode:
        stmt = stmt.where(SecurityPolicy.mode == mode)
    if outcome:
        stmt = stmt.where(SecurityPolicy.outcome == outcome)
    if builtin is not None:
        stmt = stmt.where(SecurityPolicy.is_builtin.is_(builtin))
    if q and q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(func.lower(SecurityPolicy.name).like(needle), func.lower(SecurityPolicy.description).like(needle))
        )
    return sorted(db.scalars(stmt), key=_sort_key)


def get_policy(db: Session, org_id: str, policy_id: str) -> SecurityPolicy:
    return get_scoped(db, SecurityPolicy, policy_id, org_id, label="Policy")


def _policy_ids(entries: Any) -> set[str]:
    if not isinstance(entries, list):
        return set()
    return {e["policy_id"] for e in entries if isinstance(e, dict) and isinstance(e.get("policy_id"), str)}


def empty_stats(days: int = STATS_WINDOW_DAYS) -> dict[str, Any]:
    return {"window_days": days, "matched": 0, "monitor_matched": 0, "simulated": 0, "last_matched_at": None,
            "daily": [0] * days}


def match_stats(
    db: Session, org_id: str, *, days: int = STATS_WINDOW_DAYS, now: datetime | None = None
) -> dict[str, dict[str, Any]]:
    """Per-policy match counts over the last ``days`` UTC days (today included), from recorded
    ``PolicyDecision.matched_policies`` / ``monitor_matches``. Counted in Python so the query stays
    portable across SQLite and PostgreSQL JSON columns; rows are streamed, not loaded at once."""
    now = ensure_utc(now) or utcnow()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    stmt = select(
        PolicyDecision.evaluated_at,
        PolicyDecision.matched_policies,
        PolicyDecision.monitor_matches,
        PolicyDecision.is_simulation,
    ).where(PolicyDecision.organization_id == org_id, PolicyDecision.evaluated_at >= start)
    stats: dict[str, dict[str, Any]] = {}
    for evaluated_at, matched, monitor, is_simulation in db.execute(stmt, execution_options={"yield_per": 2000}):
        when = ensure_utc(evaluated_at) or now
        day = min(max((when.date() - start.date()).days, 0), days - 1)
        for key, pids in (("matched", _policy_ids(matched)), ("monitor_matched", _policy_ids(monitor))):
            for pid in pids:
                entry = stats.setdefault(pid, empty_stats(days))
                if is_simulation:
                    entry["simulated"] += 1
                    continue
                entry[key] += 1
                entry["daily"][day] += 1
                if entry["last_matched_at"] is None or when > entry["last_matched_at"]:
                    entry["last_matched_at"] = when
    return stats


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def decision_summary(row: PolicyDecision) -> dict[str, Any]:
    snapshot = row.input_snapshot if isinstance(row.input_snapshot, dict) else {}
    agent = snapshot.get("agent") if isinstance(snapshot.get("agent"), dict) else {}
    tool = snapshot.get("tool") if isinstance(snapshot.get("tool"), dict) else {}
    return {
        "id": row.id,
        "session_id": row.session_id,
        "agent_id": row.agent_id,
        "agent_name": _str_or_none(agent.get("name")),
        "tool_name": _str_or_none(tool.get("name")),
        "tool_category": _str_or_none(tool.get("category")),
        "decision": row.decision,
        "enforcement": row.enforcement,
        "evaluated_at": row.evaluated_at,
        "explanation": row.explanation or "",
        "is_simulation": bool(row.is_simulation),
    }


def _find_entry(entries: Any, policy_id: str) -> dict[str, Any] | None:
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("policy_id") == policy_id:
                return entry
    return None


def _like_contains_quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f'%"{escaped}"%'


def decisions_for_policy(
    db: Session, org_id: str, policy_id: str, *, days: int, limit: int, offset: int, include_simulation: bool
) -> tuple[list[dict[str, Any]], int]:
    """Recorded decisions (newest first) in which the policy matched, in enforce or monitor mode."""
    get_policy(db, org_id, policy_id)
    pattern = _like_contains_quoted(policy_id)
    stmt = (
        select(PolicyDecision.id, PolicyDecision.matched_policies, PolicyDecision.monitor_matches)
        .where(
            PolicyDecision.organization_id == org_id,
            PolicyDecision.evaluated_at >= utcnow() - timedelta(days=days),
            # Cheap text pre-filter on the JSON columns; every candidate is confirmed below.
            or_(
                cast(PolicyDecision.matched_policies, String).like(pattern, escape="\\"),
                cast(PolicyDecision.monitor_matches, String).like(pattern, escape="\\"),
            ),
        )
        .order_by(PolicyDecision.evaluated_at.desc(), PolicyDecision.id.desc())
    )
    if not include_simulation:
        stmt = stmt.where(PolicyDecision.is_simulation.is_(False))
    hits: list[tuple[str, str, dict[str, Any]]] = []
    for decision_id, matched, monitor in db.execute(stmt):
        entry, mode = _find_entry(matched, policy_id), "enforce"
        if entry is None:
            entry, mode = _find_entry(monitor, policy_id), "monitor"
        if entry is not None:
            hits.append((decision_id, mode, entry))
    page = hits[offset : offset + limit]
    rows = {
        r.id: r
        for r in db.scalars(scoped(PolicyDecision, org_id).where(PolicyDecision.id.in_([h[0] for h in page])))
    } if page else {}
    items = []
    for decision_id, mode, entry in page:
        row = rows.get(decision_id)
        if row is None:
            continue
        version = entry.get("version")
        items.append({
            **decision_summary(row),
            "match_mode": mode,
            "matched_outcome": str(entry.get("outcome") or ""),
            "matched_version": version if isinstance(version, int) and not isinstance(version, bool) else None,
            "match_explanation": str(entry.get("explanation") or ""),
        })
    return items, len(hits)


def recent_decisions(
    db: Session,
    org_id: str,
    *,
    limit: int,
    offset: int,
    decision: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    include_simulation: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """Recorded decisions to pick as dry-run test inputs (newest first)."""
    stmt = scoped(PolicyDecision, org_id)
    if decision:
        stmt = stmt.where(PolicyDecision.decision == decision)
    if session_id:
        stmt = stmt.where(PolicyDecision.session_id == session_id)
    if agent_id:
        stmt = stmt.where(PolicyDecision.agent_id == agent_id)
    if not include_simulation:
        stmt = stmt.where(PolicyDecision.is_simulation.is_(False))
    stmt = stmt.order_by(PolicyDecision.evaluated_at.desc(), PolicyDecision.id.desc())
    rows, total = paginate(db, stmt, limit=limit, offset=offset)
    return [decision_summary(r) for r in rows], total


# ----------------------------------------------------------------------------- mutations


def _ensure_unique_name(db: Session, org_id: str, name: str, *, exclude_id: str | None = None) -> None:
    stmt = scoped(SecurityPolicy, org_id).where(func.lower(SecurityPolicy.name) == name.lower())
    if exclude_id:
        stmt = stmt.where(SecurityPolicy.id != exclude_id)
    if db.scalar(stmt) is not None:
        raise ConflictError(f'A policy named "{name}" already exists')


def _describe(field: str, value: Any) -> Any:
    """Short, content-free audit representation of a field value."""
    if field == "conditions":
        return explain_conditions(value if isinstance(value, dict) else {})[:1000]
    if field == "restrictions":
        return describe_restrictions(value) if isinstance(value, dict) else None
    if field == "description":
        return (value or "")[:200] or None
    return value


def _summary(row: SecurityPolicy) -> dict[str, Any]:
    return {
        "name": row.name,
        "outcome": row.outcome,
        "mode": row.mode,
        "enabled": row.enabled,
        "priority": row.priority,
        "severity": row.severity,
        "version": row.version,
        "is_builtin": row.is_builtin,
        "conditions": _describe("conditions", row.conditions),
    }


def create_policy(db: Session, org_id: str, actor: Actor, data: dict[str, Any]) -> SecurityPolicy:
    _raise_if_invalid(
        definition_errors(outcome=data["outcome"], conditions=data["conditions"],
                          restrictions=data.get("restrictions") or {}, name=data["name"],
                          description=data.get("description")),
        "The policy is invalid",
    )
    _ensure_unique_name(db, org_id, data["name"])
    row = SecurityPolicy(
        id=new_id("policy"),
        organization_id=org_id,
        name=data["name"],
        description=data.get("description"),
        enabled=data.get("enabled", True),
        mode=data.get("mode", "enforce"),
        priority=data.get("priority", 100),
        outcome=data["outcome"],
        conditions=data["conditions"],
        restrictions=data.get("restrictions") or {},
        severity=data.get("severity", "medium"),
        tags=list(data.get("tags") or []),
        version=1,
        is_builtin=False,
        created_by=actor.id if actor.type == "user" else None,
    )
    db.add(row)
    db.flush()
    append_audit(db, org_id, action="policy.created", actor_type=actor.type, actor_id=actor.id,
                 target_type="policy", target_id=row.id, details=_summary(row))
    notify(db, org_id, "policy.updated", id=row.id, change="created")
    return row


def update_policy(
    db: Session, org_id: str, actor: Actor, policy: SecurityPolicy, changes: dict[str, Any]
) -> SecurityPolicy:
    """Apply a partial update. Returns the policy unchanged (and writes no audit) if nothing differs."""
    nulls = sorted(f for f, v in changes.items() if v is None and f in _NOT_NULLABLE)
    if nulls:
        raise ValidationFailedError("These fields cannot be cleared", details={"errors": [f"{f}: may not be null" for f in nulls]})
    changed = {f: v for f, v in changes.items() if f in EDITABLE_FIELDS and getattr(policy, f) != v}
    if not changed:
        return policy
    # Disabling must always be possible, even for a policy stored before validation tightened.
    definition_touched = bool({"conditions", "outcome", "restrictions", "name", "description"} & set(changed))
    if definition_touched or changed.get("enabled") is True:
        _raise_if_invalid(
            definition_errors(
                outcome=changed.get("outcome", policy.outcome),
                conditions=changed.get("conditions", policy.conditions),
                restrictions=changed.get("restrictions", policy.restrictions),
                name=changed.get("name"),
                description=changed.get("description"),
            ),
            "The policy is invalid",
        )
    if "name" in changed:
        _ensure_unique_name(db, org_id, changed["name"], exclude_id=policy.id)
    diff = {f: {"from": _describe(f, getattr(policy, f)), "to": _describe(f, v)} for f, v in changed.items()}
    old_version = policy.version
    for field, value in changed.items():
        setattr(policy, field, value)
    if EVALUATION_FIELDS & set(changed):
        policy.version = (policy.version or 1) + 1
    db.flush()
    append_audit(
        db, org_id, action="policy.updated", actor_type=actor.type, actor_id=actor.id, target_type="policy",
        target_id=policy.id,
        details={"name": policy.name, "is_builtin": policy.is_builtin,
                 "version": {"from": old_version, "to": policy.version}, "changes": diff},
    )
    notify(db, org_id, "policy.updated", id=policy.id, change="updated")
    return policy


def delete_policy(db: Session, org_id: str, actor: Actor, policy: SecurityPolicy) -> None:
    if policy.is_builtin:
        raise ConflictError("Built-in policies cannot be deleted. Disable it instead; you can re-enable it later.")
    details = _summary(policy)
    policy_id = policy.id
    db.delete(policy)
    db.flush()
    append_audit(db, org_id, action="policy.deleted", actor_type=actor.type, actor_id=actor.id,
                 target_type="policy", target_id=policy_id, details=details)
    notify(db, org_id, "policy.updated", id=policy_id, change="deleted")


def __getattr__(name: str) -> Any:
    """Lazy re-export of the dry-run API (``policy_testing`` imports this module, so a top-level
    import would be circular)."""
    if name in ("run_policy_test", "MAX_TEST_INPUT_BYTES", "DRAFT_ID"):
        from app.services import policy_testing

        return getattr(policy_testing, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

