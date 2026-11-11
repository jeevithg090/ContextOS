"""Trust Centre shared helpers: actors, rule references and capability rules.

Capability semantics (mirrors ``app.engines.trust.sources``):
- Sources may be granted ``read``, ``instruct``, ``execute`` and ``credential_access``. Only TRUSTED
  and APPROVED sources may get more than ``read``: EXTERNAL / UNKNOWN / SUSPICIOUS content is always
  data. BLOCKED grants nothing.
- Destinations may be granted ``send``, and only when TRUSTED or APPROVED.
- Trust is contextual: "approved for reading" does not mean "trusted to give instructions".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.enums import TRUST_RANK, TrustCapability, TrustLevel
from app.engines.trust import TrustRuleSpec
from app.engines.trust.defaults import DEFAULT_TRUST_RULES
from app.engines.trust.sources import DEFAULT_CAPABILITIES
from app.models import TrustRule, User

C = TrustCapability
SOURCE_CAPABILITIES = (C.READ.value, C.INSTRUCT.value, C.EXECUTE.value, C.CREDENTIAL_ACCESS.value)
DESTINATION_CAPABILITIES = (C.SEND.value,)
ALLOW_LEVELS = frozenset({TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value})
DATA_ONLY_LEVELS = frozenset({TrustLevel.EXTERNAL.value, TrustLevel.UNKNOWN.value, TrustLevel.SUSPICIOUS.value})
OVERRIDE_PREFIX = "Destination override: "
OVERRIDE_MIN_PRIORITY = 1000
DEFAULT_RULE_KEYS = frozenset((r["name"], r["pattern"]) for r in DEFAULT_TRUST_RULES)
SYSTEM_LABEL = "ContextOS"


@dataclass(frozen=True)
class Actor:
    type: str  # "user" | "api_key" | "system"
    id: str | None
    label: str = ""


def user_labels(db: Session, user_ids: Iterable[str | None]) -> dict[str, str]:
    ids = sorted({u for u in user_ids if u})
    if not ids:
        return {}
    return {uid: (name or email) for uid, name, email in db.execute(
        select(User.id, User.name, User.email).where(User.id.in_(ids))
    )}


def actor_label(actor_type: str | None, actor_id: str | None, users: dict[str, str]) -> str:
    if actor_type == "user":
        return users.get(actor_id or "", "A user who is no longer a member")
    if actor_type == "api_key":
        return "An integration (API key)"
    return SYSTEM_LABEL


def make_actor(db: Session, actor_type: str, actor_id: str | None) -> Actor:
    return Actor(type=actor_type, id=actor_id, label=actor_label(actor_type, actor_id, user_labels(db, [actor_id])))


# ----------------------------------------------------------------------------- rules


def scope_includes(applies_to: str | None, scope: str) -> bool:
    return applies_to in (scope, "both")


def rule_ref(rule: TrustRuleSpec | TrustRule, *, is_draft: bool = False) -> dict[str, Any]:
    return {
        "id": None if is_draft else rule.id,
        "name": rule.name,
        "pattern": rule.pattern,
        "match_field": rule.match_field,
        "applies_to": rule.applies_to,
        "source_type": rule.source_type,
        "trust_level": rule.trust_level,
        "priority": int(rule.priority or 0),
        "is_draft": is_draft,
    }


def rule_sort_key(rule: TrustRule) -> tuple[int, int, int, str, str]:
    """Display order = engine precedence: priority, then the more restrictive level, then specificity."""
    return (-int(rule.priority or 0), TRUST_RANK.get(rule.trust_level, 0), -len(rule.pattern or ""),
            rule.name.casefold(), rule.id)


def rules_by_id(db: Session, org_id: str, ids: Iterable[str | None]) -> dict[str, TrustRule]:
    wanted = sorted({i for i in ids if i})
    if not wanted:
        return {}
    rows = db.scalars(select(TrustRule).where(TrustRule.organization_id == org_id, TrustRule.id.in_(wanted)))
    return {r.id: r for r in rows}


def is_default_rule(rule: TrustRule) -> bool:
    return (rule.name, rule.pattern) in DEFAULT_RULE_KEYS


def is_exact_destination_rule(rule: TrustRule | None, identifier: str | None = None) -> bool:
    """An exact-match destination rule (what classifying a destination creates)."""
    if rule is None or rule.applies_to != "destination" or rule.match_field != "identifier":
        return False
    if any(ch in (rule.pattern or "") for ch in "*?"):
        return False
    return identifier is None or (rule.pattern or "").strip().lower() == identifier.strip().lower()


# ----------------------------------------------------------------------------- capabilities


def allowed_capabilities(applies_to: str) -> tuple[str, ...]:
    if applies_to == "source":
        return SOURCE_CAPABILITIES
    if applies_to == "destination":
        return DESTINATION_CAPABILITIES
    return SOURCE_CAPABILITIES + DESTINATION_CAPABILITIES


def default_capabilities(level: str, applies_to: str) -> list[str]:
    caps: list[str] = []
    if applies_to in ("source", "both"):
        caps += [str(c) for c in DEFAULT_CAPABILITIES.get(level, ())]  # type: ignore[call-overload]
    if applies_to in ("destination", "both") and level in ALLOW_LEVELS:
        caps.append(C.SEND.value)
    return caps


def normalise_capabilities(capabilities: Sequence[str] | None, level: str, applies_to: str) -> list[str]:
    if not capabilities:
        return default_capabilities(level, applies_to)
    order = {c: i for i, c in enumerate(SOURCE_CAPABILITIES + DESTINATION_CAPABILITIES)}
    return sorted(dict.fromkeys(str(c) for c in capabilities), key=lambda c: order.get(c, 99))


def capability_errors(level: str, applies_to: str, capabilities: Sequence[str]) -> list[str]:
    """Why ``capabilities`` cannot be granted at ``level`` (``[]`` = valid)."""
    errors: list[str] = []
    allowed = allowed_capabilities(applies_to)
    for cap in capabilities:
        if cap not in allowed:
            if cap == C.SEND.value:
                errors.append("capabilities: 'send' applies to destinations only")
            else:
                errors.append(f"capabilities: '{cap}' applies to sources only")
    granted = [c for c in capabilities if c in allowed]
    if level == TrustLevel.BLOCKED.value and granted:
        errors.append("capabilities: BLOCKED grants no capabilities — leave them empty")
    elif level in DATA_ONLY_LEVELS:
        beyond_read = [c for c in granted if c in SOURCE_CAPABILITIES and c != C.READ.value]
        if beyond_read:
            listed = ", ".join(f"'{c}'" for c in beyond_read)
            errors.append(
                f"capabilities: {level} content is always treated as data, so only 'read' can be granted "
                f"(remove {listed})"
            )
        if C.SEND.value in granted:
            errors.append("capabilities: only TRUSTED or APPROVED destinations can be granted 'send'")
    return errors
