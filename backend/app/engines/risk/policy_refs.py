"""Static inspection of policy condition trees for posture assessment (pure).

Reads the policy DSL (``{"all"|"any": [...]}``, ``{"not": c}``, ``{"field", "op", "value"}``)
without evaluating it, to answer "which tool categories does this policy positively target?" and
"does it act on field X?". Negated references (``not``, ``neq``, ``not_in``...) never count as
coverage: excluding a category is not governing it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from app.domain.enums import ToolCategory

_NEGATIVE_OPS = {"neq", "not_in", "not_contains", "empty", "is_false"}
_POSITIVE_MATCH_OPS = {"eq", "in", "contains", "glob", "any_glob"}
# A negative op under an odd number of ``not`` is the positive op (``not neq X`` == ``eq X``).
_INVERSE = {"neq": "eq", "not_in": "in", "not_contains": "contains"}
_ALL_CATEGORIES = [c.value for c in ToolCategory]


@dataclass(frozen=True)
class ConditionRef:
    field: str
    op: str
    value: Any
    negated: bool


def condition_refs(conditions: Any, *, negated: bool = False, depth: int = 0) -> list[ConditionRef]:
    if depth > 32 or not isinstance(conditions, dict):
        return []
    refs: list[ConditionRef] = []
    for key in ("all", "any"):
        for child in conditions.get(key) or []:
            refs.extend(condition_refs(child, negated=negated, depth=depth + 1))
    if "not" in conditions:
        refs.extend(condition_refs(conditions["not"], negated=not negated, depth=depth + 1))
    if "field" in conditions:
        op = str(conditions.get("op") or "")
        refs.append(ConditionRef(str(conditions["field"]), op, conditions.get("value"), negated ^ (op in _NEGATIVE_OPS)))
    return refs


def _values(value: Any) -> list[str]:
    if isinstance(value, list | tuple | set):
        return [str(v) for v in value]
    return [str(value)] if value is not None else []


def _positive_op(ref: ConditionRef) -> str | None:
    if ref.negated:
        return None
    op = _INVERSE.get(ref.op, ref.op)
    return op if op in _POSITIVE_MATCH_OPS else None


def _matches(op: str, ref: ConditionRef, candidate: str) -> bool:
    values = _values(ref.value)
    if op in {"glob", "any_glob"}:
        return any(fnmatchcase(candidate, v) for v in values)
    if op == "contains":
        return any(v in candidate for v in values)
    return candidate in values


def references_field(policy: dict[str, Any], prefixes: Iterable[str]) -> bool:
    """True when a non-negated condition reads a field under one of ``prefixes``."""
    wanted = tuple(prefixes)
    for ref in condition_refs(policy.get("conditions")):
        if ref.negated:
            continue
        for prefix in wanted:
            if ref.field == prefix or ref.field.startswith((prefix + ".", prefix + "[")):
                return True
    return False


def covered_categories(policy: dict[str, Any], tools: Iterable[dict[str, Any]]) -> set[str]:
    """Tool categories this policy positively targets via tool.category / tool.name / tool.risk_level."""
    tools = list(tools)
    covered: set[str] = set()
    for ref in condition_refs(policy.get("conditions")):
        op = _positive_op(ref)
        if op is None:
            continue
        if ref.field == "tool.category":
            covered.update(c for c in _ALL_CATEGORIES if _matches(op, ref, c))
        elif ref.field == "tool.name":
            covered.update(str(t.get("category")) for t in tools
                           if t.get("name") and _matches(op, ref, str(t["name"])))
        elif ref.field == "tool.risk_level":
            covered.update(str(t.get("category")) for t in tools
                           if t.get("risk_level") and _matches(op, ref, str(t["risk_level"])))
    covered.discard("None")
    return covered


def is_enabled(policy: dict[str, Any]) -> bool:
    return policy.get("enabled", True) is not False


def is_enforced(policy: dict[str, Any]) -> bool:
    return str(policy.get("mode") or "enforce").lower() == "enforce"


def outcome(policy: dict[str, Any]) -> str:
    return str(policy.get("outcome") or "").upper()
