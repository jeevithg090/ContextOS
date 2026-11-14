"""Evaluation and plain-English rendering of the condition DSL.

Semantics (see the package docstring for the grammar):

* A field path is resolved against ``EvaluationInput.to_dict()``. ``[*]`` means "any element of
  this list" and ``.*`` "any value of this object" (e.g. ``arguments.*`` = any top-level argument):
  the leaf holds when at least one element satisfies it. ``[N]`` picks one element.
* A field that is absent or ``null`` is *missing*. Every operator except ``exists`` is false on a
  missing field (``exists`` is false too); test absence with ``{"not": {..., "op": "exists"}}``.
  Missing fields are recorded so explanations can say which inputs were not available.
* String comparison (eq/neq/in/not_in/contains/not_contains/glob/any_glob) is case-insensitive.
  Globs use ``fnmatch`` semantics: ``*`` also matches ``/``.
* gt/gte/lt/lte compare numbers, or the rank of ordered enum fields (severity, risk level, trust).
  Booleans are never numbers.
* On list fields ``contains`` tests membership, ``in`` tests "any element is one of", ``not_in``
  "no element is one of".
* An empty condition (``{}``, ``{"all": []}``, ``{"any": []}``) matches nothing — never everything.
  A structurally invalid node raises :class:`ConditionError`; the engine then treats the policy as
  not matching and reports the error.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from app.engines.policy.fields import COMPARISON_OPS, OPS, WILDCARD, lookup_field, parse_path, rank_of

MAX_DEPTH = 16
_MISSING = object()


class ConditionError(ValueError):
    """Raised for a structurally invalid condition encountered during evaluation."""


@dataclass
class Outcome:
    matched: bool
    evidence: list[str] = field(default_factory=list)  # "condition (observed: value)" lines
    missing: list[str] = field(default_factory=list)  # field paths absent from the input


# ---- formatting ------------------------------------------------------------------------------


def fmt_value(value: Any, *, limit: int = 80, _depth: int = 0) -> str:
    """Short, single-line rendering of an observed value for explanations (inputs are pre-redacted)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        if not value:
            return '""'
        flat = " ".join(value.split())
        return flat if len(flat) <= limit else flat[: limit - 1] + "…"
    if _depth >= 2:
        return "…"
    if isinstance(value, dict):
        for key in ("type", "id", "kind", "name", "identifier"):
            if isinstance(value.get(key), str):
                return fmt_value(value[key], limit=limit)
        keys = list(value)[:5]
        return "{" + ", ".join(str(k)[:40] for k in keys) + (", …" if len(value) > 5 else "") + "}"
    if isinstance(value, list | tuple):
        if not value:
            return "[]"
        shown = ", ".join(fmt_value(v, limit=40, _depth=_depth + 1) for v in value[:5])
        more = f", +{len(value) - 5} more" if len(value) > 5 else ""
        return f"[{shown}{more}]"
    return fmt_value(str(value), limit=limit)


_PHRASES = {
    "eq": "is {v}",
    "neq": "is not {v}",
    "in": "is one of {v}",
    "not_in": "is not one of {v}",
    "contains": "contains {v}",
    "not_contains": "does not contain {v}",
    "glob": "matches {v}",
    "any_glob": "has an element matching {v}",
    "exists": "is present",
    "empty": "is empty",
    "not_empty": "is not empty",
    "gt": "is greater than {v}",
    "gte": "is at least {v}",
    "lt": "is less than {v}",
    "lte": "is at most {v}",
    "is_true": "is true",
    "is_false": "is false",
}


def _fmt_expected(value: Any) -> str:
    """Condition values are policy configuration, so lists are shown in full (up to 20 items)."""
    if isinstance(value, list):
        shown = ", ".join(fmt_value(v, limit=60, _depth=1) for v in value[:20])
        return f"[{shown}{f', +{len(value) - 20} more' if len(value) > 20 else ''}]"
    return fmt_value(value, limit=120)


def explain_leaf(node: dict[str, Any]) -> str:
    path, op, value = node.get("field"), node.get("op"), node.get("value")
    phrase = _PHRASES.get(op) if isinstance(op, str) else None
    if phrase is None:
        return f"{path} <unknown operator {op!r}>"
    if op in ("glob", "any_glob") and isinstance(value, list) and len(value) != 1:
        phrase = "matches any of {v}" if op == "glob" else "has an element matching any of {v}"
    elif op in ("glob", "any_glob") and isinstance(value, list):
        value = value[0]
    return f"{path} {phrase.format(v=_fmt_expected(value))}"


def _is_composite(node: Any) -> tuple[bool, str | None]:
    if isinstance(node, dict) and len(node) == 1:
        key = next(iter(node))
        if key in ("all", "any"):
            return True, key
    return False, None


def explain(node: Any, *, _depth: int = 0) -> str:
    """Readable English for a condition, e.g. ``tool.category is one of [http, email] AND ...``."""
    if node is None or node == {}:
        return "(empty condition — matches nothing)" if _depth == 0 else "(invalid: empty condition)"
    if not isinstance(node, dict):
        return "(invalid condition)"
    if _depth > MAX_DEPTH:
        return "(condition nested too deeply)"
    composite, key = _is_composite(node)
    if composite and key:
        items = node[key]
        if not isinstance(items, list) or not items:
            return f"(empty '{key}' — matches nothing)"
        if len(items) == 1:
            return explain(items[0], _depth=_depth + 1)
        parts = []
        for child in items:
            text = explain(child, _depth=_depth + 1)
            child_composite, child_key = _is_composite(child)
            if child_composite and isinstance(child[child_key], list) and len(child[child_key]) > 1:
                text = f"({text})"
            parts.append(text)
        return (" AND " if key == "all" else " OR ").join(parts)
    if set(node) == {"not"}:
        return f"NOT ({explain(node['not'], _depth=_depth + 1)})"
    if "field" in node and "op" in node and set(node) <= {"field", "op", "value"}:
        return explain_leaf(node)
    return "(invalid condition)"


# ---- resolution ------------------------------------------------------------------------------


def resolve(data: dict[str, Any], path: str) -> tuple[bool, list[Any]]:
    """Return ``(found, values)``. ``values`` has one entry unless the path contains a wildcard."""
    segs = parse_path(path)
    if segs is None:
        raise ConditionError(f"malformed field path {path!r}")
    current: list[Any] = [data]
    for seg in segs:
        nxt: list[Any] = []
        for value in current:
            if seg == WILDCARD:
                if isinstance(value, list):
                    nxt.extend(value)
                elif isinstance(value, dict):
                    nxt.extend(value.values())
            elif isinstance(seg, int):
                if isinstance(value, list) and seg < len(value):
                    nxt.append(value[seg])
            elif isinstance(value, dict) and seg in value:
                nxt.append(value[seg])
        current = [v for v in nxt if v is not None]
        if not current:
            return False, []
    return True, current


# ---- operators -------------------------------------------------------------------------------


def _fold(v: Any) -> Any:
    return v.casefold() if isinstance(v, str) else v


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return _fold(a) == _fold(b)


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else [value]


def _glob(text: Any, patterns: Any) -> bool:
    if not isinstance(text, str):
        return False
    folded = text.casefold()
    return any(isinstance(p, str) and fnmatch.fnmatchcase(folded, p.casefold()) for p in _as_list(patterns))


def _is_number(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def _compare(op: str, observed: Any, expected: Any, spec: dict[str, Any] | None) -> bool:
    if _is_number(observed) and _is_number(expected):
        a, b = observed, expected
    else:
        ra, rb = rank_of(spec, observed), rank_of(spec, expected)
        if ra is None or rb is None:
            return False
        a, b = ra, rb
    if op == "gt":
        return a > b
    if op == "gte":
        return a >= b
    if op == "lt":
        return a < b
    return a <= b


def _apply(op: str, observed: Any, expected: Any, spec: dict[str, Any] | None) -> bool:
    if op == "exists":
        return True
    if op == "empty":
        return observed in ("", [], {}) or (isinstance(observed, str) and not observed.strip())
    if op == "not_empty":
        return not _apply("empty", observed, expected, spec)
    if op == "is_true":
        return observed is True
    if op == "is_false":
        return observed is False
    if op == "eq":
        return _same(observed, expected)
    if op == "neq":
        return not _same(observed, expected)
    if op in ("in", "not_in"):
        options = _as_list(expected)
        if isinstance(observed, list):
            hit = any(_same(o, x) for o in observed for x in options)
        else:
            hit = any(_same(observed, x) for x in options)
        return hit if op == "in" else not hit
    if op in ("contains", "not_contains"):
        if isinstance(observed, str):
            hit = isinstance(expected, str) and expected.casefold() in observed.casefold()
        elif isinstance(observed, list):
            hit = any(_same(o, expected) for o in observed)
        elif isinstance(observed, dict):
            hit = isinstance(expected, str) and any(_same(k, expected) for k in observed)
        else:
            return False
        return hit if op == "contains" else not hit
    if op == "glob":
        if isinstance(observed, list):
            return any(_glob(o, expected) for o in observed)
        return _glob(observed, expected)
    if op == "any_glob":
        return any(_glob(o, expected) for o in _as_list(observed))
    if op in COMPARISON_OPS:
        return _compare(op, observed, expected, spec)
    raise ConditionError(f"unknown operator {op!r}")


# ---- evaluation ------------------------------------------------------------------------------


def _leaf(node: dict[str, Any], data: dict[str, Any]) -> Outcome:
    path, op = node.get("field"), node.get("op")
    if not isinstance(path, str) or not path:
        raise ConditionError("condition 'field' must be a non-empty string")
    if op not in OPS:
        raise ConditionError(f"unknown operator {op!r} on {path}")
    expected = node.get("value")
    text = explain_leaf(node)
    found, values = resolve(data, path)
    if not found:
        return Outcome(False, [f"{text} (not evaluated: {path} is not present in the input)"], [path])
    spec = lookup_field(path)
    hits = [v for v in values if _apply(op, v, expected, spec)]
    shown = hits if hits else values
    observed = shown[0] if len(shown) == 1 else shown
    return Outcome(bool(hits), [f"{text} (observed: {fmt_value(observed)})"])


def evaluate_condition(node: Any, data: dict[str, Any], *, _depth: int = 0) -> Outcome:
    """Evaluate one condition node. An empty root matches nothing."""
    if _depth > MAX_DEPTH:
        raise ConditionError(f"condition nested deeper than {MAX_DEPTH} levels")
    if node is None or node == {}:
        if _depth == 0:
            return Outcome(False, ["condition is empty (matches nothing)"])
        raise ConditionError("empty condition inside a combinator")
    if not isinstance(node, dict):
        raise ConditionError(f"condition must be an object, got {type(node).__name__}")
    keys = set(node)
    if keys == {"all"} or keys == {"any"}:
        key = "all" if "all" in node else "any"
        children = node[key]
        if not isinstance(children, list) or not children:
            raise ConditionError(f"'{key}' must be a non-empty list")
        results = [evaluate_condition(c, data, _depth=_depth + 1) for c in children]
        missing = [m for r in results for m in r.missing]
        if key == "all":
            if all(r.matched for r in results):
                return Outcome(True, [e for r in results for e in r.evidence], missing)
            first_fail = next(r for r in results if not r.matched)
            return Outcome(False, first_fail.evidence, missing)
        winners = [r for r in results if r.matched]
        if winners:
            return Outcome(True, [e for r in winners for e in r.evidence], missing)
        return Outcome(False, [e for r in results for e in r.evidence], missing)
    if keys == {"not"}:
        inner = evaluate_condition(node["not"], data, _depth=_depth + 1)
        return Outcome(not inner.matched, [f"NOT ({'; '.join(inner.evidence)})"], inner.missing)
    if "field" in keys and "op" in keys and keys <= {"field", "op", "value"}:
        return _leaf(node, data)
    raise ConditionError(f"unrecognised condition keys {sorted(keys)}")
