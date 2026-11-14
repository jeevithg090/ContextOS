"""Static validation of policy conditions against the field catalog.

``validate_conditions`` returns human-readable errors (``[]`` = valid). Each error starts with the
location of the offending node, e.g. ``conditions.all[1]: unknown field "tool.categry" (did you mean
"tool.category"?)``. It checks structure, field names, operators, operator/field type compatibility,
value shapes and enum values. Policies that fail validation must not be saved.
"""

from __future__ import annotations

import difflib
from typing import Any

from app.engines.policy.conditions import MAX_DEPTH
from app.engines.policy.fields import (
    COMPARISON_OPS,
    FIELD_PATHS,
    OPS,
    VALUELESS_OPS,
    lookup_field,
    parse_path,
)

MAX_NODES = 256
_LEAF_KEYS = {"field", "op", "value"}


def _suggest(word: str, options: list[str]) -> str:
    close = difflib.get_close_matches(word, options, n=1, cutoff=0.6)
    return f' (did you mean "{close[0]}"?)' if close else ""


def _is_scalar(v: Any) -> bool:
    return isinstance(v, str | int | float | bool) and v is not None


def _is_number(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def _type_name(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if _is_number(v):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "object"
    return "null" if v is None else type(v).__name__


def _check_scalar(path: str, spec: dict[str, Any], value: Any, *, item: bool = False) -> str | None:
    """Check one comparison value against the field's (item) type. Returns an error or None."""
    ftype = spec["type"]
    if ftype == "list":
        ftype = spec.get("item_type", "string")
    if ftype in ("any", "object"):
        return (
            None
            if _is_scalar(value)
            else f"value must be a string, number or boolean, got {_type_name(value)}"
        )
    if ftype == "number":
        return (
            None
            if _is_number(value)
            else f"{path} is a number; value must be a number, got {_type_name(value)}"
        )
    if ftype == "boolean":
        return None if isinstance(value, bool) else f"{path} is a boolean; value must be true or false"
    if not isinstance(value, str):
        return f"{path} holds text; value must be a string, got {_type_name(value)}"
    allowed = spec.get("values")
    if ftype == "enum" and allowed and value.casefold() not in {a.casefold() for a in allowed}:
        what = "item value" if item else "value"
        return f'unknown {what} "{value}" for {path} (allowed: {", ".join(allowed)})' + _suggest(
            value, list(allowed)
        )
    return None


def _validate_leaf(node: dict[str, Any], loc: str, errors: list[str]) -> None:
    extra = set(node) - _LEAF_KEYS
    if extra:
        errors.append(f"{loc}: unexpected keys {sorted(extra)} in condition (allowed: field, op, value)")
    raw_path, op = node.get("field"), node.get("op")
    path = raw_path if isinstance(raw_path, str) else ""
    spec = None
    if not path.strip():
        errors.append(f"{loc}: 'field' must be a non-empty string")
    elif parse_path(path) is None:
        errors.append(f'{loc}: malformed field path "{path}" (use dots, and [*] for "any element")')
    else:
        spec = lookup_field(path)
        if spec is None:
            errors.append(f'{loc}: unknown field "{path}"' + _suggest(path, FIELD_PATHS))
    if not isinstance(op, str) or op not in OPS:
        errors.append(
            f"{loc}: unknown operator {op!r} (expected one of {', '.join(sorted(OPS))})"
            + (_suggest(op, sorted(OPS)) if isinstance(op, str) else "")
        )
        return
    has_value = "value" in node and node["value"] is not None
    value = node.get("value")
    if op in VALUELESS_OPS:
        if has_value:
            errors.append(f'{loc}: operator "{op}" takes no value; remove "value"')
        if spec is not None and spec["type"] != "any" and op not in spec["ops"]:
            errors.append(_unsupported(loc, op, path, spec))
        return
    if not has_value:
        errors.append(f'{loc}: operator "{op}" requires a "value"')
        return
    if spec is None:
        return
    if spec["type"] != "any" and op not in spec["ops"]:
        errors.append(_unsupported(loc, op, path, spec))
        return
    for problem in _value_problems(op, path, spec, value):
        errors.append(f"{loc}: {problem}")


def _unsupported(loc: str, op: str, path: str, spec: dict[str, Any]) -> str:
    kind = spec["type"]
    hint = ""
    if op in COMPARISON_OPS:
        hint = "; comparisons need a number field or an ordered enum (severity, risk level, trust level)"
    elif op in ("eq", "neq") and kind == "list":
        hint = '; use "contains" / "not_contains" to test list membership'
    elif op == "glob" and kind == "list":
        hint = '; use "any_glob" for list fields'
    return (
        f'{loc}: operator "{op}" is not supported for {kind} field {path} '
        f"(supported: {', '.join(spec['ops'])}){hint}"
    )


def _value_problems(op: str, path: str, spec: dict[str, Any], value: Any) -> list[str]:
    if op in ("eq", "neq", "contains", "not_contains"):
        if not _is_scalar(value):
            return [
                f'operator "{op}" needs a single string, number or boolean value, got {_type_name(value)}'
            ]
        if spec["type"] == "string" and op in ("contains", "not_contains") and not isinstance(value, str):
            return [f"{path} holds text; value must be a string"]
        err = _check_scalar(path, spec, value, item=spec["type"] == "list")
        return [err] if err else []
    if op in ("in", "not_in"):
        if not isinstance(value, list) or not value:
            return [f'operator "{op}" needs a non-empty list of values']
        problems = []
        for i, item in enumerate(value):
            err = _check_scalar(path, spec, item, item=spec["type"] == "list")
            if err:
                problems.append(f"value[{i}]: {err}")
        return problems
    if op in ("glob", "any_glob"):
        patterns = value if isinstance(value, list) else [value]
        if not patterns or not all(isinstance(p, str) and p.strip() for p in patterns):
            return [f'operator "{op}" needs a glob string or a non-empty list of glob strings']
        return []
    if op in COMPARISON_OPS:
        if spec["type"] in ("number", "any"):
            return [] if _is_number(value) else [f'operator "{op}" needs a number, got {_type_name(value)}']
        err = _check_scalar(path, spec, value)
        return [err] if err else []
    return []


def _validate_node(node: Any, loc: str, depth: int, errors: list[str], count: list[int]) -> None:
    count[0] += 1
    if count[0] > MAX_NODES:
        if count[0] == MAX_NODES + 1:
            errors.append(f"conditions: more than {MAX_NODES} condition nodes; simplify the policy")
        return
    if depth > MAX_DEPTH:
        errors.append(f"{loc}: nested deeper than {MAX_DEPTH} levels")
        return
    if not isinstance(node, dict):
        errors.append(f"{loc}: a condition must be an object, got {_type_name(node)}")
        return
    if not node:
        errors.append(f"{loc}: empty condition (it would never match)")
        return
    keys = set(node)
    combinators = keys & {"all", "any", "not"}
    if combinators:
        if len(keys) > 1:
            errors.append(
                f"{loc}: a combinator node must contain only one of all/any/not, got {sorted(keys)}"
            )
            return
        key = next(iter(combinators))
        child = node[key]
        if key == "not":
            _validate_node(child, f"{loc}.not", depth + 1, errors, count)
            return
        if not isinstance(child, list) or not child:
            errors.append(f"{loc}.{key}: must be a non-empty list of conditions")
            return
        for i, c in enumerate(child):
            _validate_node(c, f"{loc}.{key}[{i}]", depth + 1, errors, count)
        return
    if "field" in keys or "op" in keys:
        _validate_leaf(node, loc, errors)
        return
    errors.append(f"{loc}: unrecognised keys {sorted(keys)} (expected all, any, not, or field/op/value)")


def validate_conditions(conditions: dict[str, Any]) -> list[str]:
    if not isinstance(conditions, dict):
        return [f"conditions: must be a JSON object, got {_type_name(conditions)}"]
    if not conditions:
        return ["conditions: empty — a policy with no conditions never matches; add at least one condition"]
    errors: list[str] = []
    _validate_node(conditions, "conditions", 0, errors, [0])
    return errors
