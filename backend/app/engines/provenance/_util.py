"""Small, dependency-free helpers shared by the provenance engine modules."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

# Plain-language disclaimer attached to graphs and every risky path. Provenance edges record that two
# things were observed together (e.g. "this item entered this session"); they are not causal claims.
OBSERVED_RELATIONSHIP_NOTE = (
    "Edges are relationships observed and recorded by ContextOS. They show what was present and what "
    "happened, not proof that the content caused the action."
)

_MISSING = object()


def get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a mapping or, failing that, an attribute of an object."""
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def attr(node: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    """First non-``None`` value for any of ``keys`` on a node (top level, then its ``data`` mapping)."""
    data = node.get("data")
    for key in keys:
        value = node.get(key, _MISSING)
        if value is not _MISSING and value is not None:
            return value
        if isinstance(data, Mapping):
            value = data.get(key, _MISSING)
            if value is not _MISSING and value is not None:
                return value
    return default


def upper(value: Any) -> str | None:
    return str(value).strip().upper() if value not in (None, "") else None


def lower(value: Any) -> str | None:
    return str(value).strip().lower() if value not in (None, "") else None


def parse_time(value: Any) -> datetime | None:
    """Parse a datetime or ISO-8601 string into an aware UTC datetime. Unparseable input -> ``None``."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return None


def to_utc_iso(value: Any, *, field_name: str) -> str | None:
    """Canonical ISO-8601 UTC timestamp with a fixed microsecond precision and a ``Z`` suffix.

    Fixed precision keeps the text identical whether the value arrives as a datetime with or without
    microseconds or as a string (e.g. a receipt exported earlier). Invalid input raises ``ValueError``
    because a receipt must never attest to a timestamp it could not interpret.
    """
    if value is None or value == "":
        return None
    parsed = parse_time(value)
    if parsed is None:
        raise ValueError(f"{field_name} is not a valid ISO-8601 timestamp")
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def count_of(value: Any) -> int:
    """Length of a list-like value, or the integer value of a count; anything else counts as 0."""
    if value is None or isinstance(value, bool):
        return 0
    if isinstance(value, list | tuple | set | frozenset):
        return len(value)
    if isinstance(value, int):
        return max(value, 0)
    return 0
