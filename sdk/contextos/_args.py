"""Argument binding, JSON-safe conversion, result truncation and destination inference for guard()."""

from __future__ import annotations

import dataclasses
import inspect
import ipaddress
import json
import os
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from contextos.models import DestinationRef

_MAX_DEPTH = 20
_MAX_REPR = 2_000
_SELF_NAMES = frozenset({"self", "cls"})


@dataclasses.dataclass
class BoundCall:
    """A call bound to its signature; ``arguments`` is what gets reported and restricted."""

    bound: inspect.BoundArguments | None
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    hidden: tuple[str, ...]  # bound names not reported (self / cls)

    @property
    def arguments(self) -> dict[str, Any]:
        if self.bound is None:
            return {f"arg{i}": v for i, v in enumerate(self.args)} | dict(self.kwargs)
        return {k: v for k, v in self.bound.arguments.items() if k not in self.hidden}

    def replace_arguments(self, new: Mapping[str, Any]) -> BoundCall:
        """Return a call whose reported arguments are replaced (used to apply redaction)."""
        if self.bound is None:
            args = tuple(new.get(f"arg{i}", v) for i, v in enumerate(self.args))
            kwargs = {k: new.get(k, v) for k, v in self.kwargs.items()}
            return BoundCall(None, args, kwargs, self.hidden)
        bound = inspect.BoundArguments(self.bound.signature, self.bound.arguments.copy())
        for key, value in new.items():
            if key in bound.arguments and key not in self.hidden:
                bound.arguments[key] = value
        return BoundCall(bound, bound.args, bound.kwargs, self.hidden)


def bind_call(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> BoundCall:
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):  # builtins without signatures
        return BoundCall(None, args, kwargs, ())
    bound = signature.bind(*args, **kwargs)  # TypeError for a bad call, before anything is reported
    bound.apply_defaults()
    params = list(signature.parameters)
    hidden = (params[0],) if params and params[0] in _SELF_NAMES else ()
    return BoundCall(bound, bound.args, bound.kwargs, hidden)


def to_jsonable(value: Any, _depth: int = 0) -> Any:
    """Best-effort JSON-safe copy of a value (paths → str, bytes → text, objects → short repr)."""
    if _depth > _MAX_DEPTH:
        return "<max depth reached>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else value
        return [to_jsonable(v, _depth + 1) for v in items]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(dataclasses.asdict(value), _depth + 1)
    dump = getattr(value, "model_dump", None)
    if callable(dump):  # pydantic models; other libraries' model_dump may reject mode= (repr fallback)
        try:
            dumped = dump(mode="json")
        except TypeError:
            dumped = None
        if dumped is not None:
            return to_jsonable(dumped, _depth + 1)
    text = repr(value)
    return text if len(text) <= _MAX_REPR else text[:_MAX_REPR] + "…"


def truncate_result(value: Any, max_chars: int) -> str | dict[str, Any] | list[Any] | None:
    """JSON-safe tool result no larger than ``max_chars`` when serialised (marker appended if cut)."""
    if value is None:
        return None
    data = to_jsonable(value)
    if isinstance(data, str):
        return data if len(data) <= max_chars else data[:max_chars] + f"\n[TRUNCATED: {len(data) - max_chars} more characters]"
    if not isinstance(data, (dict, list)):
        return str(data)
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return data
    return text[:max_chars] + f"\n[TRUNCATED: {len(text) - max_chars} more characters of JSON]"


def destination_from(value: Any) -> DestinationRef | None:
    """Infer a :class:`DestinationRef` from an e-mail address, URL, host name or IP address."""
    if isinstance(value, DestinationRef) or value is None:
        return value
    text = str(value).strip()
    if not text:
        return None
    if "@" in text and "://" not in text and " " not in text:
        return DestinationRef(kind="email", identifier=text[:1024])
    host = urlsplit(text).hostname if "://" in text else text.split("/", 1)[0].split(":", 1)[0]
    if not host:
        return DestinationRef(kind="unknown", identifier=text[:1024])
    try:
        ipaddress.ip_address(host.strip("[]"))
        return DestinationRef(kind="ip", identifier=host.strip("[]"))
    except ValueError:
        pass
    return DestinationRef(kind="domain" if "." in host else "unknown", identifier=host.lower()[:1024])


__all__ = ["BoundCall", "bind_call", "destination_from", "to_jsonable", "truncate_result"]
