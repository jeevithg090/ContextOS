"""Client-side application of RESTRICT decisions for :func:`contextos.guard`.

The server returns merged restrictions (see the policy engine's ``restrictions.py``)::

    {"redact_secrets": bool, "allowed_path_globs": [...], "deny_path_globs": [...], "max_argument_bytes": int}

FAIL CLOSED: the guard runs the tool only when it can apply EVERY returned restriction. Anything
it cannot honour turns RESTRICT into a denial:

- unknown restriction keys, or an empty restriction set;
- path globs on tools whose paths are hidden inside a command (shell / code execution /
  infrastructure categories, or any call with a program-like argument such as ``command``,
  ``script`` or ``code``) — the SDK cannot see which files such a call touches;
- ``redact_secrets`` when the masked arguments cannot be re-checked by the server, or the server
  still detects a secret the SDK could not mask.

Paths are the arguments declared with ``path_args``, otherwise arguments with path-like names
(``path``, ``file``, ``filename``, ``dir``, ``dest``...), ``os.PathLike`` values, and strings that
look like paths (``/``, ``~/``, ``./``, ``../``, ``C:\\``, ``file://``). A tool that touches files
it is not given as arguments cannot be checked — declare such tools with a shell-like category.

Globs use ``fnmatch`` semantics (``*`` also matches ``/``), like the server. An allowlisted path
must match both lexically (after ``..`` is collapsed) and after symlinks are resolved; a denylisted
path is refused if any spelling of it matches (case-insensitively).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from contextos.redact import mask_value

KNOWN_KEYS = frozenset({"redact_secrets", "allowed_path_globs", "deny_path_globs", "max_argument_bytes"})
OPAQUE_PATH_CATEGORIES = frozenset({"shell", "code_execution", "infrastructure"})
# Argument names that hold a program: whatever files it touches are not visible as arguments.
OPAQUE_ARGUMENT_NAMES = frozenset({
    "command", "commands", "cmd", "script", "code", "shell", "bash", "sh", "powershell", "program",
    "exec", "argv", "cmdline", "command_line",
})

_PATH_NAME_RE = re.compile(
    r"(?:^|_)(?:path|paths|file|files|filename|filenames|filepath|dir|dirs|directory|folder|dest|src|"
    r"target|cwd|workdir|output_file|input_file)$",
    re.IGNORECASE,
)
_PATH_VALUE_RE = re.compile(r"^(?:/|~[/\\]|\.{1,2}[/\\]|[A-Za-z]:[/\\]|file://)")

# verify(masked_arguments) -> True (server finds no secrets) | False (server still finds some)
# | None (could not be verified). Raising is treated as None.
Verifier = Callable[[dict[str, Any]], bool | None]


@dataclass
class RestrictionOutcome:
    allowed: bool
    arguments: dict[str, Any]
    applied: list[str] = field(default_factory=list)
    reason: str | None = None
    redacted_types: list[str] = field(default_factory=list)


def _looks_like_path(value: str) -> bool:
    return 0 < len(value) < 4096 and "\n" not in value and bool(_PATH_VALUE_RE.match(value))


def extract_paths(arguments: Mapping[str, Any], path_args: Sequence[str] | None = None) -> list[str]:
    """File paths a call names, per the rules in the module docstring."""
    found: list[str] = []

    def visit(value: Any, key: str | None, depth: int) -> None:
        if depth > 12:
            return
        named = key is not None and (key in path_args if path_args is not None else bool(_PATH_NAME_RE.search(key)))
        if isinstance(value, os.PathLike):
            found.append(os.fspath(value))
        elif isinstance(value, str):
            if (named and "://" not in value) or value.startswith("file://") or (path_args is None and _looks_like_path(value)):
                found.append(value)
        elif isinstance(value, Mapping):
            for k, v in value.items():
                visit(v, str(k), depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                visit(item, key if named else None, depth + 1)

    for name, value in arguments.items():
        visit(value, name, 0)
    return list(dict.fromkeys(found))


def _home_folded(path: str) -> str | None:
    home = os.path.expanduser("~")
    if home and home != "~" and (path == home or path.startswith(home.rstrip("/") + "/")):
        return "~" + path[len(home.rstrip("/")):]
    return None


def _relative(path: str, cwd: str) -> str | None:
    base = cwd.rstrip("/") + "/"
    return path[len(base):] if path.startswith(base) else None


def path_forms(raw: str, cwd: str | None = None) -> tuple[set[str], set[str]]:
    """``(lexical_forms, resolved_forms)`` of a path, all with forward slashes."""
    cwd = cwd or os.getcwd()
    text = raw[7:] if raw.startswith("file://") else raw
    text = text.replace("\\", "/")
    expanded = os.path.expanduser(text)
    absolute = os.path.normpath(os.path.join(cwd, expanded))
    resolved = os.path.realpath(absolute)
    real_cwd = os.path.realpath(cwd)
    lexical = {os.path.normpath(text), absolute}
    resolved_forms = {resolved}
    for form, target, base in ((absolute, lexical, cwd), (resolved, resolved_forms, real_cwd)):
        for extra in (_home_folded(form), _relative(form, base)):
            if extra:
                target.add(extra)
    return {f.replace("\\", "/") for f in lexical}, {f.replace("\\", "/") for f in resolved_forms}


def _matches(forms: Iterable[str], globs: Sequence[str], *, case_insensitive: bool = False) -> bool:
    if case_insensitive:
        return any(fnmatch.fnmatchcase(f.lower(), g.lower()) for f in forms for g in globs)
    return any(fnmatch.fnmatchcase(f, g) for f in forms for g in globs)


def check_paths(paths: Sequence[str], allowed: Sequence[str] | None, denied: Sequence[str] | None,
                cwd: str | None = None) -> str | None:
    """Reason the paths violate the globs, or ``None`` when they comply."""
    for raw in paths:
        if "\x00" in raw:
            return "a path argument contains a NUL byte"
        lexical, resolved = path_forms(raw, cwd)
        if denied and _matches({raw, *lexical, *resolved}, denied, case_insensitive=True):
            return f"path '{raw}' matches a denied pattern ({', '.join(denied)})"
        if allowed is not None:
            if not allowed:
                return "the policy allows no file paths for this call"
            if not (_matches(lexical, allowed) and _matches(resolved, allowed)):
                return f"path '{raw}' is outside the allowed patterns ({', '.join(allowed)})"
    return None


def apply_restrictions(
    restrictions: Mapping[str, Any],
    arguments: dict[str, Any],
    *,
    category_hint: str | None = None,
    path_args: Sequence[str] | None = None,
    verify_redaction: Verifier | None = None,
    jsonable: Callable[[Any], Any] = lambda v: v,
    cwd: str | None = None,
) -> RestrictionOutcome:
    """Apply a RESTRICT decision to ``arguments``; see the module docstring for the rules."""

    def deny(reason: str) -> RestrictionOutcome:
        return RestrictionOutcome(False, arguments, reason=f"{reason}; the restriction could not be applied, "
                                  "so the call is treated as denied (fail closed)")

    if not restrictions:
        return deny("RESTRICT was returned without any restrictions")
    unknown = sorted(set(restrictions) - KNOWN_KEYS)
    if unknown:
        return deny(f"this SDK does not understand restriction(s) {', '.join(unknown)}")

    applied: list[str] = []
    current = arguments
    redacted: list[str] = []
    if restrictions.get("redact_secrets"):
        current, redacted = mask_value(arguments)
        if verify_redaction is None:
            return deny("secrets must be redacted but no server re-check is available")
        try:
            verdict = verify_redaction(current)
        except Exception:  # noqa: BLE001 - any failure means the redaction is unverified (fail closed below)
            verdict = None
        if verdict is None:
            return deny("secrets must be redacted but the server could not re-check the masked arguments")
        if verdict is False:
            return deny("the server still detects a secret in the arguments that the SDK could not mask")
        applied.append(f"redacted {len(redacted)} secret(s) in the arguments" if redacted else "no secrets needed redaction")

    allowed = restrictions.get("allowed_path_globs")
    denied = restrictions.get("deny_path_globs")
    if allowed is not None or denied:
        if (category_hint or "").lower() in OPAQUE_PATH_CATEGORIES:
            return deny(f"path restrictions cannot be checked for a {category_hint} tool (paths are hidden in the command)")
        program = opaque_argument(current)
        if program is not None:
            return deny(f"path restrictions cannot be checked for a call with a '{program}' argument (the files a "
                        "program touches are not visible in its arguments)")
        if (allowed is not None and not isinstance(allowed, list)) or (denied is not None and not isinstance(denied, list)):
            return deny("path restrictions are malformed")
        problem = check_paths(extract_paths(current, path_args), allowed, denied, cwd)
        if problem:
            return RestrictionOutcome(False, arguments, reason=problem)
        applied.append("all file paths are within the permitted patterns")

    limit = restrictions.get("max_argument_bytes")
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            return deny("max_argument_bytes is malformed")
        size = len(json.dumps(jsonable(current), ensure_ascii=False, default=str).encode("utf-8"))
        if size > limit:
            return RestrictionOutcome(False, arguments, reason=f"arguments are {size} bytes; the policy allows at most {limit}")
        applied.append(f"arguments are {size} bytes (limit {limit})")

    return RestrictionOutcome(True, current, applied=applied, redacted_types=sorted(set(redacted)))


def opaque_argument(arguments: Mapping[str, Any]) -> str | None:
    """The first top-level argument whose name says it holds a program (``command``, ``script``...)."""
    return next((str(name) for name in arguments if str(name).lower() in OPAQUE_ARGUMENT_NAMES), None)


def scan_reports_secrets(response: Any) -> bool | None:
    """Interpret a ``POST /scan`` response: True = secrets found, False = none, None = unrecognised."""
    if not isinstance(response, Mapping):
        return None
    recognised = False
    for key in ("secrets", "secret_matches"):
        if isinstance(response.get(key), list):
            recognised = True
            if response[key]:
                return True
    for key in ("secret_count", "secrets_found"):
        if isinstance(response.get(key), int) and not isinstance(response.get(key), bool):
            recognised = True
            if response[key] > 0:
                return True
    hits = response.get("hits")
    if isinstance(hits, list):
        recognised = True
        for hit in hits:
            if isinstance(hit, Mapping) and str(hit.get("category", "")).lower() == "secret_exposure":
                return True
    return False if recognised else None


__all__ = [
    "KNOWN_KEYS",
    "OPAQUE_ARGUMENT_NAMES",
    "OPAQUE_PATH_CATEGORIES",
    "RestrictionOutcome",
    "apply_restrictions",
    "check_paths",
    "extract_paths",
    "opaque_argument",
    "path_forms",
    "scan_reports_secrets",
]
