"""RESTRICT outcome: the restriction schema, its validation and how several RESTRICT matches merge.

A RESTRICT decision means "the call may proceed only with these constraints applied". Schema::

    {
      "redact_secrets": bool,            # replace detected secrets in the arguments before the call runs
      "allowed_path_globs": [str, ...],  # every file path the call touches must match one of these
      "deny_path_globs": [str, ...],     # no file path the call touches may match any of these
      "max_argument_bytes": int          # serialised arguments must not exceed this size
    }

Globs use ``fnmatch`` semantics (``*`` also matches ``/``). An absent key means "no constraint of
this kind"; ``allowed_path_globs: []`` after merging means *no* path is allowed.

FAIL CLOSED: an integration that cannot apply every returned restriction (for example a host that
cannot rewrite tool arguments, or cannot see the paths a command touches) MUST treat RESTRICT as
DENY. Applying a subset of the restrictions and letting the call run is not permitted.

Merging when RESTRICT wins over several matching RESTRICT policies — the result is at least as
strict as each policy on its own:
    redact_secrets      true if any policy sets it
    deny_path_globs     union
    allowed_path_globs  intersection: a glob is kept only if it is identical to, or provably narrower
                        than, a glob in every other policy's allowlist (otherwise it is dropped)
    max_argument_bytes  minimum
"""

from __future__ import annotations

import difflib
import fnmatch
from collections.abc import Sequence
from typing import Any

from app.domain.enums import Decision

RESTRICTION_KEYS = ("redact_secrets", "allowed_path_globs", "deny_path_globs", "max_argument_bytes")
MAX_ARGUMENT_BYTES_LIMIT = 10 * 1024 * 1024


def _glob_list_problem(key: str, value: Any) -> str | None:
    if not isinstance(value, list) or not all(isinstance(g, str) and g.strip() for g in value):
        return f"{key} must be a list of non-empty glob strings"
    return None


def validate_restrictions(restrictions: Any, *, outcome: str | None = None) -> list[str]:
    """Human-readable problems with a policy's ``restrictions`` (``[]`` = valid)."""
    if restrictions is None:
        restrictions = {}
    if not isinstance(restrictions, dict):
        return ["restrictions: must be a JSON object"]
    errors: list[str] = []
    for key in restrictions:
        if key not in RESTRICTION_KEYS:
            close = difflib.get_close_matches(str(key), RESTRICTION_KEYS, n=1)
            hint = f' (did you mean "{close[0]}"?)' if close else ""
            errors.append(f'restrictions: unknown key "{key}" (allowed: {", ".join(RESTRICTION_KEYS)}){hint}')
    if "redact_secrets" in restrictions and not isinstance(restrictions["redact_secrets"], bool):
        errors.append("restrictions: redact_secrets must be true or false")
    for key in ("allowed_path_globs", "deny_path_globs"):
        if key in restrictions:
            problem = _glob_list_problem(key, restrictions[key])
            if problem:
                errors.append(f"restrictions: {problem}")
    if restrictions.get("allowed_path_globs") == []:
        errors.append(
            "restrictions: allowed_path_globs is empty, which allows no path at all; use a DENY policy"
        )
    if "max_argument_bytes" in restrictions:
        size = restrictions["max_argument_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARGUMENT_BYTES_LIMIT:
            errors.append(
                f"restrictions: max_argument_bytes must be an integer between 1 and "
                f"{MAX_ARGUMENT_BYTES_LIMIT}"
            )
    if outcome is not None:
        out = str(outcome).upper()
        effective = [
            k for k in RESTRICTION_KEYS if k in restrictions and restrictions[k] not in (False, None)
        ]
        if out == Decision.RESTRICT and not effective:
            errors.append("restrictions: a RESTRICT policy must define at least one restriction")
        elif out != Decision.RESTRICT and restrictions:
            errors.append(f"restrictions: only RESTRICT policies use restrictions; remove them for {out}")
    return errors


def _subset(narrow: str, broad: str) -> bool:
    """True only when every path matching ``narrow`` provably matches ``broad`` (conservative)."""
    if narrow == broad:
        return True
    if any(c in broad for c in "?[]") or any(c in narrow for c in "[]"):
        return False
    # With ``broad`` limited to literals and ``*``, any metacharacter of ``narrow`` that the
    # match places inside one of broad's ``*`` spans can expand freely, so the pattern text
    # matching is sufficient for containment.
    return fnmatch.fnmatchcase(narrow, broad)


def _dedup(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def merge_restrictions(items: Sequence[tuple[str, dict[str, Any]]]) -> tuple[dict[str, Any], list[str]]:
    """Merge ``[(policy_name, restrictions), ...]``. Returns ``(merged, problems)``.

    ``problems`` lists invalid restriction values that could not be honoured; the caller must fail
    closed (DENY) when it is non-empty.
    """
    merged: dict[str, Any] = {}
    problems: list[str] = []
    allowlists: list[list[str]] = []
    for name, raw in items:
        for err in validate_restrictions(raw):
            problems.append(f'policy "{name}": {err}')
        if not isinstance(raw, dict):
            continue
        if raw.get("redact_secrets") is True:
            merged["redact_secrets"] = True
        deny = raw.get("deny_path_globs")
        if isinstance(deny, list) and _glob_list_problem("deny_path_globs", deny) is None:
            merged["deny_path_globs"] = _dedup(merged.get("deny_path_globs", []) + deny)
        allow = raw.get("allowed_path_globs")
        if isinstance(allow, list) and _glob_list_problem("allowed_path_globs", allow) is None:
            allowlists.append(list(allow))
        size = raw.get("max_argument_bytes")
        if isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_ARGUMENT_BYTES_LIMIT:
            merged["max_argument_bytes"] = min(size, merged.get("max_argument_bytes", size))
    if len(allowlists) == 1:
        merged["allowed_path_globs"] = _dedup(allowlists[0])
    elif allowlists:
        kept = [
            g
            for i, globs in enumerate(allowlists)
            for g in globs
            if all(any(_subset(g, b) for b in other) for j, other in enumerate(allowlists) if j != i)
        ]
        merged["allowed_path_globs"] = _dedup(kept)
    return {k: merged[k] for k in RESTRICTION_KEYS if k in merged}, problems


def describe_restrictions(restrictions: dict[str, Any]) -> str:
    parts: list[str] = []
    if restrictions.get("redact_secrets"):
        parts.append("secrets in the arguments are redacted")
    if "allowed_path_globs" in restrictions:
        globs = restrictions["allowed_path_globs"]
        parts.append(f"only paths matching [{', '.join(globs)}]" if globs else "no file path is allowed")
    if restrictions.get("deny_path_globs"):
        parts.append(f"never paths matching [{', '.join(restrictions['deny_path_globs'])}]")
    if "max_argument_bytes" in restrictions:
        parts.append(f"arguments at most {restrictions['max_argument_bytes']} bytes")
    return "; ".join(parts) if parts else "no restrictions"
