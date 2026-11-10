"""Glob matching for trust rules and rule precedence.

Glob semantics (case-insensitive, full match):
- ``*`` matches within one segment: it never crosses ``/``, ``?`` or ``#``, so ``*.acme.com``
  cannot be satisfied by ``evil.com/?q=.acme.com``.
- ``*.`` at the start of a host (pattern start, after ``://``, ``/`` or ``@``) means "any
  sub-domain OR the apex": ``*.acme.com`` matches ``acme.com`` and ``a.b.acme.com``.
- A trailing ``/*`` (or ``/**``) means "this path and anything under it":
  ``github.com/acme/*`` matches ``github.com/acme``, ``github.com/acme/repo/blob/x``, but not
  ``github.com/acme-evil/repo``.
- ``**`` matches anything (including ``/``); ``?`` matches one character other than ``/``;
  a pattern of only ``*`` or ``**`` matches everything.
- ``http://`` / ``https://`` / ``ws(s)://`` schemes are ignored when comparing identifiers, so
  ``https://docs.acme.com/*`` and ``docs.acme.com/*`` are equivalent. Trailing ``/`` is ignored.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from functools import lru_cache

from app.domain.enums import TRUST_RANK, TrustLevel
from app.engines.trust.canonical import strip_web_scheme
from app.engines.trust.specs import TrustRuleSpec

_VALID_LEVELS = frozenset(level.value for level in TrustLevel)

# Pattern tokens. Matching simulates an NFA over these tokens, so it runs in O(len(pattern) *
# len(value)) with no backtracking: an unlucky pattern cannot stall ingestion on a long,
# attacker-chosen identifier.
_LIT, _SEG, _HOSTSEG, _ANY, _ONE, _SPLIT = range(6)
_SEG_STOP = frozenset("/?#")
_HOSTSEG_STOP = frozenset("/?#@")
Token = tuple[int, str | int]


def normalise_pattern(pattern: str) -> str:
    text = (pattern or "").strip().lower()
    text = strip_web_scheme(text)
    if len(text) > 1 and text.endswith("/") and not text.endswith("//"):
        text = text.rstrip("/")
    return text


def _tokenise(pattern: str) -> list[Token]:
    if pattern in ("*", "**"):
        return [(_ANY, "")]
    trailing_any = False
    for suffix in ("/**", "/*"):
        if pattern.endswith(suffix):
            pattern, trailing_any = pattern[: -len(suffix)], True
            break
    tokens: list[Token] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if pattern.startswith("**", i):
                tokens.append((_ANY, ""))
                i += 2
                continue
            if (i == 0 or pattern[i - 1] in "/@") and pattern.startswith("*.", i):
                # Optional "<sub-domain>." prefix: SPLIT jumps past the group (apex) or enters it.
                split_at = len(tokens)
                tokens.extend([(_SPLIT, -1), (_HOSTSEG, ""), (_LIT, ".")])
                tokens[split_at] = (_SPLIT, len(tokens))
                i += 2
                continue
            tokens.append((_SEG, ""))
        elif char == "?":
            tokens.append((_ONE, ""))
        else:
            tokens.append((_LIT, char))
        i += 1
    if trailing_any:
        split_at = len(tokens)
        tokens.extend([(_SPLIT, -1), (_LIT, "/"), (_ANY, "")])
        tokens[split_at] = (_SPLIT, len(tokens))
    return tokens


def _closure(tokens: list[Token], states: set[int]) -> set[int]:
    stack, seen = list(states), set(states)
    while stack:
        idx = stack.pop()
        if idx >= len(tokens):
            continue
        kind, arg = tokens[idx]
        targets: tuple[int, ...] = ()
        if kind in (_SEG, _HOSTSEG, _ANY):
            targets = (idx + 1,)
        elif kind == _SPLIT:
            targets = (idx + 1, int(arg))
        for target in targets:
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


def _run(tokens: list[Token], value: str) -> bool:
    end = len(tokens)
    states = _closure(tokens, {0})
    for char in value:
        following: set[int] = set()
        for idx in states:
            if idx >= end:
                continue
            kind, arg = tokens[idx]
            if kind == _LIT and char == arg:
                following.add(idx + 1)
            elif kind == _ONE and char != "/":
                following.add(idx + 1)
            elif kind == _ANY or (kind == _SEG and char not in _SEG_STOP):
                following.add(idx)
            elif kind == _HOSTSEG and char not in _HOSTSEG_STOP:
                following.add(idx)
        if not following:
            return False
        states = _closure(tokens, following)
    return end in states


@lru_cache(maxsize=2048)
def compile_glob(pattern: str) -> Callable[[str], bool]:
    """Compile a trust-rule glob into a predicate over (already canonical) values."""

    normalised = normalise_pattern(pattern)
    if not normalised:
        return lambda _value: False
    tokens = _tokenise(normalised)
    return lambda value: _run(tokens, value.lower())


def glob_match(pattern: str, value: str) -> bool:
    """True when ``value`` matches the trust-rule glob ``pattern`` (see module docstring)."""

    return compile_glob(pattern)(strip_web_scheme(value.strip().lower()))


def identifier_candidates(identifier: str) -> list[str]:
    lowered = identifier.strip().lower()
    stripped = strip_web_scheme(lowered)
    if len(stripped) > 1 and stripped.endswith("/"):
        stripped = stripped.rstrip("/")
    return list(dict.fromkeys(c for c in (lowered, stripped) if c))


def domain_candidates(host: str | None, domain: str | None) -> list[str]:
    return list(dict.fromkeys(c.lower() for c in (host, domain) if c))


def rule_matches(rule: TrustRuleSpec, *, identifiers: Sequence[str], domains: Sequence[str]) -> bool:
    if rule.match_field == "domain":
        values = domains
    elif rule.match_field == "identifier":
        values = identifiers
    else:
        return False
    matcher = compile_glob(rule.pattern)
    return any(matcher(v) for v in values)


def _sort_key(rule: TrustRuleSpec) -> tuple[int, int, int, str]:
    # Highest priority first; on a tie the more restrictive level wins (fail safe), then the more
    # specific (longer) pattern, then a stable id order.
    return (-rule.priority, TRUST_RANK.get(rule.trust_level, 0), -len(rule.pattern or ""), rule.id)


def matching_rules(
    rules: Iterable[TrustRuleSpec],
    *,
    scope: str,
    identifiers: Sequence[str],
    domains: Sequence[str],
    source_type: str | None = None,
) -> list[TrustRuleSpec]:
    """Enabled rules for ``scope`` ("source"|"destination") that match, in precedence order.

    For sources, a rule with a ``source_type`` only applies to sources of that type. For
    destinations the ``source_type`` filter does not apply.
    """

    matched = []
    for rule in rules:
        if not rule.enabled or rule.trust_level not in _VALID_LEVELS:
            continue
        if rule.applies_to not in (scope, "both"):
            continue
        if scope == "source" and rule.source_type and rule.source_type != source_type:
            continue
        if rule_matches(rule, identifiers=identifiers, domains=domains):
            matched.append(rule)
    return sorted(matched, key=_sort_key)


def describe_rule(rule: TrustRuleSpec) -> str:
    field = "domain" if rule.match_field == "domain" else "identifier"
    return f"trust rule '{rule.name}' (pattern '{rule.pattern}' on the {field})"
