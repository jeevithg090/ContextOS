"""Lookalike detection against the organisation's allowlisted destination domains.

A destination "looks like" an allowlisted domain when it is a different registrable domain that a
person could mistake for it: a small edit (typo-squat), visually confusable characters
(homoglyphs, including IDN/punycode tricks), the same name under a different suffix, or the
allowlisted name embedded as a sub-domain of someone else's domain (``acme.com.evil.io``).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from app.engines.trust.domains import is_ip, registrable_domain, split_registrable, to_unicode

# Visually confusable characters (Cyrillic, Greek, Armenian, Latin variants) → ASCII look-alike.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s",
        "і": "i", "ї": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ү": "y", "ӏ": "l",
        "к": "k", "ɡ": "g", "ո": "n", "ս": "u", "օ": "o", "α": "a", "ο": "o", "ν": "v", "ρ": "p",
        "ι": "i", "κ": "k", "υ": "u", "χ": "x", "ε": "e", "ı": "i", "ł": "l",
        "0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s",
    }
)
_ASCII_CONFUSABLE_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@dataclass(frozen=True)
class Lookalike:
    allowlisted: str
    technique: str  # homoglyph|edit_distance|suffix_swap|embedded
    detail: str


def skeleton(text: str) -> str:
    """Collapse visually confusable spellings to one form (``аpple`` → ``apple``, ``rn`` → ``m``)."""

    decomposed = unicodedata.normalize("NFKD", text.lower())
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    mapped = stripped.translate(_CONFUSABLES)
    for pair, replacement in _ASCII_CONFUSABLE_PAIRS:
        mapped = mapped.replace(pair, replacement)
    return mapped


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance (Levenshtein plus adjacent transpositions)."""

    if a == b:
        return 0
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def edit_threshold(label: str) -> int:
    """Max edits still considered a lookalike: short names need tighter thresholds.

    Up to 2 edits for names of 7+ characters, 1 for 4-6 characters, none for 1-3 (``x.com`` vs
    ``y.com`` is not a meaningful resemblance).
    """

    if len(label) < 4:
        return 0
    return 1 if len(label) <= 6 else 2


def find_lookalike(host: str, allowlisted: Iterable[str]) -> Lookalike | None:
    if not host or is_ip(host) or "." not in host:
        return None
    candidate = registrable_domain(host) or host
    candidate_display = to_unicode(candidate) or candidate
    cand_label, cand_suffix = split_registrable(candidate_display)
    padded_host = f".{host}."
    for allowed in sorted(set(allowlisted)):
        if not allowed or allowed == candidate or "." not in allowed:
            continue
        label, suffix = split_registrable(allowed)
        if skeleton(candidate_display) == skeleton(allowed):
            return Lookalike(
                allowed,
                "homoglyph",
                f"'{candidate_display}' uses characters that look like '{allowed}' but is a different domain.",
            )
        if cand_suffix == suffix:
            distance = edit_distance(cand_label, label)
            if 0 < distance <= edit_threshold(label):
                plural = "character" if distance == 1 else "characters"
                return Lookalike(
                    allowed,
                    "edit_distance",
                    f"'{candidate}' differs from the allowlisted '{allowed}' by {distance} {plural}.",
                )
        elif cand_label == label and len(label) >= 4:
            return Lookalike(
                allowed,
                "suffix_swap",
                f"'{candidate}' uses the same name as the allowlisted '{allowed}' under a different ending.",
            )
        if f".{allowed}." in padded_host:
            return Lookalike(
                allowed,
                "embedded",
                f"'{host}' contains the allowlisted name '{allowed}' but actually belongs to '{candidate}'.",
            )
    return None
