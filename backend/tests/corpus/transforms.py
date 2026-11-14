"""Obfuscation transforms applied to malicious seeds by the corpus generator.

Each transform mirrors a technique that ``app/engines/detection/normalize.py`` claims to undo
(zero-width removal, Unicode tag decoding, homoglyph folding, leetspeak / spaced-letter collapse,
base64 and percent-decoding, case-insensitive matching). Transforms are pure and deterministic.

A transform returns ``None`` when it does not apply to a text (for example homoglyph substitution
on a script with no Latin letters, or Unicode-tag smuggling of non-ASCII text, which the tag block
cannot encode). The generator skips those combinations instead of emitting mislabelled samples.

Transforms change the *instruction-bearing words* the way an attacker would; URLs and file paths
are left intact where an attacker needs them to keep working (a leetspeak URL does not resolve).
"""

from __future__ import annotations

import base64
import re
from collections.abc import Callable

# Scripts whose letters the case / homoglyph / leetspeak / spacing transforms operate on.
LATIN_LANGS = frozenset({"en", "es", "fr", "de", "pt", "it", "nl", "tr"})

ZWSP = "​"
_TAG_OFFSET = 0xE0000
# Cover text shown to a human; the instruction rides along invisibly in Unicode tag characters.
TAG_COVER = "Thanks for reading! Feedback is welcome."

# Common Cyrillic confusables for Latin letters (Unicode TR39 confusables subset).
_HOMOGLYPHS = {
    "a": "а",
    "c": "с",
    "e": "е",
    "i": "і",
    "j": "ј",
    "o": "о",
    "p": "р",
    "s": "ѕ",
    "x": "х",
    "y": "у",
    "h": "һ",
    "A": "А",
    "B": "В",
    "C": "С",
    "E": "Е",
    "H": "Н",
    "K": "К",
    "M": "М",
    "O": "О",
    "P": "Р",
    "T": "Т",
    "X": "Х",
}
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

# A "plain word" token: letters only (any script), optionally followed by trailing punctuation.
# Tokens containing '/', '.', ':', '@', '~', '_', '=', '{', '<', digits... (URLs, paths, markup,
# canaries) are left untouched by the word-level transforms.
_WORD = re.compile(r"^([^\W\d_]+)([,;:!?.)\]\"']*)$")


def _map_words(text: str, fn: Callable[[str], str]) -> str:
    """Apply ``fn`` to every plain word, keeping whitespace and non-word tokens exactly."""
    out: list[str] = []
    for token in re.split(r"(\s+)", text):
        m = _WORD.match(token) if token and not token.isspace() else None
        out.append(fn(m.group(1)) + m.group(2) if m else token)
    return "".join(out)


def zero_width(text: str, lang: str) -> str | None:
    """Interleave ZERO WIDTH SPACE between the characters of every word of 3+ letters."""
    out = re.sub(r"[^\W\d_]{3,}", lambda m: ZWSP.join(m.group(0)), text)
    return out if out != text else None


def unicode_tags(text: str, lang: str) -> str | None:
    """Smuggle the whole instruction in invisible Unicode tag characters after a visible cover line."""
    if not text.isascii():
        return None
    hidden = "".join(
        chr(_TAG_OFFSET + ord(c)) if 0x20 <= ord(c) <= 0x7E else chr(_TAG_OFFSET + 0x20) for c in text
    )
    return f"{TAG_COVER} {hidden}"


def homoglyph(text: str, lang: str) -> str | None:
    """Swap every other eligible Latin letter of each plain word for a Cyrillic look-alike."""
    if lang not in LATIN_LANGS:
        return None

    def swap(word: str) -> str:
        chars = list(word)
        eligible = [i for i, c in enumerate(chars) if c in _HOMOGLYPHS]
        for n, i in enumerate(eligible):
            if n % 2 == 0:
                chars[i] = _HOMOGLYPHS[chars[i]]
        return "".join(chars)

    out = _map_words(text, swap)
    return out if out != text else None


def leetspeak(text: str, lang: str) -> str | None:
    """Replace a/e/i/o/s/t with 4/3/1/0/5/7 in every plain word of 3+ letters ("1gn0r3")."""
    if lang not in LATIN_LANGS:
        return None

    def leet(word: str) -> str:
        return "".join(_LEET.get(c.lower(), c) for c in word) if len(word) >= 3 else word

    out = _map_words(text, leet)
    return out if out != text else None


def spaced_letters(text: str, lang: str) -> str | None:
    """Spell each plain word of 2+ letters with single spaces ("i g n o r e"), two spaces between words."""
    if lang not in LATIN_LANGS:
        return None
    out: list[str] = []
    for token in re.split(r"(\s+)", text):
        if token == " ":
            out.append("  ")  # word separators widen so the spelt words stay distinguishable
            continue
        m = _WORD.match(token) if token and not token.isspace() else None
        out.append(" ".join(m.group(1)) + m.group(2) if m and len(m.group(1)) >= 2 else token)
    result = "".join(out)
    return result if result != text else None


def base64_segment(text: str, lang: str) -> str:
    """The whole instruction as one base64 segment (UTF-8 encoded)."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def url_encoding(text: str, lang: str) -> str:
    """Percent-encode every byte of the instruction (UTF-8), as in a crafted query parameter."""
    return "".join(f"%{b:02X}" for b in text.encode("utf-8"))


def mixed_case(text: str, lang: str) -> str | None:
    """Alternate upper/lower case across the letters of the instruction."""
    letters = 0
    out: list[str] = []
    for c in text:
        if c.isalpha() and c.lower() != c.upper():
            out.append(c.upper() if letters % 2 == 0 else c.lower())
            letters += 1
        else:
            out.append(c)
    result = "".join(out)
    return result if result != text else None


def none(text: str, lang: str) -> str:
    return text


TRANSFORMS: dict[str, Callable[[str, str], str | None]] = {
    "none": none,
    "zero_width": zero_width,
    "unicode_tags": unicode_tags,
    "homoglyph": homoglyph,
    "leetspeak": leetspeak,
    "spaced_letters": spaced_letters,
    "base64": base64_segment,
    "url_encoding": url_encoding,
    "mixed_case": mixed_case,
}
