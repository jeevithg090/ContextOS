"""Normalisation layer: produce alternate *views* of a text, each tagged with the technique that
revealed it. Rules run over every view; a hit that appears only in a non-plain view was hidden by
that technique, which is itself a signal.

Views never include the original text twice; a view is emitted only when it differs from plain.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

MAX_DECODE_SEGMENTS = 64
MAX_SEGMENT_CHARS = 20_000


@dataclass(frozen=True)
class View:
    technique: str
    text: str
    # True only for the untouched original: span offsets are meaningful.
    has_offsets: bool = False


# --- invisible characters -------------------------------------------------------------------

_INVISIBLE = {
    0x00AD,  # soft hyphen
    0x034F,  # combining grapheme joiner
    0x061C,  # arabic letter mark
    0x180E,  # mongolian vowel separator
    0xFEFF,  # BOM / zero-width no-break space
}
_INVISIBLE.update(range(0x200B, 0x2010))  # ZWSP, ZWNJ, ZWJ, LRM, RLM
_INVISIBLE.update(range(0x202A, 0x202F))  # bidi embeddings / overrides
_INVISIBLE.update(range(0x2060, 0x2065))  # word joiner, invisible operators
_INVISIBLE.update(range(0x2066, 0x206A))  # bidi isolates
_TAG_START, _TAG_END = 0xE0000, 0xE007F


def _strip_invisible(text: str) -> tuple[str, str]:
    """Return (visible text without invisible chars, payload decoded from Unicode tag chars)."""
    out: list[str] = []
    tags: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE:
            continue
        if _TAG_START <= cp <= _TAG_END:
            # Tag characters mirror ASCII (U+E0041 == 'A'); decode them so hidden text is scanned.
            if 0xE0020 <= cp <= 0xE007E:
                tags.append(chr(cp - 0xE0000))
            continue
        out.append(ch)
    return "".join(out), "".join(tags)


# --- homoglyphs -------------------------------------------------------------------------------

_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
        "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g", "к": "k", "м": "m", "н": "h", "т": "t",
        "в": "b", "ԛ": "q", "ԝ": "w",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
        "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
        # Greek
        "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
        "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
        # Latin lookalikes
        "ı": "i", "ℓ": "l",
    }
)


def fold_homoglyphs(text: str) -> str:
    return text.translate(_HOMOGLYPHS)


# --- leetspeak / spaced letters ---------------------------------------------------------------

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
# Only digits trigger a leetspeak pass: '@', '$' and '!' occur far too often in ordinary text
# (markdown images, emails, shell) to gate on, though they are still folded inside a leet word.
_LEET_CHARS = frozenset("0134578")
_LEET_WORD_CHARS = frozenset("0134578@$!")
# Letters of any script ([^\W\d_]), so accented Latin ("p r é c é d e n t e s") is handled too.
# "i g n o r e" / "i.g.n.o.r.e" / "i-g-n-o-r-e": runs of >= 4 single letters split by one separator.
_SPACED = re.compile(r"(?<![\w])(?:[^\W\d_][ ._\-*]){3,}[^\W\d_](?![\w])")
# Once a text is known to spell words out letter by letter, its short words ("t o", "a l l") are
# collapsed too. Space-separated only, so abbreviations such as "e.g." are never touched.
_SPACED_SHORT = re.compile(r"(?<![\w])[^\W\d_](?: [^\W\d_]){1,2}(?![\w])")
_MULTI_SPACE = re.compile(r"[ \t]{2,}")
# A token mixing letters and leet digits/symbols, e.g. "1gn0r3" or "p@ssw0rd" (it may start with a
# digit). Bounded length and anchored at token starts to keep the scan linear.
_LEET_WORD = re.compile(r"(?<![\w@$!])(?=[\w@$!]{0,31}[^\W\d_])[\w@$!]{3,32}(?![\w@$!])")


def collapse_leetspeak(text: str) -> str:
    collapsed = text
    if any(sep in text for sep in " ._-*") and _SPACED.search(text):
        collapsed = _SPACED.sub(lambda m: re.sub(r"[ ._\-*]", "", m.group(0)), collapsed)
        collapsed = _SPACED_SHORT.sub(lambda m: m.group(0).replace(" ", ""), collapsed)
        # Spelt-out text separates its words with wider gaps; squeeze them back to single spaces.
        collapsed = _MULTI_SPACE.sub(" ", collapsed)
    if any(c in collapsed for c in _LEET_CHARS):
        collapsed = _LEET_WORD.sub(_leet_word, collapsed)
    return collapsed


def _leet_word(m: re.Match[str]) -> str:
    word = m.group(0)
    return word.translate(_LEET) if any(c in _LEET_WORD_CHARS for c in word) else word


# --- hidden markup ----------------------------------------------------------------------------

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_HIDDEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-z][a-z0-9]*)\b[^>]*style\s*=\s*[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem)?\b|opacity\s*:\s*0(?:\.0+)?\b"
    r"|color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)[^\"']*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))"
    r"[^\"']*[\"'][^>]*>(?P<body>.*?)</(?P=tag)\s*>",
    re.S | re.I,
)
_HIDDEN_ATTR_ELEMENT = re.compile(r"<(?P<tag>[a-z][a-z0-9]*)\b[^>]*\b(?:hidden|aria-hidden\s*=\s*[\"']true[\"'])[^>]*>(?P<body>.*?)</(?P=tag)\s*>", re.S | re.I)
_SCRIPT = re.compile(r"<(script|style|noscript|template)\b[^>]*>(.*?)</\1\s*>", re.S | re.I)
_META = re.compile(r"<meta\b[^>]*\bcontent\s*=\s*[\"']([^\"']+)[\"']", re.I)
_ATTRS = re.compile(r"\b(?:alt|title|aria-label|data-[a-z-]+)\s*=\s*[\"']([^\"']{8,})[\"']", re.I)
_MD_LINK_TITLE = re.compile(r"\]\([^)\s]+\s+[\"']([^\"']{8,})[\"']\)")
_MD_COMMENT = re.compile(r"^\[[^\]]*\]:\s*#\s*\((.*?)\)\s*$", re.M)
_TAGS = re.compile(r"<[^>]+>")


def hidden_ranges(text: str) -> list[tuple[int, int, str]]:
    """Spans in the ORIGINAL text that a human reader does not see rendered (HTML comments, hidden
    elements/attributes, script/meta content, markdown link titles) with the technique label to use.
    A plain-view rule match falling inside one of these is really concealed content."""
    has_html = "<" in text
    has_md = "](" in text or "]:" in text
    if not has_html and not has_md:
        return []
    ranges: list[tuple[int, int, str]] = []
    if has_html:
        for m in _HTML_COMMENT.finditer(text):
            ranges.append((*m.span(1), "html_comment"))
        for rx in (_HIDDEN_ELEMENT, _HIDDEN_ATTR_ELEMENT):
            for m in rx.finditer(text):
                ranges.append((*m.span("body"), "hidden_text"))
        for m in _SCRIPT.finditer(text):
            ranges.append((*m.span(2), "hidden_text"))
        for m in _META.finditer(text):
            ranges.append((*m.span(1), "hidden_text"))
        for m in _ATTRS.finditer(text):
            ranges.append((*m.span(1), "hidden_text"))
    if has_md:
        for m in _MD_COMMENT.finditer(text):
            ranges.append((*m.span(1), "html_comment"))
        for m in _MD_LINK_TITLE.finditer(text):
            ranges.append((*m.span(1), "hidden_text"))
    return ranges


def extract_hidden_markup(text: str) -> tuple[list[str], list[str]]:
    """Return (comment segments, hidden-text segments) found in HTML / Markdown."""
    has_html = "<" in text
    has_md = "](" in text or "]:" in text
    if not has_html and not has_md:
        return [], []
    comments: list[str] = []
    hidden: list[str] = []
    if has_html:  # the HTML-element patterns can only match when a tag is present
        comments += [m.group(1) for m in _HTML_COMMENT.finditer(text)]
        for rx in (_HIDDEN_ELEMENT, _HIDDEN_ATTR_ELEMENT):
            hidden += [_TAGS.sub(" ", m.group("body")) for m in rx.finditer(text)]
        hidden += [m.group(2) for m in _SCRIPT.finditer(text)]
        hidden += [m.group(1) for m in _META.finditer(text)]
        hidden += [m.group(1) for m in _ATTRS.finditer(text)]
    if has_md:
        comments += [m.group(1) for m in _MD_COMMENT.finditer(text)]
        hidden += [m.group(1) for m in _MD_LINK_TITLE.finditer(text)]
    return [html.unescape(c) for c in comments if c.strip()], [html.unescape(h) for h in hidden if h.strip()]


# --- encodings --------------------------------------------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
_ESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}){3,}")


def _mostly_printable(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    letters = sum(1 for c in s if c.isalpha())
    return printable / len(s) >= 0.9 and letters / len(s) >= 0.4


def decode_base64_segments(text: str) -> list[str]:
    out: list[str] = []
    # A base64 run contains no whitespace, so it lives inside one whitespace-delimited token; if no
    # token is long enough there can be no >=24-char segment, and we skip the full scan.
    if not any(len(tok) >= 24 for tok in text.split()):
        return out
    for m in _B64.finditer(text):
        seg = m.group(0)
        if len(seg) > MAX_SEGMENT_CHARS:
            continue
        # Pure hex / pure alnum identifiers (hashes, ids) rarely decode to prose; the printable
        # check below filters them, so we only skip the trivially-impossible cases here.
        padded = seg + "=" * (-len(seg) % 4)
        try:
            raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _mostly_printable(decoded):
            out.append(decoded)
        if len(out) >= MAX_DECODE_SEGMENTS:
            break
    return out


# A single JSON-style \\uXXXX escape (serialisers with ensure_ascii emit one per non-ASCII char).
_U_ESC = re.compile(r"\\u[0-9A-Fa-f]{4}")


def _pair_surrogates(text: str) -> str:
    """Re-pair UTF-16 surrogates left by \\uXXXX decoding ("\\ud83d\\ude00", Unicode tag characters)
    into real code points; a lone surrogate becomes U+FFFD."""
    if not any(0xD800 <= ord(c) <= 0xDFFF for c in text):
        return text
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _decode_escapes(seg: str) -> str:
    def rep(m: re.Match[str]) -> str:
        tok = m.group(0)
        return chr(int(tok[2:], 16))

    return _pair_surrogates(re.sub(r"\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}", rep, seg))


def decode_url_and_escapes(text: str) -> str | None:
    """Decode %-encoded runs, \\x runs and \\u escapes in place; None when nothing was decoded."""
    if "%" not in text and "\\" not in text:
        return None
    changed = False

    def pct(m: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return unquote(m.group(0))

    def esc(m: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return _decode_escapes(m.group(0))

    decoded = _ESC.sub(esc, _PCT.sub(pct, text))
    if "\\u" in decoded:
        singles = _U_ESC.sub(lambda m: chr(int(m.group(0)[2:], 16)), decoded)
        if singles != decoded:
            changed = True
            decoded = _pair_surrogates(singles)
    return decoded if changed else None


# A hard line break inside running text (PDF extraction, 72-column e-mail): the next line starts
# with a letter or digit, so markdown structure (quotes, fences, lists, headings) is never joined.
_HARD_WRAP = re.compile(r"(?<=\S)[ \t]*\n[ \t]*(?=[^\W_])")


def reflow(text: str) -> str | None:
    """Join hard-wrapped lines so a sentence split across lines is matched as one; None if unchanged."""
    if "\n" not in text:
        return None
    joined = _HARD_WRAP.sub(" ", text)
    return joined if joined != text else None


# --- view builder -----------------------------------------------------------------------------


def build_views(text: str) -> list[View]:
    """All views of ``text``. The plain view is always first."""
    views: list[View] = [View("plain", text, has_offsets=True)]
    seen = {text}

    def add(technique: str, value: str | None) -> None:
        if value and value.strip() and value not in seen:
            seen.add(value)
            views.append(View(technique, value))

    base = text
    if not text.isascii():
        nfkc = unicodedata.normalize("NFKC", text)
        visible, tag_payload = _strip_invisible(nfkc)
        add("zero_width", visible)
        add("zero_width", tag_payload)
        folded = fold_homoglyphs(visible)
        add("homoglyph", folded)
        base = folded

    reflowed = reflow(base)
    add("leetspeak", collapse_leetspeak(base))
    add("reflowed", reflowed)
    if reflowed:  # layout and spelling tricks compose: a spelt-out sentence can also be hard-wrapped
        add("leetspeak", collapse_leetspeak(reflowed))

    comments, hidden = extract_hidden_markup(text)
    for seg in comments:
        add("html_comment", seg)
    for seg in hidden:
        add("hidden_text", seg)

    for seg in decode_base64_segments(base):
        add("base64", seg)
    decoded = decode_url_and_escapes(base)
    add("url_encoded", decoded)
    if decoded and not decoded.isascii():
        # Escaped text can itself carry invisible characters, tag payloads or look-alikes.
        visible, tag_payload = _strip_invisible(unicodedata.normalize("NFKC", decoded))
        add("url_encoded", fold_homoglyphs(visible))
        add("url_encoded", tag_payload)
    return views
