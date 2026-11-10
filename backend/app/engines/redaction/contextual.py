"""Context-dependent secret detectors.

These find credentials whose value has no recognisable format of its own, so the surrounding
text decides: ``password = "..."`` assignments, ``.env`` lines, ``--token`` CLI flags, ``curl -u``,
``.npmrc`` auth lines, and AWS secret keys / Twilio auth tokens that sit near their provider name.
Values are gated by placeholder checks, code-reference checks, length and Shannon entropy.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.engines.redaction.heuristics import (
    is_code_reference,
    is_digits,
    is_hex,
    is_path_value,
    is_placeholder,
    is_word_like,
    looks_fake,
    token_strength,
)
from app.engines.redaction.keys import classify_key, env_key_category
from app.engines.redaction.patterns import (
    SPEC_CONTEXTUAL,
    SPEC_GENERIC,
    SPEC_HEADER,
    Candidate,
    iter_needle,
    left_ok,
)

_TYPE_BY_CATEGORY = {
    "password": "generic_password",
    "api_key": "generic_api_key",
    "token": "generic_token",
    "session": "generic_token",
    "secret": "generic_secret",
    "private_key": "generic_secret",
    "credentials": "generic_secret",
}
_SLUG_RE = re.compile(r"^[a-z]+(?:[-_.][a-z]+)+$")
_UPPER_SNAKE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def gate_value(value: str, category: str, *, quoted: bool, env: bool = False) -> float | None:
    """Confidence that ``value`` assigned to a ``category`` field is a real credential, else None."""
    v = value.strip()
    min_len = (4 if quoted or env else 6) if category == "password" else (8 if quoted or env else 12)
    if len(v) < min_len or len(v) > 512 or any(ch.isspace() for ch in v):
        return None
    if is_placeholder(v) or is_path_value(v) or v.startswith("[REDACTED:"):
        return None
    entropy, classes = token_strength(v)
    if category == "password":
        if is_digits(v) and len(v) < 6:
            return None
        if env:
            if _UPPER_SNAKE_RE.match(v) or v.startswith(("$", "%")):
                return None
            return 0.75 if len(v) >= 8 and entropy >= 2.5 and classes >= 2 else 0.6
        if quoted and is_word_like(v):
            return None  # UI labels / translations: "Password", "Passwort"
        if not quoted and (is_code_reference(v) or (classes < 2 and not is_digits(v))):
            return None
        confidence = 0.75 if len(v) >= 8 and entropy >= 2.5 else 0.55
        return confidence * (0.6 if looks_fake(v) else 1.0)

    # Token-like categories: real values are long and random.
    if is_code_reference(v) or _SLUG_RE.match(v):
        if not env or _UPPER_SNAKE_RE.match(v) or v[0] in "$%!&*@{":
            return None
        return 0.55 if len(v) >= 12 else None  # literal word-ish value in a .env file
    if entropy < (2.0 if env else 3.0) or (classes < 2 and not is_hex(v)):
        return None
    if len(v) >= 20 and entropy >= 3.5:
        confidence = 0.85
    elif len(v) >= 16 and entropy >= 3.2:
        confidence = 0.75
    else:
        confidence = 0.6
    return confidence * (0.5 if looks_fake(v) else 1.0)


# --- key = value assignments, .env lines and CLI flags -----------------------------------------
#
# Rather than trying a regex at every offset, find credential hint words ("pass", "token", ...)
# in the lowered text, walk back to the start of the identifier that contains them, and run
# anchored matches from there. This keeps large inputs fast.

_HINT_RE = re.compile(r"pass|pwd|secret|token|key|auth|cred|sess|bearer|jwt|sid")
_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_KEY_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_MAX_KEY = 64
_IDENT_RUN_RE = re.compile(r"[A-Za-z0-9_.\-]*")

_ASSIGN_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})"
    r"(?:\\?[\"'])?\s*(?::=|=>|=(?![=>])|:(?![:/]))\s*"
    r"(?:\\?\"(?P<dq>[^\"\\\r\n]{1,512})\\?\"|\\?'(?P<sq>[^'\\\r\n]{1,512})\\?'|`(?P<bq>[^`\\\r\n]{1,512})`"
    r"|(?P<uq>[^\s\"'`,;<>(){}\[\]\\]{1,512}))"
)
_ENV_RE = re.compile(
    r"(?P<key>[A-Z][A-Z0-9_]{1,63})[ \t]*=[ \t]*"
    r"(?:\"(?P<dq>[^\"\\\r\n]{1,512})\"|'(?P<sq>[^'\r\n]{1,512})'|(?P<uq>[^\s\"'\\]{1,512}))"
)
_CLI_FLAG_RE = re.compile(
    r"--?(?P<flag>password|passwd|pass|token|secret|api-key|apikey|api_key|access-key|"
    r"access-token|access_token|auth-token|client-secret|private-key|bearer-token|oauth-token)"
    r"[ \t]+(?:\"(?P<dq>[^\"\s]{4,512})\"|'(?P<sq>[^'\s]{4,512})'|(?P<uq>[^\s\"'`|;&<>()]{4,512}))"
)
_SKIP_ASSIGN_CATEGORIES = frozenset({"authorization", "cookie"})  # dedicated header detectors


def _identifier_starts(text: str, lower: str) -> Iterator[int]:
    """Start offset of each identifier (<= 64 chars before the hint) that contains a hint word.

    Each identifier is visited once: later hints inside the same run are skipped, which keeps
    dense inputs ("passpasspass...") linear.
    """
    skip_until = -1
    for m in _HINT_RE.finditer(lower):
        pos = m.start()
        if pos < skip_until:
            continue
        start, floor = pos, max(0, pos - _MAX_KEY)
        while start > floor and text[start - 1] in _IDENT_CHARS:
            if start >= 2 and text[start - 2] == "\\" and text[start - 1] in "nrt":
                break  # JSON-escaped line break ("...\nAPI_KEY=...")
            start -= 1
        run = _IDENT_RUN_RE.match(text, pos)
        skip_until = run.end() if run else pos + 1
        if start == floor and floor > 0 and text[floor - 1] in _IDENT_CHARS:
            continue  # identifier longer than any credential key we classify
        yield start


def _value_group(m: re.Match[str]) -> str:
    """Name of the value alternative that matched (it is always the last group to close)."""
    return m.lastgroup or "uq"


def _at_line_start(text: str, pos: int) -> bool:
    """True at a line start: real newline, JSON-escaped "\n", an opening quote, or after "export "."""
    j = pos
    while j > 0 and text[j - 1] in " \t":
        j -= 1
    if j >= 6 and text[j - 6 : j] == "export" and j < pos:
        j -= 6
        while j > 0 and text[j - 1] in " \t":
            j -= 1
    if j == 0 or text[j - 1] in "\n\r\"'":
        return True
    return j >= 2 and text[j - 2] == "\\" and text[j - 1] in "nr"


def _assignment(text: str, key_start: int) -> tuple[Candidate | None, int]:
    m = _ASSIGN_RE.match(text, key_start)
    if m is None:
        return None, key_start
    category = classify_key(m.group("key"))
    if category is None or category in _SKIP_ASSIGN_CATEGORIES:
        return None, key_start
    group = _value_group(m)
    value = m.group(group)
    if group == "uq":
        value = value.rstrip(".")
    confidence = gate_value(value, category, quoted=group != "uq")
    if confidence is None:
        return None, key_start
    start = m.start(group)
    return Candidate(_TYPE_BY_CATEGORY[category], start, start + len(value), value, confidence, SPEC_GENERIC), m.end()


def _env_line(text: str, key_start: int) -> Candidate | None:
    if not _at_line_start(text, key_start):
        return None
    m = _ENV_RE.match(text, key_start)
    if m is None:
        return None
    category = env_key_category(m.group("key"))
    if category is None or category in _SKIP_ASSIGN_CATEGORIES:
        return None
    group = _value_group(m)
    confidence = gate_value(m.group(group), category, quoted=group != "uq", env=True)
    if confidence is None:
        return None
    return Candidate(_TYPE_BY_CATEGORY[category], *m.span(group), m.group(group), confidence, SPEC_GENERIC)


def _cli_flag(text: str, flag_start: int) -> Candidate | None:
    m = _CLI_FLAG_RE.match(text, flag_start)
    if m is None or not left_ok(text, flag_start, _WORD):
        return None
    group = _value_group(m)
    value = m.group(group)
    if value.startswith("-"):
        return None
    category = classify_key(m.group("flag")) or "token"
    confidence = gate_value(value, category, quoted=True)
    if confidence is None:
        return None
    kind = _TYPE_BY_CATEGORY.get(category, "generic_secret")
    return Candidate(kind, *m.span(group), value, confidence, SPEC_GENERIC + 10)


def scan_assignments(text: str, lower: str) -> Iterator[Candidate]:
    resume = 0
    for start in _identifier_starts(text, lower):
        if start < resume:
            continue
        key_start = start
        while key_start < len(text) and text[key_start] not in _KEY_START:
            key_start += 1
        if text[start] == "-" and (cli := _cli_flag(text, start)) is not None:
            resume = cli.end
            yield cli
            continue
        if text[key_start : key_start + 1].isupper() and (env := _env_line(text, key_start)) is not None:
            yield env
        candidate, end = _assignment(text, key_start)
        if candidate is not None:
            resume = end
            yield candidate


# --- curl -u user:password ---------------------------------------------------------------------

_CURL_USER_RE = re.compile(r"(?:-u|--user)[ \t]+[\"']?(?P<user>[^\s:\"'$]{1,128}):(?P<secret>[^\s\"']{3,512})")
_HTTP_CLIENTS = ("curl", "wget", "http ", "https ", "httpie", "xh ")


def scan_command_lines(text: str, lower: str) -> Iterator[Candidate]:
    for needle in ("-u", "--user"):
        for pos in iter_needle(lower, needle):
            m = _CURL_USER_RE.match(text, pos)
            if m is None or not left_ok(text, pos, _WORD):
                continue
            line_start = text.rfind("\n", max(0, pos - 2048), pos) + 1
            if not any(client in lower[line_start:pos] for client in _HTTP_CLIENTS):
                continue
            secret = m.group("secret")
            if is_placeholder(secret) or is_digits(secret) or secret.startswith("$"):
                continue
            yield Candidate("basic_auth", *m.span("secret"), secret, 0.8, SPEC_HEADER)


# --- provider context: AWS secret keys, Twilio auth tokens, .npmrc auth ------------------------

_B64_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=")
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_AWS_SECRET_ASSIGN_RE = re.compile(
    r"(?i)aws[A-Za-z0-9_.\- ]{0,30}?(?:secret|sk)[A-Za-z0-9_.\- ]{0,20}?\\?[\"']?\s*(?::=|=>|=|:)\s*\\?[\"']?"
    r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"
)
_B64_40_RE = re.compile(r"(?<![A-Za-z0-9/+=])(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")
_HEX_32_RE = re.compile(r"(?<![0-9a-fA-F])(?P<secret>[0-9a-f]{32})(?![0-9a-fA-F])")
_NPMRC_RE = re.compile(r"(?i)_(?P<kind>authToken|auth|password)\s*=\s*\"?(?P<secret>[^\s\"'\\]{8,512})")
_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_PROXIMITY = 200
_MAX_ANCHORS = 4096


def _aws_secret_ok(value: str) -> bool:
    entropy, classes = token_strength(value)
    return not is_hex(value) and not is_placeholder(value) and entropy >= 4.0 and classes >= 3


def _near(text: str, lower: str, anchors: tuple[str, ...], regex: re.Pattern[str],
          boundary: frozenset[str]) -> Iterator[re.Match[str]]:
    """Matches of ``regex`` starting within 200 characters after any anchor word (each once).

    Overlapping windows are merged so dense anchors ("awsawsaws...") stay linear.
    """
    positions = sorted({p for anchor in anchors for p in iter_needle(lower, anchor)})
    if len(positions) > _MAX_ANCHORS:
        yield from regex.finditer(text)  # anchor-dense input: everything is "near"; one linear pass
        return
    seen: set[int] = set()
    scanned_to = 0
    for pos in positions:
        window_end = min(len(text), pos + _PROXIMITY + 64)
        if window_end <= scanned_to:
            continue
        for m in regex.finditer(text, max(pos, scanned_to - 64), window_end):
            if m.start() > pos + _PROXIMITY + 6 or m.start() in seen:
                continue
            if m.end() < len(text) and text[m.end()] in boundary:
                continue  # the window cut a longer run short
            seen.add(m.start())
            yield m
        scanned_to = window_end


def scan_provider_context(text: str, lower: str) -> Iterator[Candidate]:
    for pos in iter_needle(lower, "aws"):
        m = _AWS_SECRET_ASSIGN_RE.match(text, pos)
        if m is not None and _aws_secret_ok(m.group("secret")):
            yield Candidate("aws_secret_key", *m.span("secret"), m.group("secret"), 0.95, SPEC_CONTEXTUAL + 5)
    for m in _near(text, lower, ("aws", "akia", "asia"), _B64_40_RE, _B64_CHARS):
        if _aws_secret_ok(m.group("secret")):
            yield Candidate("aws_secret_key", *m.span("secret"), m.group("secret"), 0.75, SPEC_CONTEXTUAL)
    for m in _near(text, lower, ("twilio",), _HEX_32_RE, _HEX_CHARS):
        if not looks_fake(m.group("secret")):
            yield Candidate("twilio_auth_token", *m.span("secret"), m.group("secret"), 0.75, SPEC_CONTEXTUAL)
    for needle in ("_auth", "_password"):
        for pos in iter_needle(lower, needle):
            m = _NPMRC_RE.match(text, pos)
            if m is None or not left_ok(text, pos, _ALNUM):
                continue
            secret = m.group("secret")
            if is_placeholder(secret) or secret.startswith("$"):
                continue
            kind = "generic_password" if m.group("kind").lower() == "password" else "npm_token"
            yield Candidate(kind, *m.span("secret"), secret, 0.9, SPEC_CONTEXTUAL + 10)


CONTEXTUAL_SCANNERS = (scan_assignments, scan_command_lines, scan_provider_context)
