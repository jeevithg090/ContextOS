"""Secret detection, redaction, fingerprinting and sensitivity classification.

Pipeline for a text: run every detector (``patterns`` for formatted credentials, ``contextual``
for assignment/context-based ones) over at most :data:`MAX_SCAN_CHARS` characters, drop candidates
inside existing ``[REDACTED:...]`` placeholders or embedded media (``data:image/...;base64``), then
resolve overlaps by keeping the most specific detector (provider format > structured >
contextual > header > generic assignment), then the higher confidence, then the longer span.

Raw secrets never leave this module: matches carry offsets and a keyed-HMAC fingerprint only.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from app.core.security import keyed_hmac
from app.domain.enums import Sensitivity
from app.engines.redaction.contextual import CONTEXTUAL_SCANNERS
from app.engines.redaction.heuristics import is_placeholder
from app.engines.redaction.keys import classify_key, is_metadata_key
from app.engines.redaction.paths import is_sensitive_path
from app.engines.redaction.patterns import STRUCTURAL_SCANNERS, Candidate
from app.engines.redaction.pii import pii_indicators

MAX_SCAN_CHARS = 2 * 1024 * 1024
MAX_DEPTH = 64
HIGH_CONFIDENCE = 0.7
FINGERPRINT_PURPOSE = "secret-fingerprint-v1"
SENSITIVE_FIELD = "sensitive_field"

_SCANNERS = STRUCTURAL_SCANNERS + CONTEXTUAL_SCANNERS
_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[a-z0-9_]{1,64}:[0-9a-f]{8}\]")
_MEDIA_DATA_URI_RE = re.compile(r"data:(?:image|font|audio|video)/[\w.+\-]{1,64};base64,[A-Za-z0-9+/=]{16,}")
_AUTH_SCHEME_RE = re.compile(r"^\s*(?:bearer|basic|token|bot|digest|apikey)\s+", re.IGNORECASE)
_ASCII_LOWER = str.maketrans({chr(c): chr(c + 32) for c in range(65, 91)})


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str  # e.g. "aws_access_key", "github_token", "private_key", "generic_password"
    start: int
    end: int
    fingerprint: str  # fingerprint_secret(raw_value)
    confidence: float  # 0..1


@dataclass
class RedactionResult:
    text: str
    matches: list[SecretMatch] = field(default_factory=list)

    @property
    def contains_secrets(self) -> bool:
        return bool(self.matches)


def fingerprint_secret(raw: str) -> str:
    """Keyed HMAC of the raw secret (16 hex chars). Stable per server key; irreversible."""
    return keyed_hmac(raw, purpose=FINGERPRINT_PURPOSE)[:16]


def placeholder_for(secret_type: str, fingerprint: str) -> str:
    return f"[REDACTED:{secret_type}:{fingerprint[:8]}]"


# --- detection ----------------------------------------------------------------------------------


def _excluded_spans(text: str) -> list[tuple[int, int]]:
    spans = [m.span() for m in _PLACEHOLDER_RE.finditer(text)] if "[REDACTED:" in text else []
    if "data:" in text:
        spans.extend(m.span() for m in _MEDIA_DATA_URI_RE.finditer(text))
    return sorted(spans)


def _overlaps_any(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(s < end and start < e for s, e in spans)


def _resolve(candidates: list[Candidate], excluded: list[tuple[int, int]]) -> list[Candidate]:
    """Keep non-overlapping candidates, preferring specificity, then confidence, then length.

    Candidates are swept into clusters of mutually overlapping spans first, so the greedy choice
    runs per cluster (almost always 1-3 candidates) and the whole step is O(n log n).
    """
    ordered = sorted((c for c in candidates if c.end > c.start), key=lambda c: (c.start, -c.end))
    excluded_starts = [s for s, _ in excluded]
    excluded_ends = sorted(e for _, e in excluded)
    kept: list[Candidate] = []
    i = 0
    while i < len(ordered):
        cluster_end = ordered[i].end
        j = i + 1
        while j < len(ordered) and ordered[j].start < cluster_end:
            cluster_end = max(cluster_end, ordered[j].end)
            j += 1
        cluster = ordered[i:j]
        i = j
        lo = bisect.bisect_right(excluded_ends, cluster[0].start)
        hi = bisect.bisect_left(excluded_starts, cluster_end)
        blocked = excluded[lo:hi] if lo < hi else []
        accepted: list[tuple[int, int]] = []
        for cand in sorted(cluster, key=lambda c: (-c.specificity, -c.confidence, c.start - c.end, c.start)):
            if _overlaps_any(blocked, cand.start, cand.end) or _overlaps_any(accepted, cand.start, cand.end):
                continue
            accepted.append((cand.start, cand.end))
            kept.append(cand)
    kept.sort(key=lambda c: c.start)
    return kept


def detect_secrets(text: str) -> list[SecretMatch]:
    """Secrets in ``text`` (first 2 MiB), sorted by offset, non-overlapping, raw values never kept."""
    if not text or not isinstance(text, str):
        return []
    scanned = text[:MAX_SCAN_CHARS]
    lower = scanned.lower()
    if len(lower) != len(scanned):
        # A few characters (e.g. "\u0130") lowercase to two; detectors index ``text`` with offsets
        # found in ``lower``, so fall back to length-preserving ASCII folding.
        lower = scanned.translate(_ASCII_LOWER)
    candidates = [cand for scanner in _SCANNERS for cand in scanner(scanned, lower)]
    if not candidates:
        return []
    return [
        SecretMatch(
            c.secret_type, c.start, c.end, fingerprint_secret(c.raw), round(min(c.confidence, 1.0), 2)
        )
        for c in _resolve(candidates, _excluded_spans(scanned))
    ]


# --- redaction ----------------------------------------------------------------------------------


def redact_text(text: str) -> RedactionResult:
    """Replace each detected secret with ``[REDACTED:<type>:<fp8>]``; offsets refer to ``text``.

    Content beyond the 2 MiB scan limit is dropped (with a marker) rather than passed through
    unscanned, so nothing unexamined can reach storage.
    """
    if not text:
        return RedactionResult("")
    if not isinstance(text, str):
        text = str(text)  # defensive: never let a non-string bypass scanning
    matches = detect_secrets(text)
    limit = min(len(text), MAX_SCAN_CHARS)
    parts: list[str] = []
    pos = 0
    for m in matches:
        parts.append(text[pos : m.start])
        parts.append(placeholder_for(m.secret_type, m.fingerprint))
        pos = m.end
    parts.append(text[pos:limit])
    if len(text) > MAX_SCAN_CHARS:
        parts.append(f"\n[TRUNCATED:{len(text) - MAX_SCAN_CHARS} characters beyond the secret-scan limit]")
    return RedactionResult("".join(parts), matches)


def _canonical_bounds(value: str) -> tuple[int, int]:
    """Bounds of the credential inside a sensitive field value (drops "Bearer " and whitespace)."""
    scheme = _AUTH_SCHEME_RE.match(value)
    start = scheme.end() if scheme else 0
    while start < len(value) and value[start].isspace():
        start += 1
    end = len(value)
    while end > start and value[end - 1].isspace():
        end -= 1
    return start, end


def _redact_sensitive(value: str, out: list[SecretMatch]) -> str:
    if not value or not value.strip() or _PLACEHOLDER_RE.fullmatch(value.strip()):
        return value
    start, end = _canonical_bounds(value)
    canonical = value[start:end] or value
    inner = detect_secrets(value)
    primary = next((m for m in inner if m.start <= start and m.end >= end), None)
    base = 0.4 if is_placeholder(canonical) or len(canonical) < 4 else 0.85
    if primary is not None:
        secret_type, fingerprint = primary.secret_type, primary.fingerprint
        confidence = max(primary.confidence, base)
    else:
        secret_type, fingerprint, confidence = SENSITIVE_FIELD, fingerprint_secret(canonical), base
    out.append(SecretMatch(secret_type, 0, len(value), fingerprint, confidence))
    out.extend(m for m in inner if m is not primary)
    return placeholder_for(SENSITIVE_FIELD, fingerprint)


def _redact_key(key: Any, out: list[SecretMatch]) -> Any:
    if not isinstance(key, str) or len(key) < 16:
        return key
    result = redact_text(key)
    out.extend(result.matches)
    return result.text


def _redact(value: Any, out: list[SecretMatch], sensitive: str | None, depth: int) -> Any:
    if isinstance(value, bytes | bytearray):
        value = bytes(value).decode("utf-8", errors="replace")  # bytes are returned as redacted text
    if isinstance(value, str):
        if sensitive:
            return _redact_sensitive(value, out)
        result = redact_text(value)
        out.extend(result.matches)
        return result.text
    if depth >= MAX_DEPTH and isinstance(value, dict | list | tuple | set | frozenset):
        return "[TRUNCATED:nesting deeper than the redaction limit]"
    if isinstance(value, dict):
        # Nested objects under a credential key (e.g. {"credentials": {...}}) stay sensitive, except
        # descriptive fields (id, name, type, scopes...); "session" objects carry ids and metadata.
        inherited = sensitive if sensitive not in (None, "session") else None
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            is_str = isinstance(key, str)
            category = classify_key(key) if is_str else None
            if category is None and inherited and not (is_str and is_metadata_key(key)):
                category = inherited
            redacted[_redact_key(key, out)] = _redact(item, out, category, depth + 1)
        return redacted
    if isinstance(value, list | tuple | set | frozenset):
        items = [_redact(item, out, sensitive, depth + 1) for item in value]
        if isinstance(value, list):
            return items
        if isinstance(value, tuple):
            return type(value)(*items) if hasattr(value, "_fields") else tuple(items)
        return type(value)(items)
    return value


def redact_value(value: Any) -> tuple[Any, list[SecretMatch]]:
    """Recursively redact dict/list/tuple/set/str values without mutating the input.

    ``bytes`` are decoded (UTF-8, invalid sequences replaced) and returned as redacted ``str``;
    other scalars are returned unchanged. Nesting deeper than 64 levels is replaced by a marker.

    Non-empty strings under sensitive keys (password, token, authorization, cookie, api_key, ...)
    are replaced entirely with ``[REDACTED:sensitive_field:<fp8>]``. The match for such a field
    uses the most specific detector type when one recognises the value; its fingerprint is taken
    over the credential itself (``Bearer <t>`` -> ``<t>``) so it matches the same secret found in
    free text. Match offsets are relative to the individual string they were found in.
    """
    matches: list[SecretMatch] = []
    return _redact(value, matches, None, 0), matches


# --- classification -----------------------------------------------------------------------------

_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".intranet",
    ".test",
    ".svc",
    ".cluster.local",
    ".localdomain",
    ".home.arpa",
)


def _host_is_internal(host: str) -> bool:
    host = host.strip("[]").lower()
    if not host or host == "localhost" or ("." not in host and ":" not in host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith(_INTERNAL_SUFFIXES)
    return not ip.is_global


def _identifier_risk(identifier: str) -> Sensitivity | None:
    found = detect_secrets(identifier)
    if any(m.confidence >= HIGH_CONFIDENCE for m in found):
        return Sensitivity.SECRET
    if found:
        return Sensitivity.CONFIDENTIAL
    if identifier.lower().startswith(("http://", "https://")):
        parts = urlsplit(identifier)
        if parts.username or parts.password:
            return Sensitivity.CONFIDENTIAL
        if parts.path and is_sensitive_path(unquote(parts.path))[0]:
            return Sensitivity.CONFIDENTIAL
        if any(classify_key(k) for k, _ in parse_qsl(parts.query, keep_blank_values=True)):
            return Sensitivity.CONFIDENTIAL
        return None
    return Sensitivity.CONFIDENTIAL if is_sensitive_path(identifier)[0] else None


def _is_public_url(identifier: str) -> bool:
    if not identifier.lower().startswith(("http://", "https://")):
        return False
    try:
        host = urlsplit(identifier).hostname or ""
    except ValueError:
        return False
    return not _host_is_internal(host)


def classify_sensitivity(text: str, matches: list[SecretMatch], identifier: str | None = None) -> Sensitivity:
    """SECRET > CONFIDENTIAL > INTERNAL (default) > PUBLIC, from evidence only.

    SECRET: a high-confidence secret in the content or identifier. CONFIDENTIAL: a sensitive path or
    identifier, low-confidence secrets, previously redacted secrets, or PII (Luhn-valid card
    numbers, valid IBANs, SSNs, bulk e-mail addresses). PUBLIC: an http(s) URL on a public host
    with none of the above.
    """
    matches = matches or []
    if any(m.confidence >= HIGH_CONFIDENCE for m in matches):
        return Sensitivity.SECRET
    ident = (identifier or "").strip()
    ident_level = _identifier_risk(ident) if ident else None
    if ident_level is Sensitivity.SECRET:
        return Sensitivity.SECRET
    body = (text or "")[:MAX_SCAN_CHARS]
    if ident_level is not None or matches or "[REDACTED:" in body and _PLACEHOLDER_RE.search(body):
        return Sensitivity.CONFIDENTIAL
    if body and pii_indicators(body):
        return Sensitivity.CONFIDENTIAL
    if ident and _is_public_url(ident):
        return Sensitivity.PUBLIC
    return Sensitivity.INTERNAL


__all__ = [
    "HIGH_CONFIDENCE",
    "MAX_SCAN_CHARS",
    "RedactionResult",
    "SecretMatch",
    "classify_sensitivity",
    "detect_secrets",
    "fingerprint_secret",
    "is_sensitive_path",
    "placeholder_for",
    "redact_text",
    "redact_value",
]
