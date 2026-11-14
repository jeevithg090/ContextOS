"""Format-specific secret detectors: provider-prefixed tokens and structured credentials.

Every detector yields :class:`Candidate` spans over the ORIGINAL text. ``raw`` is the canonical
secret value that gets fingerprinted (e.g. the password inside a database URL, the base64 body of a
PEM block), so the same secret produces the same fingerprint wherever it re-appears.

Each regex has lowercase ``needles``; it only runs when one of them occurs in the lowered input,
which keeps scanning near-linear on large documents.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.engines.redaction.heuristics import (
    char_class_count,
    is_code_reference,
    is_digits,
    is_placeholder,
    looks_fake,
    shannon_entropy,
)
from app.engines.redaction.keys import classify_key

# Specificity tiers used to resolve overlapping candidates (higher wins).
SPEC_PROVIDER = 100
SPEC_STRUCTURED = 90
SPEC_CONTEXTUAL = 75
SPEC_HEADER = 60
SPEC_GENERIC = 40


@dataclass(frozen=True, slots=True)
class Candidate:
    secret_type: str
    start: int
    end: int
    raw: str
    confidence: float
    specificity: int


@dataclass(frozen=True, slots=True)
class TokenPattern:
    secret_type: str
    regex: re.Pattern[str]
    confidence: float
    needles: tuple[str, ...]
    left: frozenset[str]  # characters that must NOT precede the match
    specificity: int = SPEC_PROVIDER


_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_WORD = _ALNUM | {"_", "-"}
_E = r"(?![A-Za-z0-9_\-])"
_EA = r"(?![A-Za-z0-9])"
# Leading look-behinds disable the regex engine's literal-prefix search (~30x slower on large
# inputs), so left boundaries are checked in Python instead: B = word boundary, BA = alphanumeric.
_B, _BA = "B", "BA"


def _tp(
    secret_type: str,
    left: str,
    pattern: str,
    confidence: float,
    needles: tuple[str, ...],
    spec: int = SPEC_PROVIDER,
) -> TokenPattern:
    return TokenPattern(
        secret_type, re.compile(pattern), confidence, needles, _WORD if left == _B else _ALNUM, spec
    )


def left_ok(text: str, start: int, forbidden: frozenset[str]) -> bool:
    return start == 0 or text[start - 1] not in forbidden


def iter_needle(lower: str, needle: str) -> Iterator[int]:
    """Offsets of every occurrence of ``needle`` in ``lower`` (fast C-level search)."""
    i = lower.find(needle)
    while i >= 0:
        yield i
        i = lower.find(needle, i + 1)


# The named group ``body`` is the random part; placeholder checks run against it.
TOKEN_PATTERNS: tuple[TokenPattern, ...] = (
    _tp(
        "aws_access_key",
        _BA,
        r"(?:AKIA|ASIA|ABIA|ACCA)(?P<body>[A-Z0-9]{16})" + _EA,
        0.95,
        ("akia", "asia", "abia", "acca"),
    ),
    _tp(
        "github_token",
        _B,
        r"gh[pousr]_(?P<body>[A-Za-z0-9]{36,251})" + _E,
        0.97,
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    _tp("github_token", _B, r"github_pat_(?P<body>[A-Za-z0-9_]{60,251})" + _E, 0.97, ("github_pat_",)),
    _tp(
        "gitlab_token",
        _B,
        r"gl(?:pat|dt|rt|ptt|cbt|soat|ft|imt)-(?P<body>[A-Za-z0-9_\-]{20,64})" + _E,
        0.95,
        ("glpat-", "gldt-", "glrt-", "glptt-", "glcbt-", "glsoat-", "glft-", "glimt-"),
    ),
    _tp(
        "slack_token",
        _B,
        r"xox[abprse]-(?P<body>[0-9A-Za-z][0-9A-Za-z\-]{8,250}[0-9A-Za-z])(?![A-Za-z0-9\-])",
        0.95,
        ("xox",),
    ),
    _tp("stripe_live_key", _B, r"(?:sk|rk)_live_(?P<body>[A-Za-z0-9]{20,247})" + _E, 0.97, ("_live_",)),
    _tp("stripe_test_key", _B, r"(?:sk|rk)_test_(?P<body>[A-Za-z0-9]{20,247})" + _E, 0.8, ("_test_",)),
    _tp("stripe_webhook_secret", _B, r"whsec_(?P<body>[A-Za-z0-9+/=]{24,128})" + _E, 0.9, ("whsec_",)),
    _tp("anthropic_api_key", _B, r"sk-ant-(?P<body>[A-Za-z0-9_\-]{20,})" + _E, 0.98, ("sk-ant-",)),
    _tp(
        "openai_api_key",
        _B,
        r"sk-(?:proj|svcacct|admin)-(?P<body>[A-Za-z0-9_\-]{20,})" + _E,
        0.97,
        ("sk-proj-", "sk-svcacct-", "sk-admin-"),
    ),
    _tp(
        "openai_api_key", _B, r"sk-(?P<body>[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})" + _E, 0.99, ("t3blbkfj",)
    ),
    _tp("openai_api_key", _B, r"sk-(?P<body>[A-Za-z0-9]{32,})" + _E, 0.8, ("sk-",), SPEC_STRUCTURED),
    _tp("google_api_key", _B, r"AIza(?P<body>[0-9A-Za-z_\-]{35})" + _E, 0.9, ("aiza",)),
    _tp("google_oauth_token", _B, r"ya29\.(?P<body>[0-9A-Za-z_\-]{20,})" + _E, 0.85, ("ya29.",)),
    _tp("google_oauth_client_secret", _B, r"GOCSPX-(?P<body>[A-Za-z0-9_\-]{24,32})" + _E, 0.95, ("gocspx-",)),
    _tp("twilio_api_key", _BA, r"SK(?P<body>[0-9a-f]{32})" + _EA, 0.8, ("sk",), SPEC_STRUCTURED),
    _tp("sendgrid_api_key", _B, r"SG\.(?P<body>[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})" + _E, 0.98, ("sg.",)),
    _tp("npm_token", _B, r"npm_(?P<body>[A-Za-z0-9]{36})" + _E, 0.95, ("npm_",)),
    _tp("huggingface_token", _B, r"hf_(?P<body>[A-Za-z0-9]{34,40})" + _E, 0.9, ("hf_",)),
    _tp(
        "pypi_token",
        _B,
        r"pypi-AgEIcHlwaS5vcmc(?P<body>[A-Za-z0-9_\-]{50,})" + _E,
        0.98,
        ("pypi-ageichlwas5vcmc",),
    ),
    _tp("docker_hub_token", _B, r"dckr_pat_(?P<body>[A-Za-z0-9_\-]{27,})" + _E, 0.95, ("dckr_pat_",)),
    _tp("digitalocean_token", _B, r"do[por]_v1_(?P<body>[a-f0-9]{64})" + _E, 0.95, ("_v1_",)),
    _tp(
        "shopify_token",
        _B,
        r"shp(?:at|ca|pa|ss)_(?P<body>[a-fA-F0-9]{32})" + _E,
        0.95,
        ("shpat_", "shpca_", "shppa_", "shpss_"),
    ),
    _tp("vault_token", _B, r"hv[sbr]\.(?P<body>[A-Za-z0-9_\-]{24,})" + _E, 0.85, ("hvs.", "hvb.", "hvr.")),
    _tp("databricks_token", _BA, r"dapi(?P<body>[a-f0-9]{32})(?:-\d)?" + _EA, 0.85, ("dapi",)),
    _tp("linear_api_key", _B, r"lin_api_(?P<body>[A-Za-z0-9]{40})" + _E, 0.95, ("lin_api_",)),
    _tp("supabase_token", _B, r"sbp_(?P<body>[a-f0-9]{40})" + _E, 0.95, ("sbp_",)),
    _tp("groq_api_key", _B, r"gsk_(?P<body>[A-Za-z0-9]{48,56})" + _E, 0.9, ("gsk_",)),
    _tp("xai_api_key", _B, r"xai-(?P<body>[A-Za-z0-9]{70,90})" + _E, 0.9, ("xai-",)),
    _tp("telegram_bot_token", _BA, r"\d{8,10}:(?P<body>AA[A-Za-z0-9_\-]{33})" + _E, 0.85, (":aa",)),
    _tp(
        "slack_webhook",
        _BA,
        r"https?://hooks\.slack\.com/(?P<body>(?:services|workflows|triggers)/[A-Za-z0-9_/\-]{20,})",
        0.95,
        ("hooks.slack.com",),
    ),
    _tp(
        "discord_webhook",
        _BA,
        r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(?P<body>\d{5,30}/[A-Za-z0-9_\-]{40,})",
        0.95,
        ("/api/webhooks/",),
    ),
    _tp("contextos_api_key", _B, r"ctxk_(?P<body>[A-Za-z0-9_\-]{40,})" + _E, 0.99, ("ctxk_",)),
    _tp("contextos_session_token", _B, r"ctxs_(?P<body>[A-Za-z0-9_\-]{40,})" + _E, 0.99, ("ctxs_",)),
)

# Webhook URLs keep their host visible (useful for destination analysis); only the path is secret.
_SPAN_IS_BODY = frozenset({"slack_webhook", "discord_webhook"})


# Patterns whose body alphabet contains their own prefix ("xoxb-xoxb-...") are matched only at
# prefix occurrences that pass the boundary check, so repeated prefixes cannot cost O(n * body).
_ANCHORED = frozenset(
    {
        "slack_token",
        "gitlab_token",
        "github_token",
        "anthropic_api_key",
        "google_api_key",
        "google_oauth_client_secret",
        "docker_hub_token",
        "contextos_api_key",
        "contextos_session_token",
    }
)


def _token_matches(pattern: TokenPattern, text: str, lower: str) -> Iterator[re.Match[str]]:
    if pattern.secret_type not in _ANCHORED:
        for m in pattern.regex.finditer(text):
            if left_ok(text, m.start(), pattern.left):
                yield m
        return
    resume = 0
    for pos in sorted({p for needle in pattern.needles for p in iter_needle(lower, needle)}):
        if pos < resume or not left_ok(text, pos, pattern.left):
            continue
        found = pattern.regex.match(text, pos)
        if found is not None:
            resume = found.end()
            yield found


def scan_tokens(text: str, lower: str) -> Iterator[Candidate]:
    for pattern in TOKEN_PATTERNS:
        if not any(needle in lower for needle in pattern.needles):
            continue
        for m in _token_matches(pattern, text, lower):
            body = m.group("body")
            if is_placeholder(body):
                continue
            confidence = pattern.confidence * (0.5 if looks_fake(body) else 1.0)
            start, end = (
                (m.start("body"), m.end("body")) if pattern.secret_type in _SPAN_IS_BODY else m.span()
            )
            yield Candidate(pattern.secret_type, start, end, text[start:end], confidence, pattern.specificity)


# --- private keys ----------------------------------------------------------------------------

_PEM_BEGIN_RE = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----")
_PEM_END_RE = re.compile(r"-----END (?P<label>[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----")
# Anything outside base64, whitespace, RFC 1421 header characters or JSON-escaped line breaks.
_PEM_BODY_BAD_RE = re.compile(r"[^A-Za-z0-9+/=\s:,.()\\\-]|\\(?![nrt])")
_PEM_HEAD_BODY_RE = re.compile(r"(?:[A-Za-z0-9+/=\s:,\-]|\\[nrt]){64,20000}")
_PEM_MAX_BODY = 20000
_PUTTY_RE = re.compile(r"Private-Lines:\s*\d+(?P<body>(?:[A-Za-z0-9+/=\s]|\\[nr]){64,8000})")
_PEM_STRIP_RE = re.compile(r"\\[nrt]|\s")
_PEM_HEADER_LINE_RE = re.compile(r"[A-Za-z\-]+:[^\n\\]*(?:\\n|\n)")


def _pem_canonical(body: str) -> str:
    return _PEM_STRIP_RE.sub("", _PEM_HEADER_LINE_RE.sub("", body))


def _last_invalid(body: str) -> int:
    last = -1
    for m in _PEM_BODY_BAD_RE.finditer(body):
        last = m.start()
    return last


def _pem_blocks(text: str) -> Iterator[Candidate]:
    """Complete BEGIN/END blocks, else truncated ones (a tool output cut short). Linear time:
    END markers are indexed once, and a body known to contain an invalid character is not
    re-validated for every later BEGIN marker that shares the same END."""
    ends: dict[str, list[int]] = {}
    for m in _PEM_END_RE.finditer(text):
        ends.setdefault(m.group("label"), []).append(m.start())
    covered = -1
    last_bad: dict[int, int] = {}  # END offset -> offset of the last invalid body character before it
    for begin in _PEM_BEGIN_RE.finditer(text):
        if begin.start() < covered:
            continue
        label, body_start = begin.group("label"), begin.end()
        positions = ends.get(label, [])
        i = bisect.bisect_left(positions, body_start)
        if i < len(positions) and positions[i] - body_start <= _PEM_MAX_BODY:
            end_at = positions[i]
            if body_start > last_bad.get(end_at, -1):
                body = text[body_start:end_at]
                bad = _last_invalid(body)
                if bad >= 0:
                    last_bad[end_at] = body_start + bad
                else:
                    canonical = _pem_canonical(body)
                    if len(canonical) >= 64 and not is_placeholder(canonical) and "..." not in body:
                        covered = end_at + len(label) + 14  # "-----END " + label + "-----"
                        yield Candidate("private_key", begin.start(), covered, canonical, 0.99, SPEC_PROVIDER)
                        continue
        head = _PEM_HEAD_BODY_RE.match(text, body_start)
        if head is not None:
            canonical = _pem_canonical(head.group(0))
            if len(canonical) >= 64 and not is_placeholder(canonical):
                covered = head.end()
                yield Candidate("private_key", begin.start(), covered, canonical, 0.9, SPEC_PROVIDER - 5)


def scan_private_keys(text: str, lower: str) -> Iterator[Candidate]:
    if "private key" in lower:
        yield from _pem_blocks(text)
    if "private-lines:" in lower:
        for m in _PUTTY_RE.finditer(text):
            canonical = _pem_canonical(m.group("body"))
            if len(canonical) >= 64 and not is_placeholder(canonical):
                yield Candidate("private_key", m.start("body"), m.end("body"), canonical, 0.9, SPEC_PROVIDER)


# --- JSON Web Tokens -------------------------------------------------------------------------

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}(?![A-Za-z0-9_\-])")


def _jwt_header_confidence(token: str) -> float:
    segment = token.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        header = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return 0.5
    if isinstance(header, dict) and "alg" in header:
        return 0.9
    return 0.7 if isinstance(header, dict) else 0.5


def scan_jwts(text: str, lower: str) -> Iterator[Candidate]:
    resume = 0
    for pos in iter_needle(lower, "eyj"):
        # Checking the boundary first means each base64url run is attempted once (linear time).
        if pos < resume or not left_ok(text, pos, _WORD):
            continue
        m = _JWT_RE.match(text, pos)
        if m is not None:
            resume = m.end()
            token = m.group(0)
            yield Candidate("jwt", pos, m.end(), token, _jwt_header_confidence(token), SPEC_PROVIDER)


# --- credentials embedded in URLs / connection strings ----------------------------------------

_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
_URL_CREDS_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{1,24})://"
    r"(?P<user>[^\s:/@'\"`<>\\]{0,128}):(?P<secret>[^\s@/'\"`<>\\]{1,256})@(?P<host>[A-Za-z0-9.\-_\[\]%]{1,253})"
)
_DB_SCHEMES = frozenset(
    {
        "postgres",
        "postgresql",
        "postgis",
        "mysql",
        "mysql2",
        "mariadb",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mssql",
        "sqlserver",
        "oracle",
        "cockroachdb",
        "clickhouse",
        "kafka",
        "nats",
        "cassandra",
        "couchdb",
        "neo4j",
        "neo4j+s",
        "bolt",
        "memcached",
        "snowflake",
        "db2",
        "sqlalchemy",
        "postgresql+psycopg",
        "postgresql+psycopg2",
        "postgresql+asyncpg",
        "mysql+pymysql",
        "mysql+mysqldb",
        "mssql+pyodbc",
        "redshift",
        "influxdb",
        "elasticsearch",
    }
)
_WEAK_DEFAULTS = frozenset({"postgres", "mysql", "guest", "pass", "pwd", "root", "admin", "user", "test"})

_AZURE_RES = (
    (
        "accountkey=",
        re.compile(r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{40,1024}={0,2})"),
        "azure_storage_key",
        0.95,
    ),
    (
        "sharedaccesskey=",
        re.compile(r"(?i)SharedAccessKey=(?P<secret>[A-Za-z0-9+/]{30,1024}={0,2})"),
        "azure_shared_access_key",
        0.9,
    ),
)
_AZURE_SAS_RE = re.compile(r"(?i)sig=(?P<secret>[A-Za-z0-9%+/]{30,1024}(?:%3D|=){0,2})")


def scan_connection_strings(text: str, lower: str) -> Iterator[Candidate]:
    if "@" in text:
        resume = 0
        for sep in iter_needle(lower, "://"):
            start = sep
            while start > 0 and sep - start < 25 and text[start - 1] in _SCHEME_CHARS:
                start -= 1
            if start == sep or start < resume or not left_ok(text, start, _SCHEME_CHARS):
                continue
            m = _URL_CREDS_RE.match(text, start)
            if m is None:
                continue
            resume = m.end()
            secret = m.group("secret")
            if is_placeholder(secret) or (is_digits(secret) and len(secret) <= 5):
                continue
            kind = "database_credentials" if m.group("scheme").lower() in _DB_SCHEMES else "url_credentials"
            confidence = 0.5 if secret.lower() in _WEAK_DEFAULTS else 0.9
            yield Candidate(kind, m.start("secret"), m.end("secret"), secret, confidence, SPEC_STRUCTURED)
    for needle, regex, kind, confidence in _AZURE_RES:
        for pos in iter_needle(lower, needle):
            m = regex.match(text, pos)
            if m and left_ok(text, pos, _ALNUM) and not is_placeholder(m.group("secret")):
                yield Candidate(kind, *m.span("secret"), m.group("secret"), confidence, SPEC_PROVIDER)
    if "sv=" in lower:
        for pos in iter_needle(lower, "sig="):
            m = _AZURE_SAS_RE.match(text, pos)
            if m is None or pos == 0 or text[pos - 1] not in "?&;":
                continue
            if "sv=" in lower[max(0, pos - 400) : pos] and not is_placeholder(m.group("secret")):
                yield Candidate("azure_sas_token", *m.span("secret"), m.group("secret"), 0.85, SPEC_PROVIDER)


# --- HTTP authentication headers and cookies ---------------------------------------------------

_HEADER_LEFT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_AUTH_HEADER_RE = re.compile(
    r"(?i)authorization\\?[\"']?\s*[:=]\s*\\?[\"']?\s*"
    r"(?:(?P<scheme>bearer|token|bot|apikey|api-key|key|sso-key|basic)\s+)?"
    r"(?P<secret>[A-Za-z0-9\-._~+/:=]{8,4096})"
)
_BEARER_RE = re.compile(r"(?i)bearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{20,4096}=*)(?![A-Za-z0-9\-._~+/=])")
_COOKIE_HEADER_RE = re.compile(r"(?i)cookie\\?[\"']?\s*[:=]\s*\\?[\"']?(?P<val>[^\r\n\"'\\`]{3,8192})")
_COOKIE_PAIR_RE = re.compile(r"(?P<name>[A-Za-z0-9_\-.!#$%&*+^|~]{1,128})=(?P<value>[^;,\s]{1,4096})")
_COOKIE_ATTRIBUTES = frozenset(
    {
        "path",
        "domain",
        "expires",
        "max-age",
        "samesite",
        "secure",
        "httponly",
        "priority",
        "partitioned",
        "version",
    }
)
_SESSIONISH = ("sess", "sid", "auth", "token", "jwt", "login", "remember", "csrf", "xsrf")


def _basic_confidence(value: str) -> float:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return 0.6
    return 0.9 if ":" in decoded and len(decoded) > 2 else 0.6


def _is_token_literal(value: str) -> bool:
    return not is_placeholder(value) and not is_code_reference(value) and char_class_count(value) >= 2


def _scan_auth_headers(text: str, lower: str) -> Iterator[Candidate]:
    resume = 0
    for pos in iter_needle(lower, "authorization"):
        if pos < resume or not left_ok(text, pos, _HEADER_LEFT):
            continue
        m = _AUTH_HEADER_RE.match(text, pos)
        if m is None:
            continue
        resume = m.end()
        secret = m.group("secret").rstrip(".,:")
        if not _is_token_literal(secret):
            continue
        scheme = (m.group("scheme") or "").lower()
        if scheme == "basic":
            kind, confidence = "basic_auth", _basic_confidence(secret)
        elif scheme:
            kind, confidence = "bearer_token", 0.9 if len(secret) >= 16 else 0.7
        elif len(secret) >= 16 and shannon_entropy(secret) >= 3.0:
            kind, confidence = "bearer_token", 0.75
        else:
            continue
        start = m.start("secret")
        yield Candidate(kind, start, start + len(secret), secret, confidence, SPEC_HEADER)


def _scan_cookies(text: str, lower: str) -> Iterator[Candidate]:
    resume = 0
    for pos in iter_needle(lower, "cookie"):
        if pos < resume or not left_ok(text, pos, _HEADER_LEFT):
            continue
        m = _COOKIE_HEADER_RE.match(text, pos)
        if m is None:
            continue
        resume = m.end()
        base = m.start("val")
        for pair in _COOKIE_PAIR_RE.finditer(m.group("val")):
            name, value = pair.group("name"), pair.group("value")
            if name.lower() in _COOKIE_ATTRIBUTES or is_placeholder(value):
                continue
            named = classify_key(name) is not None or any(h in name.lower() for h in _SESSIONISH)
            strong = len(value) >= 16 and shannon_entropy(value) >= 3.0 and char_class_count(value) >= 2
            if strong or (named and len(value) >= 8):
                start = base + pair.start("value")
                yield Candidate(
                    "session_cookie", start, start + len(value), value, 0.85 if named else 0.7, SPEC_HEADER
                )


def scan_http_auth(text: str, lower: str) -> Iterator[Candidate]:
    yield from _scan_auth_headers(text, lower)
    resume = 0
    for pos in iter_needle(lower, "bearer"):
        if pos < resume or not left_ok(text, pos, _WORD):
            continue
        m = _BEARER_RE.match(text, pos)
        if m is None:
            continue
        resume = m.end()
        secret = m.group("secret")
        if _is_token_literal(secret) and shannon_entropy(secret) >= 3.0:
            yield Candidate("bearer_token", *m.span("secret"), secret, 0.75, SPEC_HEADER - 5)
    yield from _scan_cookies(text, lower)


# --- password hashes (crackable offline; never persist) ----------------------------------------

_HASH_RES = (
    re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"),
    re.compile(r"\$[56]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}"),
    re.compile(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"),
    re.compile(r"\$y\$[./A-Za-z0-9]{1,32}\$[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{43}"),
    re.compile(r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}"),
    re.compile(r"scrypt\$[A-Za-z0-9+/]{16,}={0,2}\$[A-Za-z0-9+/]{32,}={0,2}"),
)


def scan_password_hashes(text: str, lower: str) -> Iterator[Candidate]:
    if "$" not in text:
        return
    for regex in _HASH_RES:
        for m in regex.finditer(text):
            yield Candidate("password_hash", m.start(), m.end(), m.group(0), 0.6, SPEC_STRUCTURED)


STRUCTURAL_SCANNERS = (
    scan_tokens,
    scan_private_keys,
    scan_jwts,
    scan_connection_strings,
    scan_http_auth,
    scan_password_hashes,
)
