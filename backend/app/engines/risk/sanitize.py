"""Value hygiene for resource identifiers (pure).

Resource ids end up in the database, provenance graph, policy input snapshots and the UI, so they
must never carry secret values. Arguments normally arrive already redacted by
``app.engines.redaction``; this module is defence in depth for the *identifiers* the risk engine
derives (URLs, hosts, paths): credentials in URL userinfo, secret-looking query values and
token-shaped path segments (e.g. Slack/Discord webhook tokens) are replaced with ``***``.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

MASK = "***"
MAX_ID_LENGTH = 1024

REDACTION_MARKER = "[REDACTED"

# Query/fragment keys whose values are always masked, whatever they look like.
_SENSITIVE_KEY_PARTS = (
    "token", "secret", "passw", "pwd", "auth", "sig", "credential", "session", "jwt",
    "apikey", "api_key", "api-key", "private", "cookie", "bearer",
)
_SENSITIVE_KEYS_EXACT = {"key", "code", "pass", "sid", "otp", "k", "access", "refresh"}

# Well-known credential prefixes (so short-but-real tokens are still masked).
_TOKEN_PREFIX = re.compile(
    r"^(?:sk-|sk_live_|sk_test_|rk_live_|pk_live_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abposr]-|"
    r"AKIA|ASIA|AIza|ya29\.|eyJ|npm_|pypi-|hf_|SG\.)"
)
_TOKENISH = re.compile(r"^[A-Za-z0-9+/=_\-.~:]+$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{2,59})$")
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

# Instance-metadata endpoints hand out cloud credentials to anything that can reach them.
METADATA_HOSTS = {
    "169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata", "100.100.100.200",
    "169.254.170.2",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def looks_secret(value: str, *, min_length: int = 20, min_entropy: float = 3.5) -> bool:
    """Heuristic: does this single token look like a credential / random token?"""
    if not value:
        return False
    if REDACTION_MARKER in value:
        return True
    if _TOKEN_PREFIX.match(value) and len(value) >= 12:
        return True
    if len(value) < min_length or not _TOKENISH.match(value):
        return False
    has_alpha = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    if not (has_alpha and has_digit) and len(value) < 40:
        return False
    return shannon_entropy(value) >= min_entropy


def is_sensitive_key(key: str) -> bool:
    k = key.strip().lower()
    return k in _SENSITIVE_KEYS_EXACT or any(part in k for part in _SENSITIVE_KEY_PARTS)


def mask_path_segments(path: str, *, min_length: int = 20, min_entropy: float = 3.5) -> str:
    """Replace token-shaped segments of a URL or file path with ``***``."""
    if not path:
        return path
    parts = path.split("/")
    return "/".join(MASK if looks_secret(p, min_length=min_length, min_entropy=min_entropy) else p for p in parts)


def _mask_pairs(raw: str) -> str:
    out = []
    for key, value in parse_qsl(raw, keep_blank_values=True):
        if looks_secret(key):
            out.append(MASK)
            continue
        masked = MASK if value and (is_sensitive_key(key) or looks_secret(value)) else value
        out.append(f"{quote(key, safe='')}={quote(masked, safe='*')}")
    return "&".join(out)


def truncate(value: str, limit: int = MAX_ID_LENGTH) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def sanitize_url(raw: str) -> str | None:
    """Normalise a URL for use as an identifier; secrets in it are masked. None if unparseable."""
    raw = raw.strip().strip("'\"<>()[]{},;")
    if "://" not in raw:
        return None
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if not scheme or not re.match(r"^[a-z][a-z0-9+.\-]*$", scheme):
        return None
    netloc = host
    if ":" in host:  # IPv6 literal
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    if parts.username is not None or parts.password is not None:
        netloc = f"{MASK}@{netloc}"
    path = mask_path_segments(parts.path)
    query = _mask_pairs(parts.query) if parts.query else ""
    fragment = ""
    if parts.fragment:
        fragment = _mask_pairs(parts.fragment) if "=" in parts.fragment else (
            MASK if looks_secret(parts.fragment) else parts.fragment
        )
    if scheme == "file":
        return truncate(urlunsplit((scheme, netloc, path, "", "")))
    return truncate(urlunsplit((scheme, netloc, path, query, fragment)))


def url_host(sanitized_url: str) -> str | None:
    try:
        host = urlsplit(sanitized_url).hostname
    except ValueError:
        return None
    return normalize_host(host) if host else None


def url_path(sanitized_url: str) -> str:
    try:
        return urlsplit(sanitized_url).path
    except ValueError:
        return ""


_SINGLE_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?$")


def normalize_host(raw: str | None, *, allow_single_label: bool = False) -> str | None:
    """Lower-cased host without port/brackets/trailing dot; None if it is not a host.

    ``allow_single_label`` accepts bare names such as ssh config aliases (``prod-db``).
    """
    if not raw:
        return None
    host = raw.strip().strip("'\"").lower()
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    host = host.split("/", 1)[0].rstrip(".")
    if not host or REDACTION_MARKER.lower() in host:
        return None
    if is_ip(host) or _DOMAIN.match(host) or host in _LOOPBACK_NAMES or host in METADATA_HOSTS:
        return host
    if allow_single_label and _SINGLE_LABEL.match(host) and not host.isdigit():
        return host
    return None


def looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN.match(value.lower().rstrip(".")))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_loopback(host: str) -> bool:
    """Loopback / unspecified addresses never leave the machine."""
    if host in _LOOPBACK_NAMES:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return False


def is_metadata_host(host: str) -> bool:
    return host in METADATA_HOSTS


def normalize_email(value: str) -> str | None:
    candidate = value.strip().strip("<>'\"").lower()
    if "<" in candidate and candidate.endswith(">"):  # "Name <a@b.com>"
        candidate = candidate.rsplit("<", 1)[1].rstrip(">")
    return candidate if _EMAIL.match(candidate) else None
