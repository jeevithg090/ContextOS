"""Field-name classification: does a dict key / assignment name hold a credential?

Used by ``redact_value`` (structured payloads) and by the assignment detectors (``password = ...``,
``API_KEY=...``). Keys are split into lowercase components on separators and camelCase, so
``X-Api-Key``, ``githubToken``, ``DB_PASSWORD`` and ``set-cookie`` all classify, while metadata
fields that merely *mention* a secret (``secret_type``, ``api_key_id``, ``token_count``,
``session_id``) do not — redacting those would destroy provenance without protecting anything.
"""

from __future__ import annotations

import re
from functools import lru_cache

# Last components that describe a secret rather than contain one.
_METADATA_SUFFIXES = frozenset(
    {
        "type",
        "types",
        "kind",
        "id",
        "ids",
        "name",
        "names",
        "count",
        "counts",
        "length",
        "len",
        "size",
        "prefix",
        "suffix",
        "last4",
        "hint",
        "label",
        "description",
        "desc",
        "fingerprint",
        "fingerprints",
        "fp",
        "hash",
        "hashes",
        "digest",
        "sha",
        "sha1",
        "sha256",
        "checksum",
        "integrity",
        "url",
        "uri",
        "urls",
        "endpoint",
        "path",
        "paths",
        "file",
        "filename",
        "files",
        "dir",
        "directory",
        "env",
        "var",
        "source",
        "location",
        "ref",
        "reference",
        "expires",
        "expiry",
        "expiration",
        "exp",
        "ttl",
        "at",
        "age",
        "created",
        "updated",
        "rotated",
        "rotation",
        "version",
        "mode",
        "enabled",
        "disabled",
        "required",
        "present",
        "detected",
        "found",
        "configured",
        "field",
        "fields",
        "policy",
        "policies",
        "rule",
        "rules",
        "scope",
        "scopes",
        "algorithm",
        "alg",
        "format",
        "encoding",
        "status",
        "provider",
        "issuer",
        "audience",
        "region",
        "min",
        "max",
        "limit",
        "limits",
        "timeout",
        "days",
        "hours",
        "minutes",
        "seconds",
        "ms",
        "domain",
        "secure",
        "samesite",
        "httponly",
        "store",
        "manager",
        "backend",
        "strategy",
        "method",
        "methods",
        "usage",
        "used",
        "budget",
        "rate",
        "ratio",
        "score",
        "level",
        "sensitivity",
        "category",
        "findings",
        "matches",
        "redacted",
        "redactions",
        "pattern",
        "patterns",
        "regex",
        "schema",
        "index",
        "position",
        "offset",
        "start",
        "end",
        "style",
        "class",
        "color",
        "colour",
        "icon",
        "placeholder",
        "visible",
        "strength",
        "valid",
        "validity",
        "param",
        "parameter",
        "option",
        "options",
        "flag",
    }
)

# First components that turn the key into a boolean/number/description of a secret.
_METADATA_PREFIXES = frozenset(
    {
        "is",
        "has",
        "use",
        "uses",
        "requires",
        "require",
        "needs",
        "enable",
        "enabled",
        "allow",
        "allows",
        "show",
        "hide",
        "with",
        "without",
        "no",
        "num",
        "n",
        "max",
        "min",
        "total",
        "count",
        "last",
        "masked",
        "redacted",
        "expected",
        "missing",
        "invalid",
        "valid",
    }
)

_SESSION_KEYS = frozenset({"session", "sessionid", "sessid", "phpsessid", "jsessionid", "sessionkey", "sid"})
_PASSWORD_LAST = frozenset({"pass", "pwd", "pword", "pw"})
_TOKEN_COMPONENTS = frozenset({"token", "jwt", "bearer", "otp", "totp", "csrftoken", "xsrftoken"})

_KEY_WORDS = (
    "apikey",
    "accesskey",
    "authkey",
    "signingkey",
    "encryptionkey",
    "masterkey",
    "licensekey",
    "subscriptionkey",
)

_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def split_key(key: str) -> list[str]:
    """``X-Api-Key`` -> ["x", "api", "key"]; ``githubToken`` -> ["github", "token"]."""
    parts: list[str] = []
    for chunk in _SPLIT_RE.split(key):
        if not chunk:
            continue
        pieces = _CAMEL_RE.findall(chunk)
        # Glue digits back onto the previous piece ("sha256", "last4", "db2") so they stay one word.
        merged: list[str] = []
        for piece in pieces:
            if piece.isdigit() and merged:
                merged[-1] += piece
            else:
                merged.append(piece.lower())
        parts.extend(merged)
    return parts


@lru_cache(maxsize=4096)
def classify_key(key: str) -> str | None:
    """Credential category held by a field named ``key``, or None.

    Categories: password, api_key, token, secret, private_key, credentials, authorization,
    cookie, session.
    """
    if not key or len(key) > 128:
        return None
    comps = split_key(key)
    if not comps:
        return None
    if len(comps) > 1 and (comps[-1] in _METADATA_SUFFIXES or comps[0] in _METADATA_PREFIXES):
        return None
    compact = "".join(comps)

    if "authorization" in compact:
        return "authorization"
    if "cookie" in compact:
        return "cookie"
    if "privatekey" in compact or ("private" in comps and "key" in comps):
        return "private_key"
    if "secret" in compact and "secretar" not in compact:
        return "secret"
    if "password" in compact or "passwd" in compact or "passphrase" in compact:
        return "password"
    if comps[-1] in _PASSWORD_LAST and (len(comps) > 1 or comps[0] in {"pass", "pwd"}):
        return "password"
    if any(word in compact for word in _KEY_WORDS):
        return "api_key"
    if "credential" in compact:
        return "credentials"
    if compact.endswith("token") or any(c in _TOKEN_COMPONENTS for c in comps):
        return "token"
    if compact in _SESSION_KEYS:
        return "session"
    return None


@lru_cache(maxsize=4096)
def is_metadata_key(key: str) -> bool:
    """Descriptive fields (``id``, ``name``, ``type``, ``created_at``, ``scopes``...) that do not
    inherit sensitivity from a parent credential object."""
    comps = split_key(key) if key and len(key) <= 128 else []
    return bool(comps) and (comps[-1] in _METADATA_SUFFIXES or comps[0] in _METADATA_PREFIXES)


def env_key_category(key: str) -> str | None:
    """Like :func:`classify_key`, plus env-style names ending in ``_KEY`` (``STRIPE_KEY``)."""
    category = classify_key(key)
    if category is not None:
        return category
    comps = split_key(key)
    if len(comps) > 1 and comps[-1] == "key" and comps[0] not in _METADATA_PREFIXES:
        return "api_key"
    return None
