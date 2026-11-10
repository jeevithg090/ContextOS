"""Credential primitives: password hashing, opaque tokens, API keys, keyed HMACs.

- Passwords: scrypt (stdlib) with per-password salt.
- Session tokens and API keys: high-entropy opaque strings; only their SHA-256 hash is stored.
- ``keyed_hmac``: HMAC-SHA256 with the server secret, used for secret fingerprints, receipts and
  the audit chain. Never store or log raw secrets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from app.core.config import get_settings

API_KEY_PREFIX = "ctxk_"
SESSION_TOKEN_PREFIX = "ctxs_"

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    actual = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return hmac.compare_digest(actual, expected)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(raw_key, display_prefix, key_hash)``. Show ``raw_key`` to the user exactly once."""
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[: len(API_KEY_PREFIX) + 6], hash_token(raw)


def generate_session_token() -> tuple[str, str]:
    raw = SESSION_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def keyed_hmac(message: str | bytes, *, purpose: str) -> str:
    """HMAC-SHA256 over ``message`` with a purpose-separated derivation of the server secret."""
    secret = get_settings().secret_key.encode()
    key = hmac.new(secret, purpose.encode(), hashlib.sha256).digest()
    data = message.encode() if isinstance(message, str) else message
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()
