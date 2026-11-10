"""Secret detection and redaction engine (pure; no database access).

CONTRACT — implemented by the redaction work package; signatures are stable and used by the
ingestion pipeline, audit log and workspace attachments:

    detect_secrets(text) -> list[SecretMatch]
    redact_text(text) -> RedactionResult                 # "[REDACTED:<type>:<fp8>]" placeholders
    redact_value(value) -> tuple[Any, list[SecretMatch]] # recursive over dict/list/str; also redacts
                                                         # values under sensitive keys (password, token,
                                                         # authorization, api_key, secret, cookie, ...)
    fingerprint_secret(raw) -> str                       # keyed HMAC, 16 hex chars; raw never stored
    classify_sensitivity(text, matches, identifier=None) -> Sensitivity
    is_sensitive_path(path) -> tuple[bool, str | None]   # .env, id_rsa, .aws/credentials, *.pem, ...

Fingerprints let ContextOS recognise the SAME secret later appearing in an outbound tool call
without ever persisting the secret.
"""

from app.engines.redaction.engine import (
    RedactionResult,
    SecretMatch,
    classify_sensitivity,
    detect_secrets,
    fingerprint_secret,
    is_sensitive_path,
    redact_text,
    redact_value,
)

__all__ = [
    "RedactionResult",
    "SecretMatch",
    "classify_sensitivity",
    "detect_secrets",
    "fingerprint_secret",
    "is_sensitive_path",
    "redact_text",
    "redact_value",
]
