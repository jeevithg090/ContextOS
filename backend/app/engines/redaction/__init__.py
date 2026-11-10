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

Notes for callers:
- ``SecretMatch.confidence >= HIGH_CONFIDENCE`` (0.7) means "treat as a real credential"; lower
  values are still redacted but only raise sensitivity to CONFIDENTIAL.
- Offsets refer to the string that was scanned; for ``redact_value`` that is the individual
  string value, not the whole structure.
- Only the first ``MAX_SCAN_CHARS`` (2 MiB) of a string are scanned; ``redact_text`` drops the
  remainder (with a marker) instead of passing unscanned content through.
- Module layout: ``patterns`` (formatted credentials), ``contextual`` (assignment / context-based),
  ``keys`` (sensitive field names), ``paths`` (sensitive files), ``pii`` (classification signals),
  ``heuristics`` (entropy / placeholder checks), ``engine`` (public API).
"""

from app.engines.redaction.engine import (
    HIGH_CONFIDENCE,
    MAX_SCAN_CHARS,
    RedactionResult,
    SecretMatch,
    classify_sensitivity,
    detect_secrets,
    fingerprint_secret,
    is_sensitive_path,
    placeholder_for,
    redact_text,
    redact_value,
)

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
