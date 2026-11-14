"""Session-aware secret recognition for the ingestion pipeline.

The redaction engine recognises credentials by their form (prefixes, assignments, context words).
Once a credential has been seen with high confidence in a session's context (say, an AWS secret
key in ``AWS_SECRET_ACCESS_KEY=...`` of a ``.env`` file), the same value can later appear where no
detector recognises it: ``aws=<key>`` in a request body, a bare value in a tool error. Such a
value is still that credential. Here every candidate token of later text is fingerprinted with the
same keyed HMAC and compared with the session's recorded fingerprints; matches are redacted with
the engine's placeholder and reported like engine matches, so they count as secrets in arguments
and as session secret matches (credential flow) for policy.

Raw values exist only in memory (``PipelineState.raw_secrets``) for the duration of one event.
Encoded forms (URL-encoding, base64) of a known secret are not recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from app.engines.redaction import HIGH_CONFIDENCE, fingerprint_secret, placeholder_for, redact_text
from app.models import ContextItem
from app.services.ingestion_state import PipelineState

# Confidence assigned to a value matched by fingerprint: it equals a credential previously
# detected with high confidence, so it is treated as a real credential.
KNOWN_CONFIDENCE = 0.9
MIN_TOKEN = 8
MAX_TOKEN = 512
MAX_CANDIDATES = 20_000
_LENGTH = f"{{{MIN_TOKEN},{MAX_TOKEN}}}"
_FINE = re.compile(r"[^\s\"'`<>()\[\]{},;&=:@?#|\\]" + _LENGTH)  # split on delimiters
_COARSE = re.compile(r"\S" + _LENGTH)  # whitespace-separated words (secrets with punctuation)
_STRIP = "\"'`<>()[]{},;.!?"
_PLACEHOLDER = re.compile(r"\[REDACTED:[a-z_]+:[0-9a-f]{8}\]")


@dataclass(frozen=True)
class KnownSecret:
    raw: str
    secret_type: str
    fingerprint: str
    context_item_id: str

    @property
    def placeholder(self) -> str:
        return placeholder_for(self.secret_type, self.fingerprint)


def session_fingerprints(st: PipelineState) -> dict[str, tuple[str, str]]:
    """{fingerprint: (secret type, first context item id)} of high-confidence secrets in the session."""
    if st.session is None:
        return {}
    cached = st.known_fingerprints.get(st.session.id)
    if cached is not None:
        return cached
    rows = st.db.execute(
        select(ContextItem.id, ContextItem.secret_fingerprints)
        .where(
            ContextItem.organization_id == st.ctx.org_id,
            ContextItem.session_id == st.session.id,
            ContextItem.contains_secrets.is_(True),
        )
        .order_by(ContextItem.received_at)
    ).all()
    seen: dict[str, tuple[str, str]] = {}
    for item_id, fingerprints in rows:
        for fp in fingerprints or []:
            if not isinstance(fp, dict) or not fp.get("fingerprint"):
                continue
            if float(fp.get("confidence", 1.0)) >= HIGH_CONFIDENCE:
                seen.setdefault(str(fp["fingerprint"]), (str(fp.get("type") or "secret"), item_id))
    st.known_fingerprints[st.session.id] = seen
    return seen


def forget_session_fingerprints(st: PipelineState) -> None:
    """Call after recording context with new secrets so later lookups in this event see them."""
    if st.session is not None:
        st.known_fingerprints.pop(st.session.id, None)


def _strings(value: Any, out: list[str], depth: int = 0) -> None:
    if depth > 64:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _strings(key, out, depth + 1)
            _strings(item, out, depth + 1)
    elif isinstance(value, list | tuple):
        for item in value:
            _strings(item, out, depth + 1)


def _candidates(texts: list[str]) -> set[str]:
    found: set[str] = set()
    for text in texts:
        if len(text) < MIN_TOKEN:
            continue
        cleaned = _PLACEHOLDER.sub(" ", text)
        for pattern in (_FINE, _COARSE):
            for match in pattern.finditer(cleaned):
                token = match.group(0)
                found.add(token)
                stripped = token.strip(_STRIP)
                if len(stripped) >= MIN_TOKEN:
                    found.add(stripped)
                if len(found) >= MAX_CANDIDATES:
                    return found
    return found


def find_known(st: PipelineState, value: Any) -> list[KnownSecret]:
    """Tokens of ``value`` (any JSON-like value) equal to a secret already seen in this session."""
    known = session_fingerprints(st)
    if not known:
        return []
    texts: list[str] = []
    _strings(value, texts)
    out: dict[str, KnownSecret] = {}
    for token in _candidates(texts):
        fp = fingerprint_secret(token)
        if fp in known and token not in out:
            secret_type, item_id = known[fp]
            out[token] = KnownSecret(
                raw=token, secret_type=secret_type, fingerprint=fp, context_item_id=item_id
            )
    found = sorted(out.values(), key=lambda k: -len(k.raw))
    st.remember_raw([k.raw for k in found])
    return found


def redact_known(value: Any, known: list[KnownSecret], depth: int = 0) -> Any:
    """Replace every occurrence of the known raw values (longest first) with their placeholders."""
    if not known or depth > 64:
        return value
    if isinstance(value, str):
        for secret in known:
            if secret.raw in value:
                value = value.replace(secret.raw, secret.placeholder)
        return value
    if isinstance(value, dict):
        return {
            redact_known(k, known, depth + 1): redact_known(v, known, depth + 1) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_known(v, known, depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_known(v, known, depth + 1) for v in value)
    return value


def redact_session_text(st: PipelineState, text: str | None) -> str | None:
    """Engine redaction plus session-known secrets, for free text about to be persisted."""
    if text is None:
        return None
    redacted = redact_text(text).text
    return redact_known(redacted, find_known(st, redacted))


def as_matches(known: list[KnownSecret]) -> list[dict[str, Any]]:
    """Fingerprint entries in the shape used for ``secret_fingerprints``."""
    return [
        {
            "type": k.secret_type,
            "fingerprint": k.fingerprint,
            "confidence": KNOWN_CONFIDENCE,
            "matched_by": "session_fingerprint",
        }
        for k in known
    ]
