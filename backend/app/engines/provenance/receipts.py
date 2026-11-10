"""Context receipts: a canonical, signed attestation of what ContextOS observed about a context item.

A receipt attests to metadata only — where the content came from, when it was collected and received,
its SHA-256 hash and length, its classification at ingest time and what detection found. It never
contains the content itself (raw content is never persisted).

Canonical form: the dict returned by :func:`receipt_fields` serialised as JSON with sorted keys,
compact separators, UTF-8 and no NaN/Infinity. Signatures are a keyed HMAC-SHA256 with the server
secret under the purpose ``context-receipt-v1``; rotating the server secret invalidates receipts.

``receipt_fields`` is idempotent: feeding a previously exported receipt back in yields the same
fields, so an exported receipt can be re-verified as-is.
"""

from __future__ import annotations

import hmac
import json
import math
from collections.abc import Mapping
from typing import Any

from app.core.security import keyed_hmac
from app.engines.provenance._util import count_of, get, lower, to_utc_iso, upper

RECEIPT_VERSION = "1"
RECEIPT_PURPOSE = "context-receipt-v1"
_SIGNATURE_HEX_LEN = 64  # HMAC-SHA256 hex digest


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text != "" else None


def _source_fields(item: Any) -> dict[str, Any]:
    source = get(item, "source")
    source = source if isinstance(source, Mapping) else {}
    source_type = source.get("type") or source.get("source_type") or get(item, "source_type")
    identifier = source.get("identifier") or get(item, "source_identifier")
    # Trust AT INGEST: the item's own trust_level is authoritative. A source's *current* trust level is
    # deliberately not used — it can change on reassessment, which would silently invalidate receipts.
    trust = get(item, "trust_level") or source.get("trust_level_at_ingest") or get(item, "trust_level_at_ingest")
    return {
        "type": lower(source_type),
        "identifier": _str_or_none(identifier),
        "trust_level_at_ingest": upper(trust) or "UNKNOWN",
    }


def _score(value: Any) -> float:
    try:
        number = float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(number) or math.isinf(number):
        return 0.0
    return round(number, 3)


def _detection_fields(item: Any) -> dict[str, Any]:
    summary = get(item, "detection_summary")
    if not isinstance(summary, Mapping):
        summary = get(item, "detection")
    summary = summary if isinstance(summary, Mapping) else {}
    rule_ids = summary.get("rule_ids") or []
    if isinstance(rule_ids, str):
        rule_ids = [rule_ids]
    return {
        "score": _score(summary.get("score")),
        "max_severity": lower(summary.get("max_severity")),
        "rule_ids": sorted({str(r) for r in rule_ids if r not in (None, "")}),
    }


def _content_length(value: Any) -> int:
    try:
        return max(int(value), 0) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def receipt_fields(item: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Canonical subset of a context item that a receipt attests to.

    Accepts a mapping (or an object with the same attribute names, e.g. a ``ContextItem`` row) with:
    ``id`` (or ``context_item_id``), ``organization_id``, ``source`` ({type|source_type, identifier,
    trust_level_at_ingest}) or flat ``source_type``/``source_identifier``, ``trust_level`` (at ingest),
    ``agent_id``, ``session_id``, ``event_id``, ``collected_via``, ``collected_at``, ``received_at``
    (datetimes or ISO strings), ``content_hash``, ``content_length``, ``content_type``, ``sensitivity``,
    ``contains_secrets``, ``secret_fingerprints`` (list) or ``secret_fingerprint_count``,
    ``detection_summary`` (or ``detection``) and ``tool_invocation_id``.
    """
    fingerprints = get(item, "secret_fingerprints")
    fingerprint_count = count_of(fingerprints) if fingerprints is not None else count_of(
        get(item, "secret_fingerprint_count")
    )
    return {
        "receipt_version": RECEIPT_VERSION,
        "context_item_id": _str_or_none(get(item, "id") or get(item, "context_item_id")),
        "organization_id": _str_or_none(get(item, "organization_id")),
        "source": _source_fields(item),
        "agent_id": _str_or_none(get(item, "agent_id")),
        "session_id": _str_or_none(get(item, "session_id")),
        "event_id": _str_or_none(get(item, "event_id")),
        "collected_via": _str_or_none(get(item, "collected_via")),
        "collected_at": to_utc_iso(get(item, "collected_at"), field_name="collected_at"),
        "received_at": to_utc_iso(get(item, "received_at"), field_name="received_at"),
        "content_hash": lower(get(item, "content_hash")),
        "content_length": _content_length(get(item, "content_length")),
        "content_type": _str_or_none(get(item, "content_type")),
        "sensitivity": lower(get(item, "sensitivity")),
        "contains_secrets": bool(get(item, "contains_secrets")),
        "secret_fingerprint_count": fingerprint_count,
        "detection": _detection_fields(item),
        "tool_invocation_id": _str_or_none(get(item, "tool_invocation_id")),
    }


def canonical_json(fields: Mapping[str, Any]) -> str:
    """The exact text a receipt signature covers (sorted keys, compact separators, no NaN)."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sign_receipt(fields: Mapping[str, Any]) -> str:
    """Keyed HMAC-SHA256 (hex) over the canonical JSON of ``fields``."""
    return keyed_hmac(canonical_json(fields).encode("utf-8"), purpose=RECEIPT_PURPOSE)


def verify_receipt(fields: Mapping[str, Any], signature: str | None) -> bool:
    """Constant-time check that ``signature`` matches ``fields``. Malformed input returns ``False``."""
    if not isinstance(signature, str) or len(signature) != _SIGNATURE_HEX_LEN:
        return False
    try:
        expected = sign_receipt(fields)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected.encode("ascii"), signature.lower().encode("ascii", "replace"))
