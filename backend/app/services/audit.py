"""Append-only, keyed hash-chained audit trail.

Each organisation has an independent chain. Entry ``n`` stores
``hash_n = HMAC(server_secret, canonical(entry_n) || hash_{n-1})``.

Threat model (see docs/SECURITY_MODEL.md):
- Detects modification, deletion or reordering of entries by anyone who can write to the database
  but does NOT hold ``CONTEXTOS_SECRET_KEY`` (e.g. a SQL-injection or a stolen DB backup restored
  with edits): they cannot recompute valid HMACs.
- Does NOT protect against an attacker holding both database write access and the server secret;
  they can rewrite the whole chain. For that threat, periodically export ``audit_head_hash`` to an
  external write-once store (documented as a deployment step).
- Truncation of the newest entries is detected by comparing the chain tail with
  ``Organization.audit_head_hash``.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import keyed_hmac
from app.core.timeutil import isoformat, utcnow
from app.models import AuditEvent, Organization

_PURPOSE = "audit-chain-v1"


def _canonical(entry: AuditEvent) -> str:
    body = {
        "seq": entry.seq,
        "org": entry.organization_id,
        "occurred_at": isoformat(entry.occurred_at),
        "actor_type": entry.actor_type,
        "actor_id": entry.actor_id,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details or {},
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _compute_hash(entry: AuditEvent) -> str:
    return keyed_hmac(_canonical(entry) + "|" + (entry.prev_hash or ""), purpose=_PURPOSE)


def _safe_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    try:
        from app.engines.redaction import redact_value

        redacted, _ = redact_value(details)
        return redacted if isinstance(redacted, dict) else {"value": redacted}
    except NotImplementedError:  # pragma: no cover - only before the redaction engine exists
        return details


def append_audit(
    db: Session,
    org_id: str,
    *,
    action: str,
    actor_type: str = "system",
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one audit entry in the caller's transaction. Pass ids and short metadata, not content."""
    org = db.execute(select(Organization).where(Organization.id == org_id).with_for_update()).scalar_one()
    org.audit_seq = (org.audit_seq or 0) + 1
    entry = AuditEvent(
        id=new_id("audit_event"),
        organization_id=org_id,
        seq=org.audit_seq,
        occurred_at=utcnow(),
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=_safe_details(details),
        prev_hash=org.audit_head_hash,
    )
    entry.hash = _compute_hash(entry)
    org.audit_head_hash = entry.hash
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session, org_id: str) -> dict[str, Any]:
    """Recompute the chain. Returns ``{"valid", "checked", "first_invalid_seq", "reason", "head_hash"}``."""
    org = db.get(Organization, org_id)
    prev: str | None = None
    expected_seq = 1
    checked = 0
    for entry in db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org_id).order_by(AuditEvent.seq)):
        checked += 1
        if entry.seq != expected_seq:
            return _invalid(checked, entry.seq, f"sequence gap: expected {expected_seq}, found {entry.seq}", org)
        if entry.prev_hash != prev:
            return _invalid(checked, entry.seq, "prev_hash does not match previous entry", org)
        if _compute_hash(entry) != entry.hash:
            return _invalid(checked, entry.seq, "entry contents do not match its hash", org)
        prev = entry.hash
        expected_seq += 1
    head = org.audit_head_hash if org else None
    if head != prev:
        return _invalid(checked, expected_seq, "chain tail does not match organisation head (truncation?)", org)
    return {"valid": True, "checked": checked, "first_invalid_seq": None, "reason": None, "head_hash": head}


def _invalid(checked: int, seq: int, reason: str, org: Organization | None) -> dict[str, Any]:
    return {
        "valid": False,
        "checked": checked,
        "first_invalid_seq": seq,
        "reason": reason,
        "head_hash": org.audit_head_hash if org else None,
    }
