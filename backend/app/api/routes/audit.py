"""Audit log, hash-chain verification and export.

- ``GET /audit`` (read) — newest first; filters: action prefix, actor, target, time window.
- ``GET /audit/verify`` (read) — recomputes the keyed hash chain (``services.audit.verify_chain``)
  and explains what a pass or failure means, including the threat model's limits.
- ``GET /audit/export`` (admin) — the full chain as JSON Lines, for archiving and for anchoring the
  head hash externally. The export itself is audited (``audit.exported``) before streaming.

Details were redacted when written (``append_audit``); they are passed through the redaction engine
again on the way out as defence in depth (redaction is idempotent, so hashes stay verifiable).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.core.timeutil import ensure_utc, isoformat, utcnow
from app.database.session import get_db, session_factory
from app.engines.redaction import redact_value
from app.models import ApiKey, AuditEvent, Membership, Organization, User
from app.schemas.audit import ActorTypeLiteral, AuditEventOut, AuditThreatModelOut, AuditVerifyOut
from app.schemas.common import Page
from app.services.audit import append_audit, verify_chain
from app.services.scoping import paginate, scoped

log = get_logger(__name__)
router = APIRouter(prefix="/audit", tags=["audit"])

READ = Depends(require_org_wide("read"))  # bound API keys: 403
ADMIN = Depends(require("admin"))
_EXPORT_BATCH = 500

THREAT_MODEL = AuditThreatModelOut(
    detects=[
        "Changes to any entry's time, actor, action, target or details by someone who can write to the database "
        "but does not hold the server secret (CONTEXTOS_SECRET_KEY) — for example through SQL injection, or a "
        "backup that was edited and restored.",
        "Entries that were deleted, inserted or reordered: sequence numbers and each entry's link to the previous "
        "hash no longer line up.",
        "Removal of the newest entries: the chain no longer ends at the head hash recorded for the organisation.",
    ],
    does_not_protect_against=[
        "An attacker holding both database write access and the server secret: they can recompute every hash "
        "and rewrite the whole chain consistently.",
        "Wiping every entry together with the organisation's head record. Compare against an externally anchored "
        "head hash to detect this.",
        "Actions that were never recorded. Verification proves the recorded history is intact, not that it is "
        "complete.",
    ],
    anchoring="Copy the head hash and its sequence number to an external write-once store on a schedule (every "
              "export carries them in the X-ContextOS-Audit-Head-Hash and X-ContextOS-Audit-Through-Seq headers). "
              "If the entry at an anchored sequence number later has a different hash, history up to that point was "
              "rewritten — this holds even against someone who has the server secret.",
)

_REASONS = (
    ("sequence gap", "An entry is missing or out of order, which happens when entries are deleted or re-numbered."),
    ("prev_hash", "This entry no longer links to the entry before it: an earlier entry was removed, inserted or "
                  "rewritten."),
    ("entry contents", "This entry was changed after it was written: its contents no longer match the keyed hash "
                       "stored with it."),
    ("chain tail", "The chain ends before the organisation's recorded head: the newest entries were deleted, or "
                   "the head record was altered."),
)


def _explain(reason: str | None) -> str | None:
    if not reason:
        return None
    return next((text for key, text in _REASONS if key in reason), reason)


def _safe(details: dict[str, Any] | None) -> dict[str, Any]:
    redacted, _ = redact_value(details or {})
    return redacted if isinstance(redacted, dict) else {"value": redacted}


def _actors(db: Session, principal: Principal, rows: list[AuditEvent]) -> dict[tuple[str, str], tuple[str, str | None]]:
    """Display names for the actors on this page. Users are resolved only while they are members of
    the organisation; emails are shown to signed-in users only (as for the member list)."""
    user_ids = {r.actor_id for r in rows if r.actor_type == "user" and r.actor_id}
    key_ids = {r.actor_id for r in rows if r.actor_type == "api_key" and r.actor_id}
    out: dict[tuple[str, str], tuple[str, str | None]] = {}
    if user_ids:
        members = db.execute(
            select(User.id, User.name, User.email).join(Membership, Membership.user_id == User.id)
            .where(Membership.organization_id == principal.org_id, User.id.in_(user_ids))
        ).all()
        for uid, name, email in members:
            out[("user", uid)] = (name or email, email if principal.kind == "user" else None)
    if key_ids:
        for key in db.scalars(scoped(ApiKey, principal.org_id).where(ApiKey.id.in_(key_ids))):
            out[("api_key", key.id)] = (key.name, f"{key.prefix}…")
    return out


def _out(row: AuditEvent, actors: dict[tuple[str, str], tuple[str, str | None]]) -> AuditEventOut:
    if row.actor_type == "system":
        label, detail = "ContextOS", None
    else:
        label, detail = actors.get((row.actor_type, row.actor_id or ""), (None, None))
    return AuditEventOut(
        id=row.id, seq=row.seq, occurred_at=row.occurred_at, actor_type=row.actor_type, actor_id=row.actor_id,
        actor_label=label, actor_detail=detail, action=row.action, target_type=row.target_type,
        target_id=row.target_id, details=_safe(row.details), prev_hash=row.prev_hash, hash=row.hash,
    )


@router.get("", response_model=Page[AuditEventOut])
def list_audit(
    action: str | None = Query(None, max_length=64, description="Action prefix, e.g. 'policy.' or 'auth.login'"),
    actor_type: ActorTypeLiteral | None = None,
    actor_id: str | None = Query(None, max_length=40),
    target_type: str | None = Query(None, max_length=48),
    target_id: str | None = Query(None, max_length=40),
    since: datetime | None = Query(None, description="Entries at or after this time (ISO-8601, UTC if no offset)"),
    until: datetime | None = Query(None, description="Entries at or before this time"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> Page[AuditEventOut]:
    """Audit entries of the caller's organisation, newest first."""
    since, until = ensure_utc(since), ensure_utc(until)
    if since and until and since > until:
        raise ValidationFailedError("'since' must not be later than 'until'")
    query = scoped(AuditEvent, principal.org_id)
    if action and action.strip():
        query = query.where(AuditEvent.action.startswith(action.strip(), autoescape=True))
    if actor_type:
        query = query.where(AuditEvent.actor_type == actor_type)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)
    if target_type:
        query = query.where(AuditEvent.target_type == target_type)
    if target_id:
        query = query.where(AuditEvent.target_id == target_id)
    if since:
        query = query.where(AuditEvent.occurred_at >= since)
    if until:
        query = query.where(AuditEvent.occurred_at <= until)
    rows, total = paginate(db, query.order_by(AuditEvent.seq.desc()), limit=limit, offset=offset)
    actors = _actors(db, principal, rows)
    return Page(items=[_out(r, actors) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/verify", response_model=AuditVerifyOut)
def verify(principal: Principal = READ, db: Session = Depends(get_db)) -> AuditVerifyOut:
    """Recompute the organisation's hash chain from the first entry to the recorded head."""
    result = verify_chain(db, principal.org_id)
    org = db.get(Organization, principal.org_id)
    head_seq = (org.audit_seq or 0) if org else 0
    seq = result["first_invalid_seq"]
    entry_id = None
    if seq is not None:
        entry_id = db.scalar(select(AuditEvent.id).where(AuditEvent.organization_id == principal.org_id,
                                                         AuditEvent.seq == seq))
    explained = _explain(result["reason"])
    if result["valid"]:
        summary = (f"All {result['checked']} entries verified: each matches its keyed hash, links to the entry "
                   "before it, and the chain ends at the organisation's recorded head."
                   if result["checked"] else "There are no audit entries yet, so there is nothing to verify.")
    else:
        log.warning("audit.chain_invalid", extra={"org_id": principal.org_id, "seq": seq, "reason": result["reason"]})
        summary = (f"Verification failed at entry #{seq}. Entries before it are intact; this entry and everything "
                   f"after it cannot be trusted. {explained}")
    return AuditVerifyOut(
        valid=result["valid"], checked=result["checked"], head_seq=head_seq, head_hash=result["head_hash"],
        first_invalid_seq=seq, first_invalid_entry_id=entry_id, reason=result["reason"], reason_explained=explained,
        summary=summary, verified_at=utcnow(), threat_model=THREAT_MODEL,
    )


def _export_record(row: AuditEvent) -> dict[str, Any]:
    return {
        "seq": row.seq, "id": row.id, "org": row.organization_id, "occurred_at": isoformat(row.occurred_at),
        "actor_type": row.actor_type, "actor_id": row.actor_id, "action": row.action,
        "target_type": row.target_type, "target_id": row.target_id, "details": _safe(row.details),
        "prev_hash": row.prev_hash, "hash": row.hash,
    }


def _export_lines(org_id: str, through_seq: int) -> Iterator[bytes]:
    """Streams in its own session so it does not depend on the request session's lifetime."""
    with session_factory()() as db:
        query = (select(AuditEvent)
                 .where(AuditEvent.organization_id == org_id, AuditEvent.seq <= through_seq)
                 .order_by(AuditEvent.seq)
                 .execution_options(yield_per=_EXPORT_BATCH))
        for row in db.scalars(query):
            yield (json.dumps(_export_record(row), sort_keys=True, separators=(",", ":"), default=str) + "\n").encode()


@router.get("/export", response_class=StreamingResponse)
def export(principal: Principal = ADMIN, db: Session = Depends(get_db)) -> StreamingResponse:
    """The full chain as JSON Lines (oldest first). Admin only; recorded as ``audit.exported``."""
    org = db.get(Organization, principal.org_id)
    if org is None:
        raise NotFoundError("Organisation not found")
    entry = append_audit(db, principal.org_id, action="audit.exported", actor_type=principal.actor_type,
                         actor_id=principal.actor_id, target_type="organization", target_id=principal.org_id,
                         details={"format": "jsonl", "scope": "full_chain"})
    through_seq, head_hash = entry.seq, entry.hash
    db.commit()  # the export is on the record before any byte leaves the server
    slug = re.sub(r"[^a-z0-9-]+", "-", (org.slug or "org").lower()).strip("-") or "org"
    filename = f"contextos-audit-{slug}-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    return StreamingResponse(
        _export_lines(principal.org_id, through_seq),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-ContextOS-Audit-Through-Seq": str(through_seq),
            "X-ContextOS-Audit-Head-Hash": head_hash,
        },
    )
