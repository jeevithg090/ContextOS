"""Trust Centre: trust history, read from the tamper-evident audit trail.

Trust changes are written to the audit chain by the ingestion pipeline (``trust.source_reclassified``
when observed content changes a source's classification) and by the Trust Centre (manual
classification, re-assessment, rule changes). History shown in the UI is read back from those
entries, so it is exactly what the audit log can prove.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.domain.enums import TRUST_RANK, TrustCapability
from app.models import AuditEvent, ContextSource, Destination
from app.services.scoping import scoped
from app.services.trust_service_common import actor_label, user_labels
from app.services.trust_service_simulation import simulation_only_destinations

SOURCE_TARGET = "context_source"
DESTINATION_TARGET = "destination"
SOURCE_ACTIONS = ("trust.source_reclassified", "trust.source_classified", "trust.source_reassessed")
DESTINATION_ACTIONS = ("trust.destination_reclassified", "trust.destination_classified")
MANUAL_SOURCE_ACTION = "trust.source_classified"
DOWNGRADE_WINDOW_DAYS = 30
_DOWNGRADE_SCAN = 1000
_HISTORY_LIMIT = 50


def _level(value: Any) -> str | None:
    return value if isinstance(value, str) and value in TRUST_RANK else None


def _text(value: Any, limit: int = 1000) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


def describe_entry(entry: AuditEvent) -> str:
    d = entry.details or {}
    old, new = _level(d.get("from")), _level(d.get("to"))
    change = f"{old} → {new}" if old and new and old != new else (new or "unchanged")
    action = entry.action
    if action == "trust.source_classified":
        requested = _level(d.get("requested_level"))
        text = f"Manually classified as {requested or new}"
        if requested and new and requested != new:
            text += f" (kept at {new} by recorded evidence)"
        return text
    if action == "trust.source_reassessed":
        text = f"Re-assessed: {change}"
        return text + " — manual classification cleared" if d.get("reset_manual") else text
    if action in ("trust.source_reclassified", "trust.destination_reclassified"):
        if d.get("rule_id") or d.get("cause"):
            return f"Reclassified {change} after a trust rule change"
        if d.get("event_id"):
            return f"Reclassified {change} while processing observed content"
        return f"Reclassified {change}"
    if action == "trust.destination_classified":
        return f"Manually classified as {new} with an exact-match rule"
    return action


def history(db: Session, org_id: str, target_type: str, target_id: str, *, limit: int = _HISTORY_LIMIT) -> list[dict[str, Any]]:
    actions = SOURCE_ACTIONS if target_type == SOURCE_TARGET else DESTINATION_ACTIONS
    rows = list(db.scalars(
        select(AuditEvent)
        .where(AuditEvent.organization_id == org_id, AuditEvent.target_type == target_type,
               AuditEvent.target_id == target_id, AuditEvent.action.in_(actions))
        .order_by(AuditEvent.seq.desc())
        .limit(limit)
    ))
    users = user_labels(db, [r.actor_id for r in rows if r.actor_type == "user"])
    return [
        {
            "id": r.id,
            "at": r.occurred_at,
            "action": r.action,
            "summary": describe_entry(r),
            "from_level": _level((r.details or {}).get("from")),
            "to_level": _level((r.details or {}).get("to")),
            "actor_type": r.actor_type,
            "actor_id": r.actor_id,
            "actor_label": actor_label(r.actor_type, r.actor_id, users),
            "note": _text((r.details or {}).get("note")) or _text((r.details or {}).get("reason")),
        }
        for r in rows
    ]


def latest_manual(db: Session, org_id: str, source_id: str) -> AuditEvent | None:
    return db.scalar(
        select(AuditEvent)
        .where(AuditEvent.organization_id == org_id, AuditEvent.target_type == SOURCE_TARGET,
               AuditEvent.target_id == source_id, AuditEvent.action == MANUAL_SOURCE_ACTION)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    )


def manual_details(db: Session, org_id: str, source: ContextSource) -> dict[str, Any] | None:
    """The administrator's recorded intent for a manually classified source (from the audit trail).

    The stored ``trust_level`` can be lower than what the administrator chose (evidence downgrades
    apply even to manual classifications), so re-assessment restarts from the recorded choice.
    """
    if not source.manually_classified:
        return None
    entry = latest_manual(db, org_id, source.id)
    if entry is None:
        return None
    d = entry.details or {}
    caps = d.get("requested_capabilities")
    valid = {c.value for c in TrustCapability}
    users = user_labels(db, [entry.actor_id] if entry.actor_type == "user" else [])
    return {
        "at": entry.occurred_at,
        "actor_label": actor_label(entry.actor_type, entry.actor_id, users),
        "level": _level(d.get("requested_level")) or _level(d.get("to")),
        "capabilities": [c for c in caps if c in valid] if isinstance(caps, list) else [],
        "note": _text(d.get("note")),
        "reason": _text(d.get("reason")),
    }


def recently_downgraded(db: Session, org_id: str, *, limit: int = 10,
                        include_simulated: bool = False) -> list[dict[str, Any]]:
    """Latest downgrade per source/destination in the window. Records only Simulation Lab traffic
    observed are left out unless ``include_simulated``; every row says whether it is simulated."""
    since = utcnow() - timedelta(days=DOWNGRADE_WINDOW_DAYS)
    rows = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.organization_id == org_id, AuditEvent.occurred_at >= since,
               AuditEvent.action.in_(SOURCE_ACTIONS + DESTINATION_ACTIONS))
        .order_by(AuditEvent.seq.desc())
        .limit(_DOWNGRADE_SCAN)
    )
    picked: list[AuditEvent] = []
    seen: set[tuple[str, str]] = set()
    for entry in rows:
        d = entry.details or {}
        old, new = _level(d.get("from")), _level(d.get("to"))
        key = (entry.target_type or "", entry.target_id or "")
        if not old or not new or TRUST_RANK[new] >= TRUST_RANK[old] or key in seen or not entry.target_id:
            continue
        seen.add(key)
        picked.append(entry)
        if len(picked) >= limit * 2:
            break
    source_ids = [e.target_id for e in picked if e.target_type == SOURCE_TARGET]
    dest_ids = [e.target_id for e in picked if e.target_type == DESTINATION_TARGET]
    sources = {s.id: s for s in db.scalars(scoped(ContextSource, org_id).where(ContextSource.id.in_(source_ids)))} if source_ids else {}
    dests = {d.id: d for d in db.scalars(scoped(Destination, org_id).where(Destination.id.in_(dest_ids)))} if dest_ids else {}
    simulated_dests = simulation_only_destinations(db, org_id, dests)
    users = user_labels(db, [e.actor_id for e in picked if e.actor_type == "user"])
    out: list[dict[str, Any]] = []
    for entry in picked:
        d = entry.details or {}
        if entry.target_type == SOURCE_TARGET and entry.target_id in sources:
            src = sources[entry.target_id]
            target_type, label, simulated = "source", src.display_name or src.identifier, bool(src.is_simulation)
        elif entry.target_type == DESTINATION_TARGET and entry.target_id in dests:
            target_type, label = "destination", dests[entry.target_id].identifier
            simulated = entry.target_id in simulated_dests
        else:
            continue  # the record was deleted (retention); nothing to link to
        if simulated and not include_simulated:
            continue
        out.append({
            "target_type": target_type, "target_id": entry.target_id, "label": label[:400],
            "from_level": d["from"], "to_level": d["to"], "at": entry.occurred_at,
            "actor_label": actor_label(entry.actor_type, entry.actor_id, users), "summary": describe_entry(entry),
            "is_simulation": simulated,
        })
        if len(out) >= limit:
            break
    return out
