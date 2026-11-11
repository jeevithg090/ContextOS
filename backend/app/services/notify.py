"""Live-update notifications, published only AFTER the surrounding transaction commits.

    notify(db, org_id, "finding.created", id=finding.id)

Messages are tiny ({"type", "id", ...ids}) — never put content, arguments or secrets in them.
Type names are mirrored in frontend/src/hooks/useLiveEvents.ts.

Savepoints: releasing a ``begin_nested()`` block publishes nothing (the outer transaction can still
roll back); rolling one back drops only the notifications queued inside it (the ingestion pipeline
runs every event of a batch in its own SAVEPOINT; one failed event must not silence the notices of
the events before it). Rolling back the whole transaction drops everything.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session, SessionTransaction

from app.events.bus import bus

_KEY = "contextos_pending_notifications"
_MARKS = "contextos_notification_savepoints"  # id(savepoint transaction) -> queue length when it began


def notify(db: Session, org_id: str, type_: str, **fields: Any) -> None:
    pending: list[tuple[str, dict[str, Any]]] = db.info.setdefault(_KEY, [])
    pending.append((org_id, {"type": type_, **fields}))


@event.listens_for(Session, "after_commit")
def _flush_notifications(session: Session) -> None:
    # SQLAlchemy also fires after_commit when a SAVEPOINT is released; the transaction is still open
    # then (and may yet roll back), so nothing is published until the outermost commit.
    if session.in_nested_transaction():
        return
    session.info.pop(_MARKS, None)
    pending = session.info.pop(_KEY, None)
    if not pending:
        return
    for org_id, message in pending:
        bus.publish(org_id, message)


@event.listens_for(Session, "after_transaction_create")
def _mark_savepoint(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        session.info.setdefault(_MARKS, {})[id(transaction)] = len(session.info.get(_KEY) or ())


@event.listens_for(Session, "after_transaction_end")
def _forget_savepoint(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        session.info.get(_MARKS, {}).pop(id(transaction), None)


@event.listens_for(Session, "after_rollback")
def _drop_notifications(session: Session) -> None:
    # Fired for a SAVEPOINT rollback too; the savepoint being rolled back is still the session's
    # innermost nested transaction at this point (it is closed afterwards).
    savepoint = session.get_nested_transaction()
    if savepoint is None:
        session.info.pop(_KEY, None)
        session.info.pop(_MARKS, None)
        return
    keep = session.info.get(_MARKS, {}).get(id(savepoint))
    pending = session.info.get(_KEY)
    if pending is None:
        return
    if keep is None:  # began before this module was imported: cannot tell what is ours, drop all
        session.info.pop(_KEY, None)
        return
    del pending[keep:]
