"""Live-update notifications, published only AFTER the surrounding transaction commits.

    notify(db, org_id, "finding.created", id=finding.id)

Messages are tiny ({"type", "id", ...ids}) — never put content, arguments or secrets in them.
Type names are mirrored in frontend/src/hooks/useLiveEvents.ts.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.events.bus import bus

_KEY = "contextos_pending_notifications"


def notify(db: Session, org_id: str, type_: str, **fields: Any) -> None:
    pending: list[tuple[str, dict[str, Any]]] = db.info.setdefault(_KEY, [])
    pending.append((org_id, {"type": type_, **fields}))


@event.listens_for(Session, "after_commit")
def _flush_notifications(session: Session) -> None:
    pending = session.info.pop(_KEY, None)
    if not pending:
        return
    for org_id, message in pending:
        bus.publish(org_id, message)


@event.listens_for(Session, "after_rollback")
def _drop_notifications(session: Session) -> None:
    session.info.pop(_KEY, None)
