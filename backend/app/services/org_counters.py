"""Per-organisation counters (audit chain sequence, event sequence, task and incident numbers) reserved
atomically, and the organisation-row lock (``lock_org``) for check-then-act sequences.

A read-then-write increment (``org.audit_seq = org.audit_seq + 1``) loses updates under concurrency:
on SQLite the read happens outside the write transaction, so two requests compute the same next value
and one fails on a unique constraint (or, without one, both use it). ``reserve`` increments in a
single ``UPDATE ... RETURNING``, which takes the write lock (the row lock on PostgreSQL, the database
write lock on SQLite) and holds it until the caller's transaction ends, so the values it returns —
including ``also`` columns such as the audit chain head — cannot change underneath the caller.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.models import Organization


def reserve(db: Session, org_id: str, counter: str, *also: str) -> tuple[Any, ...]:
    """Increment ``Organization.<counter>``; return ``(new value, *also)`` as stored at that moment.

    A loaded ``Organization`` in the session is brought up to date with the returned values, so later
    reads through the ORM (and later assignments of ``also`` columns) see the reserved state.
    """
    column = getattr(Organization, counter)
    statement = (
        update(Organization)
        .where(Organization.id == org_id)
        .values({counter: func.coalesce(column, 0) + 1})
        .returning(column, *(getattr(Organization, name) for name in also))
        .execution_options(synchronize_session=False)
    )
    row = db.execute(statement).one()
    org = db.get(Organization, org_id)
    if org is not None:
        for name, value in zip((counter, *also), row, strict=True):
            set_committed_value(org, name, value)
    return tuple(row)


def lock_org(db: Session, org_id: str) -> None:
    """Take the organisation row's write lock (the one ``reserve`` takes) without changing anything.

    Use it before a check-then-act that concurrent requests could otherwise pass together (a WIP limit,
    "is there already an open task for this finding?"). Every audited write and every ingested event
    takes this lock anyway (``append_audit`` / the event sequence), and ingestion takes it first, so
    taking it at the check keeps one lock order (organisation row first) and only moves the wait
    earlier. The lock is held until the caller's transaction ends.
    """
    db.execute(
        update(Organization)
        .where(Organization.id == org_id)
        .values(audit_seq=Organization.audit_seq, updated_at=Organization.updated_at)  # unchanged
        .execution_options(synchronize_session=False)
    )
