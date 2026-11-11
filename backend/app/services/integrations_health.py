"""The one staleness rule for integrations: connected while events keep arriving, stale after 24 hours
without one, never seen before the first event.

Used by the Integrations page (``integrations_service``), the Overview (``overview_service_lists``)
and agent posture (``agents_posture``) so the three always agree. Health is derived from the last
real (non-simulated) event time that the ingestion pipeline records on the ``Integration`` row.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.core.timeutil import ensure_utc

STALE_AFTER = timedelta(hours=24)
STALE_AFTER_HOURS = int(STALE_AFTER.total_seconds() // 3600)
STALE_AFTER_MINUTES = int(STALE_AFTER.total_seconds() // 60)

CONNECTED = "connected"
STALE = "stale"
NEVER_SEEN = "never_seen"
ERROR = "error"


def is_stale(last_event_at: datetime | None, now: datetime) -> bool:
    """True when no event arrived within ``STALE_AFTER`` of ``now`` (or none ever arrived)."""
    last = ensure_utc(last_event_at)
    return last is None or now - last > STALE_AFTER


def freshness(last_event_at: datetime | None, now: datetime) -> str:
    """``connected`` | ``stale`` | ``never_seen`` from the last event time alone."""
    if ensure_utc(last_event_at) is None:
        return NEVER_SEEN
    return STALE if is_stale(last_event_at, now) else CONNECTED


def integration_health(last_event_at: datetime | None, now: datetime, *, status: str | None = None) -> str:
    """Freshness, except that a row the integration marked ``error`` reports ``error``."""
    if (status or "").lower() == ERROR:
        return ERROR
    return freshness(last_event_at, now)
