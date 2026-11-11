"""Time buckets and bucketed counts for the overview charts.

Bucket boundaries are computed in Python and each series is ONE aggregate query of
``SUM(CASE WHEN ts >= lo AND ts < hi THEN 1 ELSE 0 END)`` columns, so the database returns at most
(groups x buckets) integers whatever the row volume, and no dialect-specific date function
(``date_trunc`` / ``strftime``) is needed: the same SQL runs on SQLite and PostgreSQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

# window -> (bucket count, bucket unit)
WINDOWS: dict[str, tuple[int, str]] = {"24h": (24, "hour"), "7d": (7, "day"), "30d": (30, "day")}


@dataclass(frozen=True)
class Window:
    key: str
    bucket: str  # "hour" | "day"
    since: datetime  # start of the first bucket (inclusive)
    until: datetime  # end of the last bucket (exclusive; the current bucket is still filling)
    edges: tuple[datetime, ...]  # len(buckets) + 1 boundaries

    @property
    def starts(self) -> list[datetime]:
        return list(self.edges[:-1])


def window_for(key: str, now: datetime) -> Window:
    size, bucket = WINDOWS[key]
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    floor = now.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        floor = floor.replace(hour=0)
    since = floor - step * (size - 1)
    edges = tuple(since + step * i for i in range(size + 1))
    return Window(key=key, bucket=bucket, since=since, until=edges[-1], edges=edges)


def bucketed(
    db: Session,
    column: Any,
    conditions: list[Any],
    window: Window,
    *,
    group_by: Any | None = None,
) -> dict[Any, list[int]]:
    """``{group value: [count per bucket]}`` (key ``None`` when ungrouped)."""
    pairs = list(zip(window.edges[:-1], window.edges[1:], strict=True))
    sums = [func.coalesce(func.sum(case((and_(column >= lo, column < hi), 1), else_=0)), 0) for lo, hi in pairs]
    where = [*conditions, column >= window.since, column < window.until]
    if group_by is None:
        row = db.execute(select(*sums).where(*where)).one()
        return {None: [int(v or 0) for v in row]}
    rows = db.execute(select(group_by, *sums).where(*where).group_by(group_by)).all()
    return {row[0]: [int(v or 0) for v in row[1:]] for row in rows}


def points(window: Window, counts: dict[Any, list[int]], keys: dict[str, Any]) -> list[dict[str, Any]]:
    """One dict per bucket: ``{"t": start, <name>: count, ...}``; ``keys`` maps output name -> group value."""
    empty = [0] * (len(window.edges) - 1)
    out: list[dict[str, Any]] = []
    for i, start in enumerate(window.starts):
        point: dict[str, Any] = {"t": start}
        for name, group in keys.items():
            point[name] = (counts.get(group) or empty)[i]
        out.append(point)
    return out
