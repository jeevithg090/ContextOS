"""Trust Centre summary: how sources and destinations are classified, and what changed recently.

Every number is counted from stored rows (sources, destinations, trust rules) or read from the
audit trail (recent downgrades); nothing is estimated. Sources and destinations only Simulation Lab
traffic observed are excluded unless the caller asks for them (``include_simulated``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, TRUST_RANK
from app.models import ContextSource, Destination, TrustRule
from app.services.scoping import scoped
from app.services.trust_service_history import DOWNGRADE_WINDOW_DAYS, recently_downgraded
from app.services.trust_service_simulation import real_destination_filter, real_source_filter
from app.services.trust_service_sources import capability_filter, sources_out

TOP_SOURCES = 8
_CANDIDATES = 200


def _distribution(
    db: Session, model: type[Any], column: Any, org_id: str, *where: Any
) -> tuple[int, dict[str, int]]:
    rows = db.execute(
        select(column, func.count()).where(model.organization_id == org_id, *where).group_by(column)
    ).all()
    by_level = {level: 0 for level in TRUST_RANK}
    for level, count in rows:
        by_level[str(level)] = by_level.get(str(level), 0) + int(count)
    return sum(by_level.values()), by_level


def _count(db: Session, model: type[Any], org_id: str, *where: Any) -> int:
    return int(
        db.scalar(select(func.count()).select_from(model).where(model.organization_id == org_id, *where)) or 0
    )


def summary(db: Session, org_id: str, *, include_simulated: bool = False) -> dict[str, Any]:
    """Counts over the organisation's sources and destinations; ones only Simulation Lab traffic
    observed are left out unless ``include_simulated``."""
    src = [] if include_simulated else [real_source_filter()]
    dst = [] if include_simulated else [real_destination_filter(org_id)]
    total_sources, source_levels = _distribution(db, ContextSource, ContextSource.trust_level, org_id, *src)
    total_dests, dest_levels = _distribution(db, Destination, Destination.classification, org_id, *dst)
    rules = db.execute(
        select(TrustRule.applies_to, TrustRule.enabled).where(TrustRule.organization_id == org_id)
    ).all()

    candidates = list(
        db.scalars(
            scoped(ContextSource, org_id)
            .where(ContextSource.finding_count > 0, *src)
            .order_by(ContextSource.finding_count.desc(), ContextSource.last_seen_at.desc())
            .limit(_CANDIDATES)
        )
    )
    candidates.sort(
        key=lambda s: (-SEVERITY_RANK.get(s.max_finding_severity or "", -1), -(s.finding_count or 0))
    )
    return {
        "sources": {
            "total": total_sources,
            "by_level": source_levels,
            "manual": _count(db, ContextSource, org_id, ContextSource.manually_classified.is_(True), *src),
            "with_findings": _count(db, ContextSource, org_id, ContextSource.finding_count > 0, *src),
            "can_instruct": _count(db, ContextSource, org_id, capability_filter("instruct"), *src),
        },
        "destinations": {
            "total": total_dests,
            "by_level": dest_levels,
            "with_blocked_calls": _count(db, Destination, org_id, Destination.blocked_count > 0, *dst),
            "with_sensitive_transfers": _count(
                db, Destination, org_id, Destination.sensitive_transfer_count > 0, *dst
            ),
        },
        "rules": {
            "total": len(rules),
            "enabled": sum(1 for _applies, enabled in rules if enabled),
            "source": sum(1 for applies, _enabled in rules if applies in ("source", "both")),
            "destination": sum(1 for applies, _enabled in rules if applies in ("destination", "both")),
        },
        "sources_with_findings": sources_out(db, org_id, candidates[:TOP_SOURCES]),
        "recently_downgraded": recently_downgraded(db, org_id, include_simulated=include_simulated),
        "downgrade_window_days": DOWNGRADE_WINDOW_DAYS,
    }
