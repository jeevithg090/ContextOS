"""Which Trust Centre sources and destinations only Simulation Lab traffic has observed.

Simulated data never mixes into real views unless the caller opts in (``include_simulated``).
- A source is simulation-only while ``ContextSource.is_simulation`` is true: ingestion sets it when
  simulated traffic creates the source and clears it the first time real traffic observes it.
- A destination is simulation-only when every recorded tool call sent to it was simulated (a
  destination with no recorded call at all is shown: it cannot be attributed to a simulation).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import ContextSource, Destination, ToolInvocation

__all__ = ["real_destination_filter", "real_source_filter", "simulation_only_destinations"]


def real_source_filter() -> Any:
    return ContextSource.is_simulation.is_(False)


def _calls(org_id: str) -> Any:
    return select(ToolInvocation.destination_id).where(
        ToolInvocation.organization_id == org_id, ToolInvocation.destination_id.is_not(None))


def real_destination_filter(org_id: str) -> Any:
    """Destinations observed by real traffic (or with no recorded call)."""
    calls = _calls(org_id)
    return or_(Destination.id.in_(calls.where(ToolInvocation.is_simulation.is_(False))), Destination.id.not_in(calls))


def simulation_only_destinations(db: Session, org_id: str, ids: Iterable[str]) -> set[str]:
    """The subset of ``ids`` that only simulated tool calls were sent to."""
    wanted = list(dict.fromkeys(ids))
    if not wanted:
        return set()
    rows = db.execute(
        select(ToolInvocation.destination_id, ToolInvocation.is_simulation)
        .where(ToolInvocation.organization_id == org_id, ToolInvocation.destination_id.in_(wanted))
        .group_by(ToolInvocation.destination_id, ToolInvocation.is_simulation)
    ).all()
    real = {d for d, simulated in rows if not simulated}
    return {d for d, simulated in rows if simulated and d not in real}
