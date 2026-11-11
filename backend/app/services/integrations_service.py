"""Integration registry: health of connected integrations, evidence counts and the catalog view.

``Integration`` rows are created and counted by the ingestion pipeline (``touch_integration``) for
real traffic only — Simulation Lab events never mark an integration as connected. Health follows
the shared staleness rule (``integrations_health``: stale after 24 hours without an event); the
per-integration evidence counts come from persisted rows (``IngestedEvent``, ``PolicyDecision``,
``Agent``), never from estimates.

The capability catalog lives in ``integrations_catalog`` and setup guides in ``integrations_setup``;
both are re-exported here so existing imports keep working.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc, utcnow
from app.models import Agent, IngestedEvent, Integration, Organization, PolicyDecision
from app.schemas.integrations import (
    CapabilityOut,
    CatalogEntryOut,
    ConnectedIntegrationOut,
    EnforcementCountsOut,
    IntegrationsOut,
    SetupGuideOut,
)
from app.services.bootstrap import effective_org_settings
from app.services.integrations_catalog import (
    CATALOG,
    CATALOG_BY_KIND,
    CatalogSpec,
    best_enforcement,
    catalog_spec,
    display_name,
    normalise_kind,
)
from app.services.integrations_health import (
    CONNECTED,
    NEVER_SEEN,
    STALE,
    STALE_AFTER,
    STALE_AFTER_HOURS,
    STALE_AFTER_MINUTES,
    freshness,
)
from app.services.integrations_setup import server_url_for, setup_guide

__all__ = [
    "CATALOG", "CATALOG_BY_KIND", "STALE_AFTER", "CatalogSpec", "catalog_spec", "connected_integrations",
    "display_name", "health_of", "integrations_overview", "normalise_kind", "server_url_for", "setup_guide",
    "setup_guide_for_org",
]

_ORDER = {CONNECTED: 0, STALE: 1, NEVER_SEEN: 2}
_best_enforcement = best_enforcement  # former private name


def health_of(last_event_at: datetime | None, now: datetime) -> tuple[str, str]:
    """``connected`` | ``stale`` (no event for 24 hours) | ``never_seen``, with a plain explanation."""
    health = freshness(last_event_at, now)
    if health == NEVER_SEEN:
        return health, "Registered, but no event has been received yet."
    if health == CONNECTED:
        return health, f"Received an event in the last {STALE_AFTER_HOURS} hours."
    return health, (f"No event in the last {STALE_AFTER_HOURS} hours. The agent may simply be idle; if it is "
                    "running, check its configuration with `contextos doctor`.")


def setup_guide_for_org(db: Session, org_id: str, kind: str, base_url: str) -> SetupGuideOut | None:
    """``setup_guide`` with the organisation's configured fail mode written into the steps."""
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    fail_mode = str(effective_org_settings(org)["fail_mode"]) if org is not None else None
    return setup_guide(kind, base_url, fail_mode=fail_mode)


# ----------------------------------------------------------------------------- evidence counts


def _events_24h(db: Session, org_id: str, since: datetime) -> dict[str, int]:
    rows = db.execute(
        select(IngestedEvent.integration, func.count())
        .where(IngestedEvent.organization_id == org_id, IngestedEvent.is_simulation.is_(False),
               IngestedEvent.received_at >= since)
        .group_by(IngestedEvent.integration)
    ).all()
    counts: dict[str, int] = {}
    for raw, n in rows:
        key = normalise_kind(raw)
        counts[key] = counts.get(key, 0) + int(n)
    return counts


def _decisions_by_kind(db: Session, org_id: str) -> dict[str, EnforcementCountsOut]:
    rows = db.execute(
        select(IngestedEvent.integration, PolicyDecision.enforcement, func.count())
        .join(IngestedEvent, (IngestedEvent.id == PolicyDecision.event_id)
              & (IngestedEvent.organization_id == PolicyDecision.organization_id))
        .where(PolicyDecision.organization_id == org_id, PolicyDecision.is_simulation.is_(False))
        .group_by(IngestedEvent.integration, PolicyDecision.enforcement)
    ).all()
    out: dict[str, EnforcementCountsOut] = {}
    for raw, mode, n in rows:
        counts = out.setdefault(normalise_kind(raw), EnforcementCountsOut())
        if mode in ("enforced", "advisory", "observed"):
            setattr(counts, mode, getattr(counts, mode) + int(n))
    return out


def _agents_by_integration(db: Session, org_id: str, ids: list[str]) -> dict[str, int]:
    if not ids:
        return {}
    rows = db.execute(
        select(Agent.integration_id, func.count())
        .where(Agent.organization_id == org_id, Agent.is_simulation.is_(False), Agent.integration_id.in_(ids))
        .group_by(Agent.integration_id)
    ).all()
    return {str(i): int(n) for i, n in rows}


# ----------------------------------------------------------------------------- registry


def connected_integrations(db: Session, org_id: str, now: datetime) -> list[ConnectedIntegrationOut]:
    rows = list(db.scalars(select(Integration).where(Integration.organization_id == org_id)))
    events = _events_24h(db, org_id, now - timedelta(hours=24))
    decisions = _decisions_by_kind(db, org_id)
    agents = _agents_by_integration(db, org_id, [r.id for r in rows])
    out: list[ConnectedIntegrationOut] = []
    for row in rows:
        health, detail = health_of(row.last_event_at, now)
        out.append(ConnectedIntegrationOut(
            id=row.id, kind=row.kind, name=row.name, display_name=display_name(row.kind),
            supported=getattr(CATALOG_BY_KIND.get(row.kind), "status", None) == "supported",
            best_enforcement=best_enforcement(row.kind), health=health, health_detail=detail,
            first_seen_at=row.created_at, last_event_at=row.last_event_at,
            event_count=row.event_count or 0, decision_count=row.decision_count or 0,
            events_24h=events.get(row.kind, 0), decisions=decisions.get(row.kind, EnforcementCountsOut()),
            agent_count=agents.get(row.id, 0), last_error=row.last_error,
        ))
    epoch = datetime.min.replace(tzinfo=now.tzinfo)
    out.sort(key=lambda i: (_ORDER[i.health], -(ensure_utc(i.last_event_at) or epoch).timestamp(), i.kind))
    return out


def _catalog_entry(spec: CatalogSpec, connected: list[ConnectedIntegrationOut]) -> CatalogEntryOut:
    mine = [c for c in connected if c.kind == spec.kind]
    health = min((c.health for c in mine), key=_ORDER.__getitem__, default="never_seen")
    last = max((c.last_event_at for c in mine if c.last_event_at is not None), default=None)

    def caps(items: tuple[tuple[str, str, str], ...]) -> list[CapabilityOut]:
        return [CapabilityOut(name=n, mode=m, description=d) for n, m, d in items]  # type: ignore[arg-type]

    return CatalogEntryOut(
        kind=spec.kind, name=spec.name, status=spec.status, summary=spec.summary,  # type: ignore[arg-type]
        best_enforcement=spec.best_enforcement, monitoring=caps(spec.monitoring),  # type: ignore[arg-type]
        enforcement=caps(spec.enforcement), limitations=list(spec.limitations),
        integration_surface=spec.integration_surface, available_today=spec.available_today,
        interim_kind=spec.interim_kind, docs_path=spec.docs_path, api_key_scopes=list(spec.api_key_scopes),
        health=health, last_event_at=last,  # type: ignore[arg-type]
    )


def integrations_overview(db: Session, org_id: str, *, now: datetime | None = None) -> IntegrationsOut:
    now = now or utcnow()
    connected = connected_integrations(db, org_id, now)
    return IntegrationsOut(
        connected=connected,
        catalog=[_catalog_entry(spec, connected) for spec in CATALOG],
        stale_after_minutes=STALE_AFTER_MINUTES,
        stale_after_hours=STALE_AFTER_HOURS,
        generated_at=now,
    )
