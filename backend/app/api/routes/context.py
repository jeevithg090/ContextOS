"""Context Explorer: context items, sources and Context Receipts.

Answers "what information entered my agents, and from where?". Every endpoint needs ``read``
(users or API keys with the ``read`` scope). Lookups are scoped to the caller's organisation and,
for API keys bound to one agent, to that agent: anything else is reported as not found (404).

Static paths are registered before ``/items/{item_id}`` and ``/sources/{source_id}``.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.database.session import get_db
from app.domain.enums import Permission, Sensitivity, SourceType, TrustLevel
from app.schemas.common import Page
from app.schemas.context import (
    ContextFacetsOut,
    ContextItemDetailOut,
    ContextItemSummaryOut,
    ContextReceiptOut,
    ContextSourceDetailOut,
    ContextSourceSummaryOut,
)
from app.services import context_service
from app.services.context_service import ItemFilters

router = APIRouter(prefix="/context", tags=["context"])

READ = Depends(require(Permission.READ.value))
_Q = Query(default=None, max_length=200, description="Matches the redacted preview, source identifier or "
           "display name; an exact item id or SHA-256 content hash also matches")


def _filters(
    q: str | None = _Q,
    source_id: str | None = Query(default=None, max_length=40),
    source_type: SourceType | None = None,
    agent_id: str | None = Query(default=None, max_length=40),
    session_id: str | None = Query(default=None, max_length=40),
    trust_level: list[TrustLevel] | None = Query(default=None, description="Trust at ingest; repeat for several"),
    sensitivity: list[Sensitivity] | None = Query(default=None),
    has_detections: bool | None = None,
    contains_secrets: bool | None = None,
    since: datetime | None = Query(default=None, description="Only items received at or after this time"),
    include_simulated: bool = Query(default=False, description="Include Simulation Lab data"),
) -> ItemFilters:
    return ItemFilters(
        q=q, source_id=source_id, source_type=source_type.value if source_type else None, agent_id=agent_id,
        session_id=session_id, trust_levels=tuple(t.value for t in trust_level or ()),
        sensitivities=tuple(s.value for s in sensitivity or ()), has_detections=has_detections,
        contains_secrets=contains_secrets, since=since, include_simulated=include_simulated,
    )


@router.get("/facets", response_model=ContextFacetsOut)
def item_facets(
    filters: ItemFilters = Depends(_filters), principal: Principal = READ, db: Session = Depends(get_db)
) -> ContextFacetsOut:
    """Item counts by trust, sensitivity and source type for the given filters (each facet ignores
    its own filter, so selecting a trust level does not hide the other levels' counts)."""
    return ContextFacetsOut.model_validate(
        context_service.facets(db, principal.org_id, filters, bound_agent_id=principal.bound_agent_id)
    )


@router.get("/items", response_model=Page[ContextItemSummaryOut])
def list_items(
    filters: ItemFilters = Depends(_filters),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> Page[ContextItemSummaryOut]:
    """Context that entered the organisation's agents, newest first (by server receive time)."""
    items, total = context_service.list_items(
        db, principal.org_id, filters, bound_agent_id=principal.bound_agent_id, limit=limit, offset=offset
    )
    return Page[ContextItemSummaryOut](
        items=[ContextItemSummaryOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset
    )


@router.get("/items/{item_id}", response_model=ContextItemDetailOut)
def get_item(item_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> ContextItemDetailOut:
    """One context item: redacted preview, detections with explanations, findings and observed provenance."""
    return ContextItemDetailOut.model_validate(
        context_service.get_item(db, principal.org_id, item_id, bound_agent_id=principal.bound_agent_id)
    )


@router.get("/items/{item_id}/receipt", response_model=ContextReceiptOut)
def get_receipt(
    item_id: str,
    events_limit: int = Query(default=10, ge=0, le=50, description="How many later session events to include"),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> ContextReceiptOut:
    """The signed Context Receipt, re-verified now, with a plain-language statement of what it proves."""
    return ContextReceiptOut.model_validate(
        context_service.get_receipt(
            db, principal.org_id, item_id, bound_agent_id=principal.bound_agent_id, events_limit=events_limit
        )
    )


@router.get("/sources", response_model=Page[ContextSourceSummaryOut])
def list_sources(
    q: str | None = Query(default=None, max_length=200, description="Matches identifier, display name or domain"),
    source_type: SourceType | None = None,
    trust_level: TrustLevel | None = Query(default=None, description="The source's current classification"),
    has_findings: bool | None = None,
    include_simulated: bool = Query(default=False, description="Count Simulation Lab items and findings"),
    sort: str = Query(default="last_seen", pattern="^(last_seen|items|findings)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> Page[ContextSourceSummaryOut]:
    """Where context came from, with how much each source delivered and what it triggered."""
    items, total = context_service.list_sources(
        db, principal.org_id, q=q, source_type=source_type.value if source_type else None,
        trust_level=trust_level.value if trust_level else None, has_findings=has_findings,
        include_simulated=include_simulated, sort=sort, bound_agent_id=principal.bound_agent_id,
        limit=limit, offset=offset,
    )
    return Page[ContextSourceSummaryOut](
        items=[ContextSourceSummaryOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset
    )


@router.get("/sources/{source_id}", response_model=ContextSourceDetailOut)
def get_source(
    source_id: str,
    include_simulated: bool = Query(default=False, description="Include Simulation Lab items and findings"),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> ContextSourceDetailOut:
    """A source with its trust explanation, recent items, findings and the agents that consumed it."""
    return ContextSourceDetailOut.model_validate(
        context_service.get_source(
            db, principal.org_id, source_id, include_simulated=include_simulated,
            bound_agent_id=principal.bound_agent_id,
        )
    )
