"""Event ingestion (POST /events), synchronous decisions (POST /decide), approval polling and
cancellation, stateless scanning (POST /scan), the event log (GET /events) and the live stream
(GET /stream).

Authorisation: ``ingest`` for /events, ``decide`` for /decide and approval polling/cancellation,
``read`` for everything else. Scopes are checked before the body is validated. Writes are committed before the response is returned so a decision the
integration receives is always durable (and its approval pollable).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from app.api.deps import Principal, require
from app.core.config import get_settings
from app.core.errors import PayloadTooLargeError
from app.database.session import get_db
from app.domain.enums import EventType, Permission
from app.events.bus import bus
from app.schemas.common import Page
from app.schemas.events import (
    ApprovalCancelIn,
    ApprovalPollOut,
    DecisionResponse,
    EventBatch,
    EventBatchOut,
    EventEnvelope,
    IngestedEventDetailOut,
    IngestedEventOut,
    ScanIn,
    ScanOut,
)
from app.services import approvals, ingestion, ingestion_queries
from app.services.ingestion import AttributionRejectedError, DecisionFailedError, IngestContext

router = APIRouter(prefix="", tags=["events"])

INGEST = Depends(require(Permission.INGEST.value))
DECIDE = Depends(require(Permission.DECIDE.value))
READ = Depends(require(Permission.READ.value))
PING_SECONDS = 15


def ingest_context(principal: Principal) -> IngestContext:
    return IngestContext(
        org_id=principal.org_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        api_key_id=principal.api_key_id,
        bound_agent_id=principal.bound_agent_id,
    )


@router.post("/events", response_model=EventBatchOut)
def post_events(batch: EventBatch, principal: Principal = INGEST, db: Session = Depends(get_db)) -> EventBatchOut:
    """Record events as observed. Per-event results: ``accepted`` | ``duplicate`` | ``rejected``."""
    results = ingestion.ingest_batch(db, ingest_context(principal), batch.events)
    db.commit()
    return EventBatchOut(results=results)


@router.post("/decide", response_model=DecisionResponse)
def decide(
    envelope: EventEnvelope, request: Request, principal: Principal = DECIDE, db: Session = Depends(get_db)
) -> DecisionResponse:
    """Policy decision for a ``tool.requested`` event, returned before the tool runs."""
    length = request.headers.get("content-length")
    limit = get_settings().max_event_bytes
    if length and length.isdigit() and int(length) > limit:
        raise PayloadTooLargeError(f"Event exceeds the {limit}-byte limit")
    try:
        response = ingestion.decide_tool_request(db, ingest_context(principal), envelope)
    except (AttributionRejectedError, DecisionFailedError):
        db.commit()  # keep the audit entry / error record; the integration applies its fail mode
        raise
    db.commit()
    return response


@router.get("/decide/approvals/{approval_id}", response_model=ApprovalPollOut)
def poll_approval(approval_id: str, principal: Principal = DECIDE, db: Session = Depends(get_db)) -> ApprovalPollOut:
    approval = ingestion_queries.poll_approval(db, principal.org_id, approval_id,
                                               bound_agent_id=principal.bound_agent_id)
    db.commit()  # persists a lazy expiry
    return ApprovalPollOut(approval_id=approval.id, status=approval.status, decided_at=approval.decided_at,
                           decision_note=approval.decision_note, expires_at=approval.expires_at)


@router.post("/decide/approvals/{approval_id}/cancel", response_model=ApprovalPollOut)
def cancel_approval(
    approval_id: str, body: ApprovalCancelIn | None = None, principal: Principal = DECIDE,
    db: Session = Depends(get_db),
) -> ApprovalPollOut:
    """Withdraw a pending approval the integration is no longer waiting for (idempotent; 409 once a
    person decided it or it expired). The held call is recorded as cancelled."""
    approval = approvals.cancel_approval(
        db, principal.org_id, approval_id, actor_type=principal.actor_type, actor_id=principal.actor_id,
        reason=body.reason if body else None, bound_agent_id=principal.bound_agent_id,
    )
    db.commit()
    return ApprovalPollOut(approval_id=approval.id, status=approval.status, decided_at=approval.decided_at,
                           decision_note=approval.decision_note, expires_at=approval.expires_at)


@router.post("/scan", response_model=ScanOut)
def scan(body: ScanIn, principal: Principal = READ) -> ScanOut:
    """Run secret and prompt-injection detection on content without storing anything."""
    result = ingestion_queries.scan_content(
        body.content, source_type=body.source_type.value if body.source_type else None, content_type=body.content_type
    )
    return ScanOut.model_validate(result)


@router.get("/events", response_model=Page[IngestedEventOut])
def list_events(
    agent_id: str | None = None,
    session_id: str | None = Query(default=None, description="Server session id or the integration's session id"),
    event_type: EventType | None = None,
    since: datetime | None = Query(default=None, description="Only events received at or after this time"),
    processing_status: str | None = Query(default=None, pattern="^(processed|error)$"),
    is_simulation: bool | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> Page[IngestedEventOut]:
    items, total = ingestion_queries.list_events(
        db, principal.org_id, bound_agent_id=principal.bound_agent_id, agent_id=agent_id, session_id=session_id,
        event_type=event_type.value if event_type else None, since=since, processing_status=processing_status,
        is_simulation=is_simulation, limit=limit, offset=offset,
    )
    return Page[IngestedEventOut](items=[IngestedEventOut.model_validate(i) for i in items], total=total,
                                  limit=limit, offset=offset)


@router.get("/events/{event_id}", response_model=IngestedEventDetailOut)
def get_event(event_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> IngestedEventDetailOut:
    return IngestedEventDetailOut.model_validate(
        ingestion_queries.get_event(db, principal.org_id, event_id, bound_agent_id=principal.bound_agent_id)
    )


async def live_messages(
    org_id: str, is_disconnected: Callable[[], Awaitable[bool]], *, idle_check_s: float = PING_SECONDS
) -> AsyncIterator[dict[str, Any]]:
    """SSE payloads for one subscriber: ``stream.connected`` first, then bus notifications (ids only)."""
    queue = bus.subscribe(org_id)
    try:
        yield {"data": json.dumps({"type": "stream.connected"})}
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=idle_check_s)
            except TimeoutError:
                if await is_disconnected():
                    return
                continue
            yield {"data": json.dumps(message, default=str)}
    finally:
        bus.unsubscribe(org_id, queue)


@router.get("/stream")
async def stream(request: Request, principal: Principal = READ, db: Session = Depends(get_db)) -> EventSourceResponse:
    """Server-Sent Events: small notifications ({"type", "id", ...}); clients refetch details."""
    org_id = principal.org_id
    await run_in_threadpool(db.commit)  # end the auth transaction; the stream holds no DB connection
    return EventSourceResponse(
        live_messages(org_id, request.is_disconnected),
        ping=PING_SECONDS,
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
