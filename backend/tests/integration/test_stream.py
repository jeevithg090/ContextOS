"""GET /stream (SSE): authorisation, per-org fan-out of committed notifications, unsubscribe.

TestClient buffers a response until it completes, so an endless SSE stream cannot be read through
it; the subscriber generator behind the endpoint is driven directly on a real event loop instead.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from starlette.requests import Request

from app.api.deps import Principal
from app.api.routes import events as events_route
from app.events.bus import bus
from app.events.envelope import EventEnvelope
from app.services.ingestion import IngestContext, ingest_batch
from tests.integration.ingestion_support import event


@pytest.fixture()
async def bound_bus():
    """Bind the global bus to the test's running loop, as the app lifespan does."""
    previous = bus._loop  # noqa: SLF001 - restored after the test
    bus.bind_loop(asyncio.get_running_loop())
    yield bus
    bus._loop = previous  # noqa: SLF001


def _ctx(org) -> IngestContext:
    return IngestContext(org_id=org.org_id, actor_type="api_key", actor_id=org.api_key_id, api_key_id=org.api_key_id)


def _ingest(db, org, content: str) -> None:
    ingest_batch(db, _ctx(org), [EventEnvelope.model_validate(event("prompt.submitted", content=content))])


async def _next(stream: AsyncIterator[dict[str, Any]], timeout: float = 2.0) -> dict[str, Any]:
    return json.loads((await asyncio.wait_for(anext(stream), timeout))["data"])


def _subscribers(org_id: str) -> int:
    return len(bus._subscribers.get(org_id, ()))  # noqa: SLF001


def test_stream_requires_read_permission(client, make_org):
    ingest_only = make_org("Initech", scopes=["ingest"])
    assert client.get("/api/v1/stream").status_code == 401
    response = client.get("/api/v1/stream", headers=ingest_only.api_headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_committed_notifications_reach_only_the_same_org(bound_bus, db, org, other_org):
    connected = {"value": False}

    async def is_disconnected() -> bool:
        return connected["value"]

    mine = events_route.live_messages(org.org_id, is_disconnected, idle_check_s=0.05)
    theirs = events_route.live_messages(other_org.org_id, is_disconnected, idle_check_s=0.05)
    assert await _next(mine) == {"type": "stream.connected"}
    assert await _next(theirs) == {"type": "stream.connected"}
    assert _subscribers(org.org_id) == 1 and _subscribers(other_org.org_id) == 1

    # Rolled-back work publishes nothing.
    _ingest(db, org, "This batch is rolled back.")
    db.rollback()
    with pytest.raises(TimeoutError):
        await _next(mine, timeout=0.3)
    mine = events_route.live_messages(org.org_id, is_disconnected, idle_check_s=0.05)
    assert await _next(mine) == {"type": "stream.connected"}

    _ingest(db, org, "Summarise the changelog for the release notes.")
    db.commit()
    received = [await _next(mine) for _ in range(3)]
    assert {m["type"] for m in received} == {"event.ingested", "session.updated", "agent.updated"}
    assert all(m["org_id"] == org.org_id and m["id"] for m in received)
    assert "changelog" not in json.dumps(received)  # ids only, never content
    ingested = next(m for m in received if m["type"] == "event.ingested")
    assert ingested["count"] == 1 and ingested["session_id"]

    with pytest.raises(TimeoutError):  # another organisation's subscriber sees nothing
        await _next(theirs, timeout=0.3)
    assert _subscribers(other_org.org_id) == 0  # a cancelled subscriber unsubscribes

    connected["value"] = True  # client went away: the generator ends at its next idle check
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(mine), 2.0)
    assert _subscribers(org.org_id) == 0


async def test_stream_endpoint_returns_an_sse_response(bound_bus, db, org):
    scope = {"type": "http", "method": "GET", "path": "/api/v1/stream", "headers": [], "query_string": b""}

    async def receive() -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    principal = Principal(org_id=org.org_id, kind="user", permissions={"read"}, user_id=org.user_id)
    response = await events_route.stream(Request(scope, receive), principal=principal, db=db)
    assert response.ping_interval == events_route.PING_SECONDS == 15
    assert response.headers["cache-control"] == "no-store"
    assert response.media_type == "text/event-stream"
    body = response.body_iterator
    assert json.loads((await anext(body))["data"]) == {"type": "stream.connected"}
    await body.aclose()
    assert _subscribers(org.org_id) == 0


def _session_principal(db, org) -> Principal:
    from sqlalchemy import select

    from app.core.security import hash_token
    from app.models import AuthSession

    auth = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(org.session_token)))
    return Principal(org_id=org.org_id, kind="user", permissions={"read"}, user_id=org.user_id, role="owner",
                     auth_session_id=auth.id)


async def _drain(stream: AsyncIterator[dict[str, Any]]) -> list[dict[str, Any]]:
    """Messages delivered until the stream ends (fails with TimeoutError if it does not end)."""
    delivered: list[dict[str, Any]] = []
    try:
        while True:
            delivered.append(json.loads((await asyncio.wait_for(anext(stream), 2.0))["data"]))
    except StopAsyncIteration:
        return delivered


@pytest.mark.parametrize("revoke", ["logout", "disable_user", "remove_membership"])
async def test_stream_ends_when_its_credential_stops_being_valid(bound_bus, db, org, revoke):
    from fastapi.concurrency import run_in_threadpool

    from app.api.deps import recheck_credential
    from app.core.timeutil import utcnow
    from app.models import AuthSession, Membership, User

    principal = _session_principal(db, org)

    async def still_authorized() -> bool:
        return await run_in_threadpool(recheck_credential, principal, "read")

    async def connected() -> bool:
        return False

    stream = events_route.live_messages(org.org_id, connected, idle_check_s=0.05, still_authorized=still_authorized)
    assert await _next(stream) == {"type": "stream.connected"}
    with pytest.raises(TimeoutError):  # still valid: the stream stays open
        await _next(stream, timeout=0.3)
    stream = events_route.live_messages(org.org_id, connected, idle_check_s=0.05, still_authorized=still_authorized)
    assert await _next(stream) == {"type": "stream.connected"}

    if revoke == "logout":
        db.get(AuthSession, principal.auth_session_id).revoked_at = utcnow()
    elif revoke == "disable_user":
        db.get(User, org.user_id).is_active = False
    else:
        for membership in db.query(Membership).filter(Membership.user_id == org.user_id):
            db.delete(membership)
    db.commit()
    assert await _drain(stream) == []
    assert _subscribers(org.org_id) == 0


async def test_stream_ends_when_its_api_key_is_revoked(bound_bus, db, org):
    from fastapi.concurrency import run_in_threadpool

    from app.api.deps import recheck_credential
    from app.core.timeutil import utcnow
    from app.models import ApiKey

    principal = Principal(org_id=org.org_id, kind="api_key", permissions={"read"}, api_key_id=org.api_key_id)

    async def still_authorized() -> bool:
        return await run_in_threadpool(recheck_credential, principal, "read")

    async def connected() -> bool:
        return False

    stream = events_route.live_messages(org.org_id, connected, idle_check_s=0.05, still_authorized=still_authorized)
    assert await _next(stream) == {"type": "stream.connected"}
    db.get(ApiKey, org.api_key_id).revoked_at = utcnow()
    db.commit()
    await asyncio.sleep(0.1)  # past the re-check interval: the next message triggers a re-check first
    _ingest(db, org, "A notification queued after revocation is never delivered.")
    db.commit()
    assert await _drain(stream) == []
