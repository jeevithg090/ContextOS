"""Size limits on the integration endpoints: ``max_event_bytes`` per event on POST /events and
POST /decide (with or without a Content-Length header) and 4x that for a whole request body."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.models import IngestedEvent
from tests.integration.ingestion_support import event, tool_requested

LIMIT = 4_000


@pytest.fixture()
def small_limit(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_event_bytes", LIMIT)
    return LIMIT


def _big_request(size: int) -> dict:
    return tool_requested("Bash", {"command": "echo " + "a" * size})


def test_events_rejects_an_oversized_event_but_keeps_the_rest_of_the_batch(client, seeded_org, small_limit, db):
    small = event("session.started")
    big = event("context.ingested", source={"type": "file", "identifier": "/work/big.txt"}, content="b" * (LIMIT + 10))
    response = client.post("/api/v1/events", json={"events": [small, big]}, headers=seeded_org.api_headers)
    assert response.status_code == 200, response.text
    by_id = {r["event_id"]: r for r in response.json()["results"]}
    assert by_id[small["event_id"]]["status"] == "accepted"
    assert by_id[big["event_id"]]["status"] == "rejected"
    assert f"{LIMIT}-byte limit" in by_id[big["event_id"]]["error"]
    db.rollback()
    assert db.scalar(select(func.count()).select_from(IngestedEvent)) == 1  # the oversized event was not stored


def test_request_body_over_four_times_the_limit_is_413_before_authentication(client, small_limit):
    body = json.dumps({"events": [event("context.ingested", content="c" * (4 * LIMIT + 1))]})
    for path in ("/api/v1/events", "/api/v1/decide"):
        response = client.post(path, content=body, headers={"Content-Type": "application/json"})
        assert response.status_code == 413, path
        assert response.json()["error"]["code"] == "payload_too_large"


def test_decide_rejects_an_oversized_event_with_413(client, seeded_org, small_limit, db):
    response = client.post("/api/v1/decide", json=_big_request(LIMIT + 10), headers=seeded_org.api_headers)
    assert response.status_code == 413, response.text
    assert response.json()["error"]["code"] == "payload_too_large"
    db.rollback()
    assert db.scalar(select(func.count()).select_from(IngestedEvent)) == 0


def test_decide_without_content_length_is_still_limited(client, seeded_org, small_limit):
    """A chunked body carries no Content-Length, so the header check alone would let it through."""
    raw = json.dumps(_big_request(LIMIT + 10)).encode()

    def chunks():
        for i in range(0, len(raw), 1024):
            yield raw[i:i + 1024]

    response = client.post("/api/v1/decide", content=chunks(),
                           headers={**seeded_org.api_headers, "Content-Type": "application/json"})
    assert "content-length" not in {k.lower() for k in response.request.headers}
    assert response.status_code == 413, response.text


def test_decide_just_under_the_limit_is_decided(client, seeded_org, small_limit):
    response = client.post("/api/v1/decide", json=_big_request(LIMIT // 2), headers=seeded_org.api_headers)
    assert response.status_code == 200, response.text
    assert response.json()["decision"] in ("ALLOW", "AUDIT")
