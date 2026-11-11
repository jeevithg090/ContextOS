"""Simulation-only sources and destinations stay out of the Trust Centre and Context Explorer.

``ContextSource.is_simulation`` is set when Simulation Lab traffic creates a source, cleared the
first time real traffic observes it and never set back. Destinations are simulation-only while every
recorded call to them was simulated. ``include_simulated=true`` brings them back.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.envelope import EventEnvelope
from app.models import ContextSource
from app.services.ingestion import IngestContext, decide_tool_request, ingest_event
from tests.integration.ingestion_support import decide, event, post_events, tool_requested

PAGE = {"type": "web", "identifier": "https://sim-only.example.net/pricing"}
WEBHOOK = {"url": "https://collector.example.org/hook", "method": "POST", "body": "status=ok"}


def _sim(org_id: str) -> IngestContext:
    return IngestContext(org_id=org_id, actor_type="system", is_simulation=True)


def _simulated_page(db: Session, org_id: str, session: str = "sim-1") -> str:
    envelope = EventEnvelope.model_validate(event(
        "context.ingested", agent="sim-agent", session=session, source=PAGE, content="Simulated pricing page."))
    result = ingest_event(db, _sim(org_id), envelope)
    db.commit()
    return result.refs["source_id"]


def _ids(client, path: str, headers, **params) -> list[str]:
    response = client.get(f"/api/v1{path}", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return [i["id"] for i in response.json()["items"]]


def _source(db: Session, source_id: str) -> ContextSource:
    db.rollback()
    return db.scalar(select(ContextSource).where(ContextSource.id == source_id))


def test_simulation_only_source_is_hidden_until_real_traffic_observes_it(client, seeded_org, db):
    h = seeded_org.user_headers
    source_id = _simulated_page(db, seeded_org.org_id)
    assert _source(db, source_id).is_simulation is True

    for path in ("/trust/sources", "/context/sources"):
        assert source_id not in _ids(client, path, h), path
        included = client.get(f"/api/v1{path}", headers=h, params={"include_simulated": "true"}).json()["items"]
        entry = next(i for i in included if i["id"] == source_id)
        assert entry["is_simulation"] is True, path
    assert client.get("/api/v1/trust/summary", headers=h).json()["sources"]["total"] == 0
    assert client.get("/api/v1/trust/summary", headers=h,
                      params={"include_simulated": "true"}).json()["sources"]["total"] == 1
    # Still reachable by id (e.g. from a simulated item).
    assert client.get(f"/api/v1/trust/sources/{source_id}", headers=h).status_code == 200
    assert client.get(f"/api/v1/context/sources/{source_id}", headers=h).status_code == 200

    real = post_events(client, seeded_org.api_headers, event(
        "context.ingested", agent="researcher", session="real-1", source=PAGE, content="The real pricing page."))[0]
    assert real["refs"]["source_id"] == source_id
    assert _source(db, source_id).is_simulation is False
    for path in ("/trust/sources", "/context/sources"):
        assert source_id in _ids(client, path, h), path
    assert client.get("/api/v1/trust/summary", headers=h).json()["sources"]["total"] == 1

    # Later simulations never flip it back.
    _simulated_page(db, seeded_org.org_id, session="sim-2")
    assert _source(db, source_id).is_simulation is False
    assert source_id in _ids(client, "/trust/sources", h)


def test_source_first_seen_by_real_traffic_is_never_simulation_only(client, seeded_org, db):
    real = post_events(client, seeded_org.api_headers, event(
        "context.ingested", agent="researcher", session="real-1", source=PAGE, content="Real page."))[0]
    source_id = real["refs"]["source_id"]
    _simulated_page(db, seeded_org.org_id)
    assert _source(db, source_id).is_simulation is False
    assert source_id in _ids(client, "/trust/sources", seeded_org.user_headers)


def test_simulation_only_destination_is_hidden_from_trust_lists(client, seeded_org, db):
    h = seeded_org.user_headers
    envelope = EventEnvelope.model_validate(tool_requested("WebFetch", WEBHOOK, agent="sim-agent", session="sim-1"))
    simulated = decide_tool_request(db, _sim(seeded_org.org_id), envelope)
    db.commit()
    dest_id = next(iter(client.get("/api/v1/trust/destinations", headers=h,
                                   params={"include_simulated": "true"}).json()["items"]))["id"]
    assert simulated.policy_decision_id
    assert _ids(client, "/trust/destinations", h) == []
    included = client.get("/api/v1/trust/destinations", headers=h, params={"include_simulated": "true"}).json()
    assert included["items"][0]["is_simulation"] is True
    assert client.get("/api/v1/trust/summary", headers=h).json()["destinations"]["total"] == 0
    assert client.get(f"/api/v1/trust/destinations/{dest_id}", headers=h).json()["is_simulation"] is True

    decide(client, seeded_org.api_headers, tool_requested("WebFetch", WEBHOOK, agent="coder", session="real-1"))
    listed = client.get("/api/v1/trust/destinations", headers=h).json()["items"]
    assert [d["id"] for d in listed] == [dest_id] and listed[0]["is_simulation"] is False
    assert client.get("/api/v1/trust/summary", headers=h).json()["destinations"]["total"] == 1


def test_other_org_never_sees_simulated_sources(client, seeded_org, other_org, db):
    source_id = _simulated_page(db, seeded_org.org_id)
    for path in ("/trust/sources", "/context/sources"):
        assert _ids(client, path, other_org.user_headers, include_simulated="true") == []
    assert client.get(f"/api/v1/trust/sources/{source_id}", headers=other_org.user_headers).status_code == 404
