"""GET /audit, GET /audit/verify, GET /audit/export.

Entries are produced by real state changes (API-key management, enforced denials from the ingestion
pipeline) or by ``append_audit`` itself; tampering tests edit rows directly, as an attacker with
database write access but no server secret would.
"""

from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import select, update

from app.core.timeutil import isoformat, utcnow
from app.domain.enums import Role
from app.models import AuditEvent, Organization
from app.services.audit import append_audit
from tests.integration.agents_support import exfil_session
from tests.integration.ingestion_support import GITHUB_TOKEN

URL = "/api/v1/audit"


def _list(client, headers, **params):
    response = client.get(URL, headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _create_key(client, org, name="ci key"):
    response = client.post("/api/v1/org/api-keys", headers=org.user_headers,
                           json={"name": name, "scopes": ["ingest"]})
    assert response.status_code in (200, 201), response.text
    return response.json()


def _key_id(created):
    return created.get("id") or created["api_key"]["id"]


# ----------------------------------------------------------------------------- listing


def test_lists_newest_first_with_resolved_actors(client, org):
    first = _create_key(client, org, "first")
    second = _create_key(client, org, "second")
    body = _list(client, org.user_headers)
    assert body["total"] == 2 and body["limit"] == 50 and body["offset"] == 0
    newest, oldest = body["items"]
    assert newest["seq"] > oldest["seq"]
    assert newest["target_id"] == _key_id(second) and oldest["target_id"] == _key_id(first)
    assert newest["action"] == "api_key.created" and newest["target_type"] == "api_key"
    assert newest["actor_type"] == "user" and newest["actor_id"] == org.user_id
    assert newest["actor_label"] == "Acme Owner" and newest["actor_detail"] == org.email
    assert newest["prev_hash"] == oldest["hash"] and len(newest["hash"]) == 64
    assert newest["details"]["name"] == "second"


def test_filters(client, seeded_org):
    org = seeded_org
    created = _create_key(client, org)
    exfil_session(client, org.api_headers)  # the built-in pack denies the exfiltration -> tool.denied
    everything = _list(client, org.user_headers, limit=500)
    assert everything["total"] >= 3

    keys = _list(client, org.user_headers, action="api_key.")
    assert keys["total"] == 1 and keys["items"][0]["target_id"] == _key_id(created)

    denied = _list(client, org.user_headers, action="tool.denied")
    assert denied["total"] >= 1
    entry = denied["items"][0]
    assert entry["actor_type"] == "api_key" and entry["actor_id"] == org.api_key_id
    assert entry["actor_label"] == "test key" and entry["actor_detail"].endswith("…")
    assert entry["target_type"] == "tool_invocation" and entry["details"]["enforcement"] == "enforced"

    by_actor = _list(client, org.user_headers, actor_type="api_key", actor_id=org.api_key_id)
    assert by_actor["total"] >= 1 and {i["actor_id"] for i in by_actor["items"]} == {org.api_key_id}
    by_target = _list(client, org.user_headers, target_type="api_key", target_id=_key_id(created))
    assert [i["action"] for i in by_target["items"]] == ["api_key.created"]

    # LIKE wildcards are matched literally: "%" and "_" in a prefix never act as patterns.
    assert _list(client, org.user_headers, action="%")["total"] == 0
    assert _list(client, org.user_headers, action="api_key")["total"] == 1
    assert _list(client, org.user_headers, action="apixkey")["total"] == 0
    assert _list(client, org.user_headers, action="api%key")["total"] == 0


def test_time_window_and_pagination(client, org, db):
    for i in range(5):
        append_audit(db, org.org_id, action="test.event", details={"i": i})
    db.commit()
    old = db.scalar(select(AuditEvent).where(AuditEvent.organization_id == org.org_id, AuditEvent.seq == 1))
    old.occurred_at = utcnow() - timedelta(days=3)
    db.commit()
    since = isoformat(utcnow() - timedelta(days=1))
    assert _list(client, org.user_headers, since=since)["total"] == 4
    assert _list(client, org.user_headers, until=since)["total"] == 1
    page = _list(client, org.user_headers, limit=2, offset=2)
    assert page["total"] == 5 and [i["seq"] for i in page["items"]] == [3, 2]
    bad = client.get(URL, headers=org.user_headers, params={"since": isoformat(utcnow()), "until": since})
    assert bad.status_code == 422


def test_details_never_expose_secrets(client, org, db):
    append_audit(db, org.org_id, action="test.secret", details={"token": GITHUB_TOKEN, "note": f"saw {GITHUB_TOKEN}"})
    db.commit()
    raw = client.get(URL, headers=org.user_headers).text
    assert GITHUB_TOKEN not in raw and "[REDACTED" in raw


def test_api_key_callers_do_not_see_member_emails(client, org):
    _create_key(client, org)
    entry = _list(client, org.api_headers)["items"][0]
    assert entry["actor_label"] == "Acme Owner" and entry["actor_detail"] is None


# ----------------------------------------------------------------------------- verification


def test_verify_intact_chain(client, org):
    empty = client.get(f"{URL}/verify", headers=org.user_headers).json()
    assert empty["valid"] is True and empty["checked"] == 0 and "nothing to verify" in empty["summary"]
    _create_key(client, org)
    _create_key(client, org, "two")
    body = client.get(f"{URL}/verify", headers=org.user_headers).json()
    assert body["valid"] is True and body["checked"] == 2 and body["head_seq"] == 2
    assert body["first_invalid_seq"] is None and body["reason"] is None
    newest = _list(client, org.user_headers)["items"][0]
    assert body["head_hash"] == newest["hash"]
    model = body["threat_model"]
    assert any("server secret" in d for d in model["detects"])
    assert any("both database write access and the server secret" in d for d in model["does_not_protect_against"])
    assert "external" in model["anchoring"]


def _three_entries(db, org_id):
    for i in range(3):
        append_audit(db, org_id, action="test.event", details={"i": i})
    db.commit()


def test_verify_detects_modified_entry(client, org, db):
    _three_entries(db, org.org_id)
    db.execute(update(AuditEvent).where(AuditEvent.organization_id == org.org_id, AuditEvent.seq == 2)
               .values(details={"i": 99}))
    db.commit()
    body = client.get(f"{URL}/verify", headers=org.user_headers).json()
    assert body["valid"] is False and body["first_invalid_seq"] == 2
    assert "contents" in body["reason"] and "changed after it was written" in body["reason_explained"]
    entry = db.scalar(select(AuditEvent).where(AuditEvent.organization_id == org.org_id, AuditEvent.seq == 2))
    assert body["first_invalid_entry_id"] == entry.id
    assert "#2" in body["summary"]


def test_verify_detects_deleted_and_truncated_entries(client, org, db):
    _three_entries(db, org.org_id)
    db.query(AuditEvent).filter(AuditEvent.organization_id == org.org_id, AuditEvent.seq == 3).delete()
    db.commit()
    tail = client.get(f"{URL}/verify", headers=org.user_headers).json()
    assert tail["valid"] is False and "chain tail" in tail["reason"]
    assert "newest entries were deleted" in tail["reason_explained"]

    db.query(AuditEvent).filter(AuditEvent.organization_id == org.org_id, AuditEvent.seq == 1).delete()
    db.commit()
    gap = client.get(f"{URL}/verify", headers=org.user_headers).json()
    assert gap["valid"] is False and gap["first_invalid_seq"] == 2 and "sequence gap" in gap["reason"]


# ----------------------------------------------------------------------------- export


def test_export_is_admin_only_jsonl_and_audited(client, org):
    _create_key(client, org)
    response = client.get(f"{URL}/export", headers=org.user_headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in response.headers["content-disposition"]
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert [r["seq"] for r in lines] == [1, 2]
    assert lines[-1]["action"] == "audit.exported" and lines[-1]["actor_id"] == org.user_id
    assert lines[-1]["prev_hash"] == lines[0]["hash"]
    assert response.headers["x-contextos-audit-through-seq"] == "2"
    assert response.headers["x-contextos-audit-head-hash"] == lines[-1]["hash"]
    assert {r["org"] for r in lines} == {org.org_id}
    # The export is on the record and the chain is still intact.
    assert _list(client, org.user_headers, action="audit.exported")["total"] == 1
    assert client.get(f"{URL}/verify", headers=org.user_headers).json()["valid"] is True


def test_export_redacts_details(client, org, db):
    append_audit(db, org.org_id, action="test.secret", details={"note": f"saw {GITHUB_TOKEN}"})
    db.commit()
    response = client.get(f"{URL}/export", headers=org.user_headers)
    assert response.status_code == 200 and GITHUB_TOKEN not in response.text


def test_export_permissions(client, make_org):
    viewer = make_org("Viewer Co", role=Role.VIEWER)
    analyst = make_org("Analyst Co", role=Role.SECURITY_ANALYST)
    for ctx in (viewer, analyst):
        denied = client.get(f"{URL}/export", headers=ctx.user_headers)
        assert denied.status_code == 403 and denied.json()["error"]["code"] == "forbidden"
        assert client.get(f"{URL}/export", headers=ctx.api_headers).status_code == 403  # keys never have admin
        # Read access still lists and verifies.
        assert client.get(URL, headers=ctx.user_headers).status_code == 200
        assert client.get(f"{URL}/verify", headers=ctx.user_headers).status_code == 200
    assert client.get(URL).status_code == 401
    no_read = make_org("No read", scopes=["ingest"])
    assert client.get(URL, headers=no_read.api_headers).status_code == 403
    assert client.get(f"{URL}/verify", headers=no_read.api_headers).status_code == 403


# ----------------------------------------------------------------------------- isolation


def test_cross_org_isolation(client, org, other_org, db):
    created = _create_key(client, org)
    append_audit(db, other_org.org_id, action="test.other", details={})
    db.commit()
    theirs = _list(client, other_org.user_headers)
    assert [i["action"] for i in theirs["items"]] == ["test.other"]
    assert _list(client, other_org.user_headers, target_id=_key_id(created))["total"] == 0
    assert _list(client, other_org.user_headers, actor_id=org.user_id)["total"] == 0

    # Each organisation has an independent chain; tampering with one does not affect the other.
    db.execute(update(AuditEvent).where(AuditEvent.organization_id == org.org_id).values(action="tampered"))
    db.commit()
    assert client.get(f"{URL}/verify", headers=org.user_headers).json()["valid"] is False
    assert client.get(f"{URL}/verify", headers=other_org.user_headers).json()["valid"] is True

    exported = client.get(f"{URL}/export", headers=other_org.user_headers)
    assert {json.loads(line)["org"] for line in exported.text.splitlines()} == {other_org.org_id}
    other = db.get(Organization, other_org.org_id)
    db.refresh(other)
    assert exported.headers["x-contextos-audit-head-hash"] == other.audit_head_hash


def test_actor_from_another_org_is_not_resolved(client, org, other_org, db):
    # An entry naming a user who is not a member of this organisation shows only the id.
    append_audit(db, org.org_id, action="test.foreign_actor", actor_type="user", actor_id=other_org.user_id)
    db.commit()
    entry = _list(client, org.user_headers, action="test.foreign_actor")["items"][0]
    assert entry["actor_id"] == other_org.user_id
    assert entry["actor_label"] is None and entry["actor_detail"] is None
