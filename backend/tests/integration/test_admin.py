"""Organisation administration: settings, members/roles, API keys, permissions and tenant isolation."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app import models
from app.core.ids import new_id
from app.core.security import hash_token
from app.services.auth_service import login_limiter

CSRF = {"X-Requested-With": "contextos"}
MEMBER_PASSWORD = "member-password-123"


@pytest.fixture(autouse=True)
def _reset_limiter():
    login_limiter.clear()
    yield
    login_limiter.clear()


def _bearer(client, email: str, password: str) -> dict[str, str]:
    """Sign in through the API and return bearer headers for that session."""
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    token = res.cookies.get("contextos_session") or next(iter(res.cookies.values()))
    client.cookies.clear()
    return {"Authorization": f"Bearer {token}", **CSRF}


def _members(client, headers) -> dict[str, dict]:
    res = client.get("/api/v1/org/members", headers=headers)
    assert res.status_code == 200, res.text
    return {m["email"]: m for m in res.json()["items"]}


def _add_member(client, headers, email: str, role: str, password: str = MEMBER_PASSWORD) -> dict:
    res = client.post(
        "/api/v1/org/members",
        headers=headers,
        json={"email": email, "name": email.split("@")[0], "role": role, "password": password},
    )
    assert res.status_code == 201, res.text
    return res.json()


def _audit(db, org_id: str, action: str) -> list[models.AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(
            select(models.AuditEvent).where(
                models.AuditEvent.organization_id == org_id, models.AuditEvent.action == action
            )
        )
    )


# ----------------------------------------------------------------------------- organisation settings


def test_get_org_returns_defaults(client, org):
    res = client.get("/api/v1/org", headers=org.user_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == org.org_id
    assert body["settings"] == {
        "retention_days": 90,
        "fail_mode": "ask",
        "default_decision": "ALLOW",
        "approval_timeout_s": 600,
        "store_previews": True,
    }
    assert body["member_count"] == 1
    assert body["active_api_key_count"] == 1


def test_api_key_with_read_scope_can_read_org_but_not_members(client, org):
    assert client.get("/api/v1/org", headers=org.api_headers).status_code == 200
    assert client.get("/api/v1/org/members", headers=org.api_headers).status_code == 403
    assert client.get("/api/v1/org/api-keys", headers=org.api_headers).status_code == 403


def test_patch_settings_validates_and_audits(client, org, db):
    res = client.patch(
        "/api/v1/org/settings",
        headers=org.user_headers,
        json={
            "name": "Acme Security",
            "fail_mode": "closed",
            "default_decision": "AUDIT",
            "retention_days": 30,
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["name"] == "Acme Security"
    assert body["settings"]["fail_mode"] == "closed"
    assert body["settings"]["default_decision"] == "AUDIT"
    assert body["settings"]["retention_days"] == 30
    assert body["settings"]["approval_timeout_s"] == 600  # untouched

    entries = _audit(db, org.org_id, "organization.settings_updated")
    assert len(entries) == 1
    changes = entries[0].details["changes"]
    assert changes["fail_mode"] == {"from": "ask", "to": "closed"}
    assert changes["name"]["to"] == "Acme Security"
    assert "approval_timeout_s" not in changes

    # A no-op patch writes no audit entry.
    assert (
        client.patch(
            "/api/v1/org/settings", headers=org.user_headers, json={"fail_mode": "closed"}
        ).status_code
        == 200
    )
    assert len(_audit(db, org.org_id, "organization.settings_updated")) == 1


def test_patch_settings_preserves_unknown_stored_keys(client, org, db):
    row = db.get(models.Organization, org.org_id)
    row.settings = {"integration_hint": "keep-me"}
    db.commit()
    assert (
        client.patch(
            "/api/v1/org/settings", headers=org.user_headers, json={"store_previews": False}
        ).status_code
        == 200
    )
    db.expire_all()
    stored = db.get(models.Organization, org.org_id).settings
    assert stored["integration_hint"] == "keep-me"
    assert stored["store_previews"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"fail_mode": "maybe"},
        {"default_decision": "DENY"},
        {"retention_days": 0},
        {"approval_timeout_s": 5},
        {"secret_key": "x"},
        {"name": "   "},
    ],
)
def test_patch_settings_rejects_invalid_values(client, org, body):
    assert client.patch("/api/v1/org/settings", headers=org.user_headers, json=body).status_code == 422


# ----------------------------------------------------------------------------- permissions matrix


@pytest.mark.parametrize("role", ["viewer", "developer", "security_analyst"])
def test_non_admin_roles_cannot_administer(client, make_org, role):
    ctx = make_org(f"Team {role}", role=role)
    h = ctx.user_headers
    assert client.get("/api/v1/org", headers=h).status_code == 200
    assert client.get("/api/v1/org/members", headers=h).status_code == 200  # assignee pickers
    assert client.patch("/api/v1/org/settings", headers=h, json={"retention_days": 7}).status_code == 403
    assert (
        client.post(
            "/api/v1/org/members",
            headers=h,
            json={"email": "x@y.test", "name": "X", "role": "viewer", "password": "0123456789"},
        ).status_code
        == 403
    )
    assert client.get("/api/v1/org/api-keys", headers=h).status_code == 403
    assert (
        client.post("/api/v1/org/api-keys", headers=h, json={"name": "k", "scopes": ["ingest"]}).status_code
        == 403
    )
    assert client.delete(f"/api/v1/org/api-keys/{ctx.api_key_id}", headers=h).status_code == 403


def test_admin_role_can_administer(client, make_org):
    ctx = make_org("Admins", role="admin")
    h = ctx.user_headers
    assert client.patch("/api/v1/org/settings", headers=h, json={"retention_days": 7}).status_code == 200
    assert client.get("/api/v1/org/api-keys", headers=h).status_code == 200
    assert (
        client.post("/api/v1/org/api-keys", headers=h, json={"name": "k", "scopes": ["ingest"]}).status_code
        == 201
    )


# ----------------------------------------------------------------------------- members


def test_add_member_creates_user_who_can_sign_in(client, org, db):
    added = _add_member(client, org.user_headers, "Dev@Acme.test", "developer")
    assert added["email"] == "dev@acme.test"
    assert added["role"] == "developer"
    assert added["last_login_at"] is None
    assert "password" not in added and "password_hash" not in added

    headers = _bearer(client, "dev@acme.test", "member-password-123")
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["organization"]["id"] == org.org_id and me["role"] == "developer"

    listed = _members(client, org.user_headers)
    assert listed["dev@acme.test"]["last_login_at"] is not None
    assert _audit(db, org.org_id, "member.added")[0].details["role"] == "developer"


def test_add_member_validation(client, org):
    no_password = client.post(
        "/api/v1/org/members",
        headers=org.user_headers,
        json={"email": "new@acme.test", "name": "New", "role": "viewer"},
    )
    assert no_password.status_code == 422
    short = client.post(
        "/api/v1/org/members",
        headers=org.user_headers,
        json={"email": "new@acme.test", "name": "New", "role": "viewer", "password": "short"},
    )
    assert short.status_code == 422
    bad_role = client.post(
        "/api/v1/org/members",
        headers=org.user_headers,
        json={"email": "new@acme.test", "name": "New", "role": "superuser", "password": "0123456789"},
    )
    assert bad_role.status_code == 422
    duplicate = client.post(
        "/api/v1/org/members",
        headers=org.user_headers,
        json={"email": org.email, "name": "Me", "role": "viewer"},
    )
    assert duplicate.status_code == 409


def test_adding_existing_user_never_changes_their_password(client, org, other_org):
    res = client.post(
        "/api/v1/org/members",
        headers=other_org.user_headers,
        json={
            "email": org.email,
            "name": "Renamed",
            "role": "viewer",
            "password": "attacker-chosen-password",
        },
    )
    assert res.status_code == 201
    assert res.json()["name"] != "Renamed"
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": org.email, "password": "attacker-chosen-password"}
        ).status_code
        == 401
    )
    assert (
        client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password}).status_code
        == 200
    )


def test_change_role_and_remove_member(client, org, db):
    member = _add_member(client, org.user_headers, "analyst@acme.test", "viewer")
    res = client.patch(
        f"/api/v1/org/members/{member['id']}", headers=org.user_headers, json={"role": "security_analyst"}
    )
    assert res.status_code == 200 and res.json()["role"] == "security_analyst"
    entry = _audit(db, org.org_id, "member.role_changed")[0]
    assert entry.details == {"user_id": member["user_id"], "from": "viewer", "to": "security_analyst"}

    assert client.delete(f"/api/v1/org/members/{member['id']}", headers=org.user_headers).status_code == 204
    assert "analyst@acme.test" not in _members(client, org.user_headers)
    assert _audit(db, org.org_id, "member.removed")
    # The removed user can still authenticate but has no access to the organisation.
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "analyst@acme.test", "password": "member-password-123"}
        ).status_code
        == 403
    )


def test_last_owner_is_protected(client, org):
    owner = _members(client, org.user_headers)[org.email]
    demote = client.patch(
        f"/api/v1/org/members/{owner['id']}", headers=org.user_headers, json={"role": "admin"}
    )
    assert demote.status_code == 409
    assert "last owner" in demote.json()["error"]["message"]
    remove_self = client.delete(f"/api/v1/org/members/{owner['id']}", headers=org.user_headers)
    assert remove_self.status_code == 409


def test_owner_role_changes_require_an_owner(client, org):
    admin = _add_member(client, org.user_headers, "admin@acme.test", "admin")
    admin_h = _bearer(client, "admin@acme.test", "member-password-123")
    owner = _members(client, org.user_headers)[org.email]

    assert (
        client.patch(
            f"/api/v1/org/members/{owner['id']}", headers=admin_h, json={"role": "viewer"}
        ).status_code
        == 403
    )
    assert client.delete(f"/api/v1/org/members/{owner['id']}", headers=admin_h).status_code == 403
    assert (
        client.patch(
            f"/api/v1/org/members/{admin['id']}", headers=admin_h, json={"role": "owner"}
        ).status_code
        == 403
    )
    add_owner = client.post(
        "/api/v1/org/members",
        headers=admin_h,
        json={"email": "o2@acme.test", "name": "O2", "role": "owner", "password": "0123456789"},
    )
    assert add_owner.status_code == 403
    assert (
        client.delete(f"/api/v1/org/members/{admin['id']}", headers=admin_h).status_code == 409
    )  # not yourself

    # An owner can promote; with two owners, one may step down; the remaining one may not.
    assert (
        client.patch(
            f"/api/v1/org/members/{admin['id']}", headers=org.user_headers, json={"role": "owner"}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/org/members/{owner['id']}", headers=org.user_headers, json={"role": "admin"}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/org/members/{admin['id']}", headers=admin_h, json={"role": "admin"}
        ).status_code
        == 409
    )


# ----------------------------------------------------------------------------- API keys


def test_api_key_create_use_revoke(client, org, db):
    res = client.post(
        "/api/v1/org/api-keys",
        headers=org.user_headers,
        json={"name": "Reader", "scopes": ["read", "read"], "expires_in_days": 30},
    )
    assert res.status_code == 201, res.text
    created = res.json()
    raw = created["key"]
    assert raw.startswith("ctxk_") and created["prefix"] == raw[: len(created["prefix"])]
    assert created["scopes"] == ["read"]
    assert created["status"] == "active" and created["expires_at"] is not None
    assert created["created_by_user_id"] == org.user_id

    row = db.get(models.ApiKey, created["id"])
    assert row.key_hash == hash_token(raw)

    listing = client.get("/api/v1/org/api-keys", headers=org.user_headers)
    assert listing.status_code == 200
    text = listing.text
    assert raw not in text and row.key_hash not in text and "key_hash" not in text
    assert "key" not in listing.json()["items"][0]

    use = {"Authorization": f"Bearer {raw}"}
    assert client.get("/api/v1/org", headers=use).status_code == 200
    # A read-only key has no admin rights.
    assert client.patch("/api/v1/org/settings", headers=use, json={"retention_days": 1}).status_code == 403

    assert client.delete(f"/api/v1/org/api-keys/{created['id']}", headers=org.user_headers).status_code == 204
    revoked = client.get("/api/v1/org", headers=use)
    assert revoked.status_code == 401
    statuses = {
        k["id"]: k["status"]
        for k in client.get("/api/v1/org/api-keys", headers=org.user_headers).json()["items"]
    }
    assert statuses[created["id"]] == "revoked"
    assert _audit(db, org.org_id, "api_key.created") and _audit(db, org.org_id, "api_key.revoked")
    assert raw not in str([e.details for e in _audit(db, org.org_id, "api_key.created")])


def test_api_key_scope_validation(client, org):
    for body in (
        {"name": "k", "scopes": []},
        {"name": "k", "scopes": ["admin"]},
        {"name": "k", "scopes": ["ingest"], "expires_in_days": 0},
    ):
        assert client.post("/api/v1/org/api-keys", headers=org.user_headers, json=body).status_code == 422


def test_api_key_bound_to_agent(client, org, other_org, db):
    agent = models.Agent(id=new_id("agent"), organization_id=org.org_id, name="claude-code-laptop")
    foreign = models.Agent(id=new_id("agent"), organization_id=other_org.org_id, name="globex-bot")
    db.add_all([agent, foreign])
    db.commit()

    res = client.post(
        "/api/v1/org/api-keys",
        headers=org.user_headers,
        json={"name": "bound", "scopes": ["ingest", "decide"], "agent_id": agent.id},
    )
    assert res.status_code == 201
    assert res.json()["agent_id"] == agent.id and res.json()["agent_name"] == "claude-code-laptop"
    db.expire_all()
    assert db.get(models.ApiKey, res.json()["id"]).agent_id == agent.id
    listed = {
        k["id"]: k for k in client.get("/api/v1/org/api-keys", headers=org.user_headers).json()["items"]
    }
    assert listed[res.json()["id"]]["agent_name"] == "claude-code-laptop"

    # Another organisation's agent is invisible (404), not "forbidden".
    cross = client.post(
        "/api/v1/org/api-keys",
        headers=org.user_headers,
        json={"name": "x", "scopes": ["ingest"], "agent_id": foreign.id},
    )
    assert cross.status_code == 404


# ----------------------------------------------------------------------------- tenant isolation


def test_cross_org_isolation(client, org, other_org):
    member = _add_member(client, org.user_headers, "private@acme.test", "viewer")

    theirs = _members(client, other_org.user_headers)
    assert "private@acme.test" not in theirs and org.email not in theirs
    their_keys = {
        k["id"] for k in client.get("/api/v1/org/api-keys", headers=other_org.user_headers).json()["items"]
    }
    assert org.api_key_id not in their_keys

    assert (
        client.patch(
            f"/api/v1/org/members/{member['id']}", headers=other_org.user_headers, json={"role": "admin"}
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/api/v1/org/members/{member['id']}", headers=other_org.user_headers).status_code
        == 404
    )
    assert (
        client.delete(f"/api/v1/org/api-keys/{org.api_key_id}", headers=other_org.user_headers).status_code
        == 404
    )
    # org's key still works.
    assert client.get("/api/v1/org", headers=org.api_headers).json()["id"] == org.org_id
    assert client.get("/api/v1/org", headers=other_org.user_headers).json()["id"] == other_org.org_id
