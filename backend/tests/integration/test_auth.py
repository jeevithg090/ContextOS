"""Authentication: first-run setup, login/logout, /me, CSRF on cookie sessions, brute-force limiting."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app import models
from app.core.config import get_settings
from app.services.auth_service import LoginRateLimiter, login_limiter

SETUP = {
    "organization_name": "Acme AI",
    "name": "Ada Owner",
    "email": "Ada@Acme.test",
    "password": "a-long-enough-password",
}


@pytest.fixture(autouse=True)
def _reset_limiter():
    login_limiter.clear()
    yield
    login_limiter.clear()


def _audit_actions(db, org_id: str) -> list[str]:
    db.expire_all()
    return list(db.scalars(select(models.AuditEvent.action).where(models.AuditEvent.organization_id == org_id)))


def _cookie_name() -> str:
    return get_settings().session_cookie_name


# ----------------------------------------------------------------------------- setup


def test_setup_creates_org_owner_and_signs_in(client, db):
    assert client.get("/api/v1/auth/setup-status").json() == {"needs_setup": True}

    res = client.post("/api/v1/auth/setup", json=SETUP)
    assert res.status_code == 201, res.text
    me = res.json()
    assert me["user"]["email"] == "ada@acme.test"  # normalised
    assert me["organization"]["name"] == "Acme AI"
    assert me["organization"]["slug"] == "acme-ai"
    assert me["role"] == "owner"
    assert "admin" in me["permissions"] and "policy:manage" in me["permissions"]
    assert me["memberships"] == [{"organization_id": me["organization"]["id"], "organization_name": "Acme AI", "role": "owner"}]

    cookie = res.headers["set-cookie"]
    assert f"{_cookie_name()}=ctxs_" in cookie
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower() and "Path=/" in cookie
    assert f"Max-Age={get_settings().session_ttl_hours * 3600}" in cookie

    # Cookie session works for /me without any other header.
    assert client.get("/api/v1/auth/me").json()["user"]["id"] == me["user"]["id"]
    assert client.get("/api/v1/auth/setup-status").json() == {"needs_setup": False}

    org_id = me["organization"]["id"]
    org = db.get(models.Organization, org_id)
    assert org.settings["fail_mode"] == "ask"
    policies = db.scalar(select(func.count()).select_from(models.SecurityPolicy).where(models.SecurityPolicy.organization_id == org_id))
    assert policies > 0, "built-in policy pack should be seeded"
    user = db.get(models.User, me["user"]["id"])
    assert user.password_hash.startswith("scrypt$") and SETUP["password"] not in user.password_hash
    actions = _audit_actions(db, org_id)
    assert {"organization.created", "organization.defaults_seeded", "auth.setup_completed"} <= set(actions)


def test_setup_only_once(client):
    assert client.post("/api/v1/auth/setup", json=SETUP).status_code == 201
    again = client.post("/api/v1/auth/setup", json={**SETUP, "email": "mallory@evil.test"})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "conflict"


def test_setup_refused_when_users_exist(client, org):
    assert client.get("/api/v1/auth/setup-status").json() == {"needs_setup": False}
    assert client.post("/api/v1/auth/setup", json=SETUP).status_code == 409


@pytest.mark.parametrize(
    "patch",
    [{"password": "short"}, {"email": "not-an-email"}, {"organization_name": "   "}, {"role": "owner"}],
)
def test_setup_validation(client, patch):
    res = client.post("/api/v1/auth/setup", json={**SETUP, **patch})
    assert res.status_code == 422
    assert client.get("/api/v1/auth/setup-status").json() == {"needs_setup": True}


# ----------------------------------------------------------------------------- login / logout / me


def test_login_sets_cookie_and_returns_me(client, org, db):
    res = client.post("/api/v1/auth/login", json={"email": org.email.upper(), "password": org.password})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["user"]["id"] == org.user_id
    assert body["organization"]["id"] == org.org_id
    assert body["role"] == "owner"
    assert _cookie_name() in res.cookies
    db.expire_all()
    assert db.get(models.User, org.user_id).last_login_at is not None
    assert "auth.login" in _audit_actions(db, org.org_id)


def test_login_errors_are_uniform(client, org, db):
    wrong_password = client.post("/api/v1/auth/login", json={"email": org.email, "password": "nope-nope-nope"})
    unknown_email = client.post("/api/v1/auth/login", json={"email": "nobody@nowhere.test", "password": "nope-nope-nope"})
    malformed = client.post("/api/v1/auth/login", json={"email": "not an email", "password": "x"})
    for res in (wrong_password, unknown_email, malformed):
        assert res.status_code == 401
        assert res.json()["error"] == {"code": "unauthenticated", "message": "Invalid email or password", "details": None}
        assert "set-cookie" not in res.headers
    # The failure against a real account is audited (and survives the request rollback).
    assert _audit_actions(db, org.org_id).count("auth.login_failed") == 1


def test_inactive_user_cannot_login(client, org, db):
    user = db.get(models.User, org.user_id)
    user.is_active = False
    db.commit()
    res = client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password})
    assert res.status_code == 401
    assert res.json()["error"]["message"] == "Invalid email or password"


def test_cookie_session_requires_csrf_header_on_unsafe_requests(client, org):
    assert client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password}).status_code == 200
    # Safe request: cookie alone is enough.
    assert client.get("/api/v1/org").status_code == 200
    # Unsafe request with the cookie but without the CSRF header is refused.
    res = client.patch("/api/v1/org/settings", json={"retention_days": 30})
    assert res.status_code == 403
    assert "CSRF" in res.json()["error"]["message"]
    ok = client.patch("/api/v1/org/settings", json={"retention_days": 30}, headers={"X-Requested-With": "contextos"})
    assert ok.status_code == 200
    # Logout is also an unsafe cookie request.
    assert client.post("/api/v1/auth/logout").status_code == 403


def test_logout_revokes_session_and_clears_cookie(client, org, db):
    res = client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password})
    token = res.cookies[_cookie_name()]
    out = client.post("/api/v1/auth/logout", headers={"X-Requested-With": "contextos"})
    assert out.status_code == 204
    assert f'{_cookie_name()}=""' in out.headers["set-cookie"] or "Max-Age=0" in out.headers["set-cookie"]
    # The token is revoked server-side, not just forgotten by the browser.
    client.cookies.clear()
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert "auth.logout" in _audit_actions(db, org.org_id)
    # Idempotent without a session.
    assert client.post("/api/v1/auth/logout").status_code == 204


def test_me_requires_authentication(client):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "unauthenticated"


def test_me_rejects_api_keys(client, org):
    assert client.get("/api/v1/auth/me", headers=org.api_headers).status_code == 403


def test_me_honours_org_header_for_multi_org_users(client, org, other_org):
    # other_org's owner adds org's owner (an existing user) to their organisation.
    res = client.post(
        "/api/v1/org/members", headers=other_org.user_headers, json={"email": org.email, "name": "ignored", "role": "viewer"}
    )
    assert res.status_code == 201, res.text

    default = client.get("/api/v1/auth/me", headers=org.user_headers).json()
    assert default["organization"]["id"] == org.org_id and default["role"] == "owner"
    assert {m["organization_id"] for m in default["memberships"]} == {org.org_id, other_org.org_id}

    switched = client.get("/api/v1/auth/me", headers={**org.user_headers, "X-ContextOS-Org": other_org.org_id}).json()
    assert switched["organization"]["id"] == other_org.org_id
    assert switched["role"] == "viewer"
    assert "admin" not in switched["permissions"]

    # Cookie auth + org header works the same way.
    client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password})
    via_cookie = client.get("/api/v1/auth/me", headers={"X-ContextOS-Org": other_org.org_id}).json()
    assert via_cookie["organization"]["id"] == other_org.org_id

    stranger = client.get("/api/v1/auth/me", headers={**other_org.user_headers, "X-ContextOS-Org": org.org_id})
    assert stranger.status_code == 403


# ----------------------------------------------------------------------------- rate limiting


def test_login_rate_limited_after_five_failures(client, org):
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json={"email": org.email, "password": "wrong-password"}).status_code == 401
    blocked = client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password})
    assert blocked.status_code == 429
    error = blocked.json()["error"]
    assert error["code"] == "rate_limited"
    assert 0 < error["details"]["retry_after_s"] <= 300
    # Other accounts from the same client are unaffected.
    assert client.post("/api/v1/auth/login", json={"email": "someone@else.test", "password": "x"}).status_code == 401


def test_successful_login_resets_failure_count(client, org):
    for _ in range(4):
        client.post("/api/v1/auth/login", json={"email": org.email, "password": "wrong-password"})
    assert client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password}).status_code == 200
    for _ in range(4):
        assert client.post("/api/v1/auth/login", json={"email": org.email, "password": "wrong-password"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": org.email, "password": org.password}).status_code == 200


def test_rate_limiter_window_and_key_isolation():
    now = [1000.0]
    limiter = LoginRateLimiter(max_failures=3, window_s=60, clock=lambda: now[0])
    for _ in range(3):
        limiter.record_failure("a|1.1.1.1")
    assert limiter.retry_after("a|1.1.1.1") == 60
    assert limiter.retry_after("a|2.2.2.2") == 0  # different IP
    now[0] += 30
    assert limiter.retry_after("a|1.1.1.1") == 30
    now[0] += 31
    assert limiter.retry_after("a|1.1.1.1") == 0  # window passed


def test_rate_limiter_memory_is_bounded():
    limiter = LoginRateLimiter(max_failures=5, window_s=60, max_keys=10)
    for i in range(50):
        limiter.record_failure(f"user{i}|ip")
    assert len(limiter._failures) <= 10
