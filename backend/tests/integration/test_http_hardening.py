"""HTTP-level hardening: body and nesting limits before authentication, the uniform error envelope for
framework errors, redacted validation echoes, security headers, cookie flags, session expiry,
password-spraying limits, production settings and the absence of server-side fetches (SSRF)."""

from __future__ import annotations

import json
import socket
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.middleware import API_CSP, MAX_JSON_DEPTH, SPA_CSP
from app.core.config import Settings, get_settings
from app.core.ids import new_id
from app.core.security import generate_session_token
from app.core.timeutil import utcnow
from app.models import AuthSession
from tests.integration.ingestion_support import event, tool_requested

API = "/api/v1"
LIMIT = 4_000


@pytest.fixture()
def small_limit(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_event_bytes", LIMIT)
    return LIMIT


def _nested(depth: int) -> object:
    value: object = "leaf"
    for _ in range(depth):
        value = {"a": value}
    return value


def _chunks(raw: bytes):
    for i in range(0, len(raw), 1024):
        yield raw[i:i + 1024]


# ----------------------------------------------------------------------------- body and nesting limits


def test_chunked_body_over_the_limit_is_413_before_authentication(client, small_limit):
    raw = json.dumps({"name": "x" * (4 * LIMIT + 10)}).encode()
    for method, path in (("POST", "/auth/login"), ("PATCH", "/org/settings"), ("POST", "/events")):
        response = client.request(method, API + path, content=_chunks(raw), headers={"Content-Type": "application/json"})
        assert "content-length" not in {k.lower() for k in response.request.headers}
        assert response.status_code == 413, (path, response.text)  # not 401: the body never reached the app
        assert response.json()["error"]["code"] == "payload_too_large"


def test_deeply_nested_json_is_422_not_a_server_error(client, seeded_org):
    for depth in (MAX_JSON_DEPTH + 1, 400, 900):
        body = tool_requested("Bash", {"command": "ls", "deep": _nested(depth)})
        response = client.post(f"{API}/decide", content=json.dumps(body),
                               headers={**seeded_org.api_headers, "Content-Type": "application/json"})
        assert response.status_code == 422, (depth, response.text)
        assert response.json()["error"] == {"code": "validation_failed", "details": {"max_depth": MAX_JSON_DEPTH},
                                             "message": f"Request body is nested more than {MAX_JSON_DEPTH} levels deep"}
    batch = {"events": [event("session.started", metadata={"deep": _nested(400)})]}
    response = client.post(f"{API}/events", json=batch, headers=seeded_org.api_headers)
    assert response.status_code == 422  # the SDK isolates a 422 event instead of retrying the batch forever


def test_nesting_within_the_limit_and_brackets_inside_strings_are_accepted(client, seeded_org):
    text = "[" * 500 + '\\"{{{' + "}" * 3  # brackets and escaped quotes inside a string do not count
    body = tool_requested("Bash", {"command": "echo ok", "deep": _nested(MAX_JSON_DEPTH - 8), "note": text})
    response = client.post(f"{API}/decide", json=body, headers=seeded_org.api_headers)
    assert response.status_code == 200, response.text


# ----------------------------------------------------------------------------- error envelope and echoes


def test_framework_errors_use_the_uniform_envelope(client, org):
    missing = client.get(f"{API}/no-such-route", headers=org.api_headers)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"
    wrong_method = client.delete(f"{API}/events", headers=org.api_headers)
    assert wrong_method.status_code == 405 and wrong_method.json()["error"]["code"] == "method_not_allowed"
    assert wrong_method.headers["allow"]  # the Allow header survives the envelope
    unparsable = client.post(f"{API}/auth/login", content=b"{not json", headers={"Content-Type": "application/json"})
    assert unparsable.status_code == 422 and unparsable.json()["error"]["code"] == "validation_failed"


def test_validation_errors_do_not_echo_secrets(client, org):
    token = "ghp_" + "Zq8RtY2uV4wX6yA1bC3dE5fG7hJ9kL0mN2pQ"
    smuggled = {**event("session.started"), token: "x"}
    response = client.post(f"{API}/events", json={"events": [smuggled]}, headers=org.api_headers)
    assert response.status_code == 422
    assert token not in response.text and "[REDACTED:github_token:" in response.text
    assert response.json()["error"]["details"][0]["type"] == "extra_forbidden"


# ----------------------------------------------------------------------------- headers


def test_api_responses_carry_security_headers(client, org):
    response = client.get(f"{API}/org", headers=org.api_headers)
    headers = response.headers
    assert headers["content-security-policy"] == API_CSP
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer" and "camera=()" in headers["permissions-policy"]
    assert "strict-transport-security" not in headers  # plain-HTTP development
    assert "content-security-policy" not in client.get("/api/docs").headers  # Swagger UI loads its own scripts


def test_spa_gets_a_same_origin_csp_and_hsts_when_cookies_are_secure(engine, tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>")
    settings = get_settings()
    monkeypatch.setattr(settings, "serve_frontend", True)
    monkeypatch.setattr(settings, "frontend_dist", str(dist))
    monkeypatch.setattr(settings, "cookie_secure", True)
    from app.main import create_app

    with TestClient(create_app()) as spa:
        page = spa.get("/incidents")
        assert page.status_code == 200 and page.headers["content-security-policy"] == SPA_CSP
        assert "script-src 'self'" in SPA_CSP and "unsafe-eval" not in SPA_CSP
        assert page.headers["strict-transport-security"].startswith("max-age=")


# ----------------------------------------------------------------------------- sessions and login


def test_session_cookie_is_secure_when_configured(client, org, monkeypatch):
    monkeypatch.setattr(get_settings(), "cookie_secure", True)
    response = client.post(f"{API}/auth/login", json={"email": org.email, "password": org.password})
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "samesite=lax" in cookie.lower()


def test_expired_or_revoked_sessions_are_rejected(client, org, db):
    token, token_hash = generate_session_token()
    db.add(AuthSession(id=new_id("auth_session"), user_id=org.user_id, token_hash=token_hash,
                       expires_at=utcnow() - timedelta(seconds=1)))
    db.commit()
    response = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401 and response.json()["error"]["code"] == "unauthenticated"


def test_password_spraying_from_one_address_is_limited(client, org):
    from app.services.auth_service import ip_login_limiter

    for i in range(ip_login_limiter.max_failures):  # one failure per account: the per-account limit never triggers
        response = client.post(f"{API}/auth/login", json={"email": f"user{i}@example.test", "password": "Winter2026!"})
        assert response.status_code == 401
    blocked = client.post(f"{API}/auth/login", json={"email": org.email, "password": org.password})
    assert blocked.status_code == 429 and blocked.json()["error"]["code"] == "rate_limited"


# ----------------------------------------------------------------------------- settings and CORS


def _production(**overrides) -> Settings:
    values = {"env": "production", "secret_key": "s" * 48, "cookie_secure": True,
              "cors_origins": ["https://contextos.example.com"], **overrides}
    return Settings(**values)


def test_production_refuses_insecure_settings():
    _production().validate_for_production()
    for overrides, needle in (({"cors_origins": ["*"]}, "CORS"), ({"cookie_secure": False}, "COOKIE_SECURE"),
                              ({"secret_key": "short"}, "SECRET_KEY"), ({"session_ttl_hours": 0}, "SESSION_TTL")):
        with pytest.raises(RuntimeError, match=needle):
            _production(**overrides).validate_for_production()


def test_wildcard_cors_never_allows_credentials(engine, monkeypatch):
    monkeypatch.setattr(get_settings(), "cors_origins", ["*"])
    from app.main import create_app

    with TestClient(create_app()) as anywhere:
        response = anywhere.options(f"{API}/org", headers={"Origin": "https://evil.example",
                                                           "Access-Control-Request-Method": "GET"})
        assert response.headers.get("access-control-allow-credentials") != "true"


# ----------------------------------------------------------------------------- SSRF


def test_destination_verification_never_opens_a_connection(client, seeded_org, monkeypatch):
    calls: list[str] = []

    def refuse(name):
        def _refuse(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"ContextOS must not open network connections ({name})")
        return _refuse

    monkeypatch.setattr(socket, "getaddrinfo", refuse("getaddrinfo"))
    monkeypatch.setattr(socket, "create_connection", refuse("create_connection"))
    monkeypatch.setattr(socket.socket, "connect", refuse("connect"))
    for kind, identifier in (("domain", "http://169.254.169.254/latest/meta-data/"), ("domain", "localhost:8000"),
                             ("ip", "10.0.0.1"), ("domain", "https://hooks.exfil.invalid/in"), ("email", "a@b.example")):
        response = client.post(f"{API}/trust/destinations/verify", json={"kind": kind, "identifier": identifier},
                               headers=seeded_org.user_headers)
        assert response.status_code == 200, (identifier, response.text)
    assert calls == []
