"""ContextOSClient over a mocked transport: batching, retries, typed errors, approvals, scope probes."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from contextos.client import MAX_BATCH_EVENTS, ContextOSClient, withdraw_approval
from contextos.errors import APIError, ApprovalTimeout, AuthError, ServerError, Unreachable
from contextos.models import AgentRef, EventEnvelope, ToolRef

from .sdk_fakes import API_KEY, FakeServer, decision_body


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))


def _event(client: ContextOSClient, i: int = 0, **fields) -> EventEnvelope:
    return client.new_event(
        "prompt.submitted", "ses_1", content=fields.pop("content", f"prompt {i}"), **fields
    )


def _tool_request(client: ContextOSClient) -> EventEnvelope:
    return client.new_event("tool.requested", "ses_1", tool=ToolRef(name="shell"), arguments={"cmd": "ls"})


def test_send_events_batches_at_500(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    outcome = client.send_events([_event(client, i) for i in range(1201)])
    sizes = [len(b["events"]) for b in server.bodies("POST", "/api/v1/events")]
    assert sizes == [MAX_BATCH_EVENTS, MAX_BATCH_EVENTS, 201]
    assert outcome.accepted == 1201 and not outcome.spooled


def test_send_events_batches_by_size(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    big = "x" * 150_000
    client.send_events([_event(client, i, content=big) for i in range(20)])
    batches = server.bodies("POST", "/api/v1/events")
    assert len(batches) > 1
    assert all(len(json.dumps(b)) < 2_000_000 for b in batches)


def test_events_carry_bearer_key_identity_and_integration(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    client.send_event(_event(client))
    request = server.calls("POST", "/api/v1/events")[0]
    assert request.headers["Authorization"] == f"Bearer {API_KEY}"
    assert request.headers["User-Agent"].startswith("contextos-python/")
    event = server.events()[0]
    assert event["agent"]["name"] == "test-agent" and event["integration"] == "python_sdk"


def test_idempotent_sends_retry_with_backoff(tmp_path: Path) -> None:
    server = FakeServer()
    slept: list[float] = []
    client = server.client(tmp_path, sleep=slept.append)
    ok = {"results": [{"event_id": "x", "status": "accepted"}]}
    server.sequence("POST", "/api/v1/events", [(0, httpx.ConnectError("refused")), (503, {}), (200, ok)])
    outcome = client.send_event(_event(client))
    assert len(server.calls("POST", "/api/v1/events")) == 3
    assert slept == [0.25, 0.5]
    assert outcome.results[0].status == "accepted"


def test_decide_is_not_retried_after_a_read_timeout(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    server.sequence("POST", "/api/v1/decide", [(0, httpx.ReadTimeout("slow")), (200, decision_body())])
    with pytest.raises(Unreachable):
        client.decide(_tool_request(client))
    assert len(server.calls("POST", "/api/v1/decide")) == 1


def test_decide_retries_when_the_connection_never_opened(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    server.sequence(
        "POST", "/api/v1/decide", [(0, httpx.ConnectError("refused")), (200, decision_body("DENY"))]
    )
    assert client.decide(_tool_request(client)).decision == "DENY"
    assert len(server.calls("POST", "/api/v1/decide")) == 2


def test_decide_only_accepts_tool_requested(tmp_path: Path) -> None:
    client = FakeServer().client(tmp_path)
    with pytest.raises(ValueError):
        client.decide(_event(client))


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, AuthError),
        (403, AuthError),
        (500, ServerError),
        (404, APIError),
        (422, APIError),
        (502, Unreachable),
    ],
)
def test_typed_errors(tmp_path: Path, status: int, error: type[Exception]) -> None:
    server = FakeServer()
    server.route(
        "GET",
        "/api/v1/agents",
        {"error": {"code": "c", "message": "explained", "details": None}},
        status=status,
    )
    client = server.client(tmp_path, max_retries=0)
    with pytest.raises(error) as info:
        client.list_agents()
    if isinstance(info.value, APIError):
        assert info.value.message == "explained" and info.value.status_code == status


def test_missing_key_fails_before_any_request(tmp_path: Path) -> None:
    server = FakeServer()
    client = ContextOSClient("http://contextos.test", None, transport=server.transport(), spool=False)
    with pytest.raises(AuthError, match="No API key"):
        client.list_agents()
    assert server.requests == []
    assert client.health() == {"status": "ok"}  # health needs no key


def test_base_url_with_api_prefix_is_normalised(tmp_path: Path) -> None:
    server = FakeServer()
    client = ContextOSClient(
        "http://contextos.test/api/v1/", API_KEY, transport=server.transport(), spool=False
    )
    client.health()
    assert server.requests[0].url.path == "/api/v1/health"


def test_poison_event_is_isolated_instead_of_blocking_the_batch(tmp_path: Path) -> None:
    server = FakeServer()

    def handler(request: httpx.Request) -> httpx.Response:
        events = json.loads(request.content)["events"]
        if any(e.get("content") == "poison" for e in events):
            return httpx.Response(
                422, json={"error": {"code": "validation_failed", "message": "bad event", "details": []}}
            )
        return FakeServer._accept_events(request)

    server.route("POST", "/api/v1/events", handler=handler)
    client = server.client(tmp_path)
    events = [_event(client, 0), _event(client, 1, content="poison"), _event(client, 2), _event(client, 3)]
    outcome = client.send_events(events)
    assert outcome.accepted == 3
    assert [r.event_id for r in outcome.rejected] == [events[1].event_id]


def test_wait_for_approval_polls_until_decided(tmp_path: Path) -> None:
    server = FakeServer()
    server.sequence(
        "GET",
        "/api/v1/decide/approvals/apr_1",
        [
            (200, {"status": "pending"}),
            (503, {}),
            (200, {"status": "pending"}),
            (200, {"status": "approved"}),
        ],
    )
    slept: list[float] = []
    client = server.client(tmp_path, sleep=slept.append, max_retries=0)
    assert client.wait_for_approval("apr_1", timeout_s=60, poll_s=1.5)["status"] == "approved"
    assert slept == [1.5, 1.5, 1.5]


def test_wait_for_approval_times_out(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("GET", "/api/v1/decide/approvals/apr_1", {"status": "pending"})
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    client = server.client(tmp_path, sleep=sleep, clock=lambda: now[0])
    with pytest.raises(ApprovalTimeout) as info:
        client.wait_for_approval("apr_1", timeout_s=5, poll_s=2)
    assert info.value.last_status == "pending" and now[0] == pytest.approx(5)


def test_cancel_approval_posts_the_reason_once(tmp_path: Path) -> None:
    server = FakeServer()
    server.route(
        "POST", "/api/v1/decide/approvals/apr_2/cancel", {"approval_id": "apr_2", "status": "cancelled"}
    )
    client = server.client(tmp_path)
    assert client.cancel_approval("apr_2", "  stopped waiting  ")["status"] == "cancelled"
    assert server.bodies("POST", "/api/v1/decide/approvals/apr_2/cancel") == [{"reason": "stopped waiting"}]
    client.cancel_approval("apr_2", "x" * 900)
    assert len(server.bodies("POST", "/api/v1/decide/approvals/apr_2/cancel")[1]["reason"]) == 500
    client.cancel_approval("apr_2")
    assert (
        server.calls("POST", "/api/v1/decide/approvals/apr_2/cancel")[2].content == b""
    )  # no body: no reason


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, {"approval_id": "apr_1", "status": "cancelled"}, "cancelled"),
        (
            409,
            {"error": {"code": "conflict", "message": "decided", "details": {"status": "APPROVED"}}},
            "approved",
        ),
        (409, {"error": {"code": "conflict", "message": "decided", "details": None}}, None),
        (404, {"error": {"code": "not_found", "message": "Approval not found", "details": None}}, None),
        (401, {"error": {"code": "unauthorized", "message": "revoked", "details": None}}, None),
        (503, {}, None),
    ],
)
def test_withdraw_approval_never_raises(
    tmp_path: Path, status: int, body: dict, expected: str | None
) -> None:
    server = FakeServer()
    server.route("POST", "/api/v1/decide/approvals/apr_1/cancel", body, status=status)
    assert withdraw_approval(server.client(tmp_path, max_retries=0), "apr_1", "stopped waiting") == expected


def test_withdraw_approval_when_unreachable(tmp_path: Path) -> None:
    server = FakeServer()
    server.down = True
    assert withdraw_approval(server.client(tmp_path, max_retries=0), "apr_1", "stopped waiting") is None


def test_probe_scopes_uses_requests_that_cannot_change_state(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("GET", "/api/v1/agents", {"items": [], "total": 0, "limit": 1, "offset": 0})
    server.route(
        "POST", "/api/v1/events", {"error": {"code": "validation_failed", "message": "x"}}, status=422
    )
    server.route(
        "POST",
        "/api/v1/decide",
        {"error": {"code": "forbidden", "message": "Missing permission 'decide'"}},
        status=403,
    )
    client = server.client(tmp_path)
    assert client.probe_scopes() == {"read": True, "ingest": True, "decide": False}
    assert server.bodies("POST", "/api/v1/events") == [{"events": []}]


def test_probe_scopes_raises_for_an_invalid_key(tmp_path: Path) -> None:
    server = FakeServer()
    server.route(
        "GET",
        "/api/v1/agents",
        {"error": {"code": "unauthenticated", "message": "Invalid or revoked API key"}},
        status=401,
    )
    with pytest.raises(AuthError, match="revoked"):
        server.client(tmp_path).probe_scopes()


def test_scan_and_read_helpers_hit_the_documented_endpoints(tmp_path: Path) -> None:
    server = FakeServer()
    for method, path in (
        ("POST", "/api/v1/scan"),
        ("GET", "/api/v1/sessions/ses_1/timeline"),
        ("GET", "/api/v1/simulations/scenarios"),
        ("POST", "/api/v1/simulations/runs"),
        ("GET", "/api/v1/events"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/policies"),
    ):
        server.route(method, path, {"ok": path})
    client = server.client(tmp_path)
    assert client.scan("ignore previous instructions", "web") == {"ok": "/api/v1/scan"}
    assert server.bodies("POST", "/api/v1/scan") == [
        {"content": "ignore previous instructions", "source_type": "web"}
    ]
    client.session_timeline("ses_1")
    client.list_scenarios()
    client.run_simulation("prompt-injection-basic")
    assert server.bodies("POST", "/api/v1/simulations/runs") == [{"scenario_id": "prompt-injection-basic"}]
    client.list_events(session_id="ses_1", limit=5)
    first_events_call = server.calls("GET", "/api/v1/events")[0].url.params
    assert first_events_call["session_id"] == "ses_1" and "include_simulated" not in first_events_call
    client.list_events(include_simulated=True)
    assert server.calls("GET", "/api/v1/events")[1].url.params["include_simulated"] == "true"
    client.list_incidents(status="open")
    client.list_policies()


def test_list_agents_search_uses_the_server_parameter(tmp_path: Path) -> None:
    """GET /agents searches with ``q``; an unknown parameter would be ignored and list every agent."""
    server = FakeServer()
    server.route("GET", "/api/v1/agents", {"items": [], "total": 0, "limit": 50, "offset": 0})
    client = server.client(tmp_path)
    client.list_agents(search="billing", include_simulated=True)
    params = server.calls("GET", "/api/v1/agents")[0].url.params
    assert params["q"] == "billing" and "search" not in params and params["include_simulated"] == "true"
    client.list_agents()
    assert "q" not in server.calls("GET", "/api/v1/agents")[1].url.params


def test_find_session_resolves_an_integration_session_id(tmp_path: Path) -> None:
    server = FakeServer()
    server.route(
        "GET",
        "/api/v1/sessions",
        {
            "items": [
                {"id": "asn_2", "external_session_id": "ses_x2"},
                {"id": "asn_1", "external_session_id": "ses_x"},
            ],
            "total": 2,
            "limit": 50,
            "offset": 0,
        },
    )
    server.route("GET", "/api/v1/sessions/asn_1", {"id": "asn_1", "external_session_id": "ses_x"})
    client = server.client(tmp_path)
    assert client.find_session("ses_x")["id"] == "asn_1"
    assert client.find_session("asn_1")["id"] == "asn_1"
    with pytest.raises(APIError) as info:
        client.find_session("ses_nope")
    assert info.value.status_code == 404


def test_repr_never_contains_the_key(tmp_path: Path) -> None:
    client = FakeServer().client(tmp_path)
    assert API_KEY not in repr(client) and "ctxk_tes…" in repr(client)


def test_default_agent_comes_from_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from contextos.config import load_config

    monkeypatch.chdir(tmp_path)
    cfg = load_config(tmp_path, env={"CONTEXTOS_AGENT_NAME": "invoice-agent", "CONTEXTOS_API_KEY": API_KEY})
    client = ContextOSClient.from_config(cfg, spool=False)
    assert client.agent == AgentRef(name="invoice-agent", framework="python_sdk")


@pytest.mark.parametrize(
    ("url", "in_clear"),
    [
        ("http://contextos.example.com", True),
        ("http://10.0.0.5:8000/api/v1", True),
        ("https://contextos.example.com", False),
        ("http://localhost:8000", False),
        ("http://127.0.0.1:8000", False),
        ("http://[::1]:8000", False),
        ("http://app.localhost:8000", False),
        ("HTTPS://CONTEXTOS.EXAMPLE.COM", False),
    ],
)
def test_plain_http_to_another_host_is_detected(url: str, in_clear: bool) -> None:
    from contextos.client import sends_credentials_in_clear

    assert sends_credentials_in_clear(url) is in_clear


def test_client_warns_once_when_the_key_would_travel_unencrypted(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="contextos.client"):
        ContextOSClient("http://contextos.example.com", "ctxk_" + "x" * 20, spool=False)
        ContextOSClient("https://contextos.example.com", "ctxk_" + "x" * 20, spool=False)
        ContextOSClient("http://contextos.example.com", None, spool=False)  # no key, nothing to protect
    warnings = [r for r in caplog.records if "unencrypted" in r.getMessage()]
    assert len(warnings) == 1 and "ctxk_" not in warnings[0].getMessage()
