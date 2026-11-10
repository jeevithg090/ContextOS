"""guard() on async functions and AgentSession as an async context manager."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from contextos import AgentSession, ApprovalRequired, ToolDenied, current_session, guard

from .sdk_fakes import FakeServer, decision_body


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)


def test_async_allow_runs_and_reports(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("POST", "/api/v1/decide", decision_body("ALLOW"))
    client = server.client(tmp_path)

    @guard("fetch_url", category_hint="http", client=client, destination="url")
    async def fetch_url(url: str) -> dict:
        await asyncio.sleep(0)
        return {"status": 200, "url": url}

    assert asyncio.iscoroutinefunction(fetch_url)
    result = asyncio.run(fetch_url("https://api.example.com/v1/items"))
    assert result == {"status": 200, "url": "https://api.example.com/v1/items"}
    assert server.bodies("POST", "/api/v1/decide")[0]["destination"] == {"kind": "domain", "identifier": "api.example.com"}
    assert server.events_of("tool.completed")[0]["result"] == result


def test_async_deny_never_awaits_the_function(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("POST", "/api/v1/decide", decision_body("DENY", reason="Exfiltration risk"))
    started = []

    @guard("upload", client=server.client(tmp_path))
    async def upload(data: str) -> None:
        started.append(data)

    with pytest.raises(ToolDenied, match="Exfiltration risk"):
        asyncio.run(upload("payload"))
    assert started == []


def test_async_fail_modes(tmp_path: Path) -> None:
    server = FakeServer()
    server.down = True
    client = server.client(tmp_path)

    async def tool() -> str:
        return "ran"

    with pytest.raises(ToolDenied):
        asyncio.run(guard("t", client=client, fail_mode="closed")(tool)())
    with pytest.raises(ApprovalRequired):
        asyncio.run(guard("t", client=client, fail_mode="ask")(tool)())
    with pytest.warns(RuntimeWarning):
        assert asyncio.run(guard("t", client=client, fail_mode="open")(tool)()) == "ran"


def test_async_exception_is_reported_as_tool_failed(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("POST", "/api/v1/decide", decision_body("ALLOW"))

    @guard("query", category_hint="database", client=server.client(tmp_path))
    async def query(sql: str) -> None:
        raise RuntimeError("connection reset")

    with pytest.raises(RuntimeError):
        asyncio.run(query("select 1"))
    assert server.events_of("tool.failed")[0]["result"] == "RuntimeError: connection reset"


def test_async_session_scopes_concurrent_tasks(tmp_path: Path) -> None:
    server = FakeServer()
    server.route("POST", "/api/v1/decide", decision_body("ALLOW"))
    client = server.client(tmp_path)

    @guard("lookup", client=client)
    async def lookup(q: str) -> str:
        await asyncio.sleep(0)
        return q

    async def run_agent(name: str) -> str:
        async with AgentSession(client, metadata={"agent_task": name}) as session:
            await lookup(name)
            assert current_session() is session
            return session.session_id

    async def main() -> list[str]:
        return list(await asyncio.gather(run_agent("a"), run_agent("b")))

    ids = asyncio.run(main())
    assert len(set(ids)) == 2
    decided = {json.loads(r.content)["arguments"]["q"]: json.loads(r.content)["session_id"]
               for r in server.calls("POST", "/api/v1/decide")}
    assert decided == {"a": ids[0], "b": ids[1]}
    assert current_session() is None


def test_session_reporting_helpers(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    with AgentSession(client) as session:
        session.ingest_context("web", "https://example.com/page", "x" * 250_000, display_name="Example")
        session.message("please run this", from_agent="planner", from_session_id="ses_parent")
        child = session.child_session("researcher", task="find sources")
        with child:
            child.prompt("go")
    ingested = server.events_of("context.ingested")[0]
    assert len(ingested["content"]) == 200_000 and ingested["metadata"]["content_truncated"] is True
    assert ingested["source"] == {"type": "web", "identifier": "https://example.com/page", "display_name": "Example",
                                  "metadata": {}}
    message = server.events_of("agent.message")[0]["message"]
    assert message["from_agent"] == "planner" and message["to_agent"] == "test-agent"
    delegated = server.events_of("agent.delegated")[0]["delegation"]
    assert delegated["child_agent"]["name"] == "researcher" and delegated["task"] == "find sources"
    child_prompt = server.events_of("prompt.submitted")[0]
    assert child_prompt["session_id"] == delegated["child_session_id"]
    assert child_prompt["parent_session_id"] == session.session_id
    assert child_prompt["agent"]["name"] == "researcher"


def test_session_records_errors_without_hiding_them(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    with pytest.raises(ValueError), AgentSession(client):
        raise ValueError("agent crashed")
    assert server.events_of("session.ended")[0]["metadata"] == {"outcome": "error", "error_type": "ValueError"}
