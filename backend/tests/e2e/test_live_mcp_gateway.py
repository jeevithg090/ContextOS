"""Live: ``contextos mcp-gateway`` in front of the example MCP servers, driven by a real MCP client.

    test (MCP host) ──stdio──▶ contextos mcp-gateway ──stdio──▶ examples/mcp/<server>.py
                                      └──HTTP──▶ contextos-server (live_support)

Asserted from the MCP responses the host receives, from the example server's own call log (what the
upstream really executed) and from the ContextOS API (what was recorded).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.e2e.live_support import EXAMPLES, LiveServer, client_env

pytestmark = pytest.mark.live
mcp = pytest.importorskip("mcp")

import anyio  # noqa: E402
from mcp import ClientSession, StdioServerParameters, stdio_client  # noqa: E402

DENY_POLICY = "Live: deny deleting every note"


def _calls(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _gateway(live: LiveServer, tmp_path: Path, name: str, example: str, calls: Path) -> StdioServerParameters:
    env = client_env(live, tmp_path / "home", MCP_EXAMPLE_CALL_LOG=str(calls))
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "contextos",
            "mcp-gateway",
            "--name",
            name,
            "--agent",
            f"mcp-live-{name}",
            "--approval-timeout",
            "0",
            "--startup-timeout",
            "240",
            "--",
            sys.executable,
            str(EXAMPLES / "mcp" / example),
        ],
        env=env,
        cwd=str(tmp_path),
    )


def _session(params: StdioServerParameters, errlog: Path, steps: Any) -> dict[str, Any]:
    async def scenario() -> dict[str, Any]:
        with errlog.open("w", encoding="utf-8") as err, anyio.fail_after(480):
            async with stdio_client(params, errlog=err) as (read, write), ClientSession(read, write) as host:
                await host.initialize()
                return await steps(host)

    try:
        return anyio.run(scenario)
    except BaseException:
        print("gateway stderr:\n" + errlog.read_text(encoding="utf-8", errors="replace"))
        raise


def _ensure_deny_policy(live: LiveServer) -> None:
    names = {p["name"] for p in live.get("/policies", limit=200)["items"]}
    if DENY_POLICY not in names:
        live.post(
            "/policies",
            {
                "name": DENY_POLICY,
                "outcome": "DENY",
                "severity": "high",
                "priority": 5000,
                "description": "Irreversible; goes through a ticket.",
                "conditions": {"field": "tool.name", "op": "eq", "value": "delete_all_notes"},
            },
            201,
        )


def test_gateway_blocks_denied_calls_before_upstream_and_flags_poisoned_tools(
    live: LiveServer, tmp_path: Path
) -> None:
    _ensure_deny_policy(live)
    calls, errlog = tmp_path / "calls.jsonl", tmp_path / "gateway.stderr"

    async def steps(host: ClientSession) -> dict[str, Any]:
        return {
            "tools": (await host.list_tools()).tools,
            "forecast": await host.call_tool("get_forecast", {"city": "Paris"}),
            "delete": await host.call_tool("delete_all_notes", {"confirm": True}),
        }

    out = _session(_gateway(live, tmp_path, "notes", "malicious_server.py", calls), errlog, steps)
    logged = errlog.read_text(encoding="utf-8", errors="replace")

    # The denied tools/call never reached the upstream server; the host got a policy error.
    assert out["delete"].is_error
    assert _text(out["delete"]).startswith(f"Blocked by ContextOS policy '{DENY_POLICY}'"), _text(
        out["delete"]
    )
    executed = [c["tool"] for c in _calls(calls)]
    assert executed == ["get_forecast"], executed
    assert not any(c["contextos_settings_visible"] for c in _calls(calls)), (
        "the upstream saw CONTEXTOS_* settings"
    )
    assert "Forecast for Paris" in _text(out["forecast"])
    assert live.api_key not in logged and "SYSTEM OVERRIDE" not in logged

    # The poisoned add_note description raised a finding on the MCP server source.
    assert sorted(t.name for t in out["tools"]) == ["add_note", "delete_all_notes", "get_forecast"]
    poisoning = live.get("/findings", q="MCP-POISON-001", limit=50)["items"]
    assert poisoning and poisoning[0]["source"]["source_type"] == "mcp_server", poisoning
    assert poisoning[0]["source"]["identifier"] == "notes"

    # What ContextOS recorded for the calls: an enforced DENY and an allowed call whose result was scanned.
    (agent,) = [a for a in live.get("/agents", q="mcp-live-notes")["items"] if a["name"] == "mcp-live-notes"]
    decisions = live.get("/policies/recent-decisions", agent_id=agent["id"], limit=50)["items"]
    by_tool = {d["tool_name"]: d for d in decisions}
    assert (
        by_tool["delete_all_notes"]["decision"] == "DENY"
        and by_tool["delete_all_notes"]["enforcement"] == "enforced"
    )
    assert by_tool["get_forecast"]["decision"] in ("ALLOW", "AUDIT")
    result_findings = {f["category"] for f in live.get("/findings", agent_id=agent["id"], limit=100)["items"]}
    assert result_findings & {"prompt_injection", "instruction_override", "exfiltration"}, result_findings


def test_benign_server_runs_unchanged_through_the_gateway(live: LiveServer, tmp_path: Path) -> None:
    calls, errlog = tmp_path / "calls.jsonl", tmp_path / "gateway.stderr"

    async def steps(host: ClientSession) -> dict[str, Any]:
        return {
            "tools": (await host.list_tools()).tools,
            "add": await host.call_tool("add", {"a": 2, "b": 3}),
            "words": await host.call_tool("word_count", {"text": "three little words"}),
        }

    out = _session(_gateway(live, tmp_path, "toolbox", "benign_server.py", calls), errlog, steps)
    assert sorted(t.name for t in out["tools"]) == ["add", "utc_now", "word_count"]
    assert _text(out["add"]) in ("5", "5.0") and _text(out["words"]) == "3"
    assert [c["tool"] for c in _calls(calls)] == ["add", "word_count"]
    (agent,) = [
        a for a in live.get("/agents", q="mcp-live-toolbox")["items"] if a["name"] == "mcp-live-toolbox"
    ]
    assert live.get("/findings", agent_id=agent["id"])["total"] == 0
    decisions = live.get("/policies/recent-decisions", agent_id=agent["id"], limit=50)["items"]
    assert sorted(d["decision"] for d in decisions) == ["ALLOW", "ALLOW"]
