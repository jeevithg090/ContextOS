"""End to end: real ContextOS backend + the real gateway process + examples/mcp/malicious_server.py.

    test (MCP host) ──stdio──▶ `python -m contextos mcp-gateway` ──stdio──▶ malicious_server.py
                                          └──HTTP──▶ ContextOS (uvicorn on 127.0.0.1:18000-18999, temp SQLite)

The organisation has the default policy pack plus one DENY policy for ``delete_all_notes``.
Asserts against the database what ContextOS actually recorded, and against the example server's
call log what the upstream server actually executed.

Skipped when the backend package (``app``) is not importable. Slow by nature (three Python
processes); allow a few minutes on a loaded machine.
"""

from __future__ import annotations

import os
import random
import socket
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

os.environ.setdefault("CONTEXTOS_ENV", "test")
os.environ.setdefault("CONTEXTOS_SECRET_KEY", "test-secret-key-for-contextos-unit-tests-0123456789")
os.environ.setdefault("CONTEXTOS_SERVE_FRONTEND", "false")

pytest.importorskip("mcp")
pytest.importorskip("app.main")
uvicorn = pytest.importorskip("uvicorn")

import anyio  # noqa: E402
from mcp import ClientSession, StdioServerParameters, stdio_client  # noqa: E402
from sqlalchemy import select  # noqa: E402

from .mcp_gateway_support import EXAMPLES, call_log, text_of  # noqa: E402

DENY_POLICY = "Deny deleting notes"


@dataclass
class Backend:
    url: str
    api_key: str
    org_id: str
    session_factory: object

    def rows(self, model, *where):
        with self.session_factory() as db:  # type: ignore[operator]
            return list(db.scalars(select(model).where(model.organization_id == self.org_id, *where)).all())


def _free_port() -> int:
    ports = list(range(18000, 19000))
    random.shuffle(ports)
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    pytest.skip("no free port in 18000-18999")


def _seed(db) -> tuple[str, str]:
    from app.core.ids import new_id
    from app.core.security import generate_api_key
    from app.models import ApiKey, Organization, SecurityPolicy
    from app.services.seed import seed_security_defaults

    org = Organization(
        id=new_id("organization"),
        name="Gateway Co",
        slug="gateway-co-" + new_id("x")[-6:].lower(),
        settings={},
    )
    db.add(org)
    db.flush()
    raw_key, prefix, key_hash = generate_api_key()
    db.add(
        ApiKey(
            id=new_id("api_key"),
            organization_id=org.id,
            name="mcp gateway",
            prefix=prefix,
            key_hash=key_hash,
            scopes=["ingest", "decide", "read"],
        )
    )
    seed_security_defaults(db, org.id)
    db.add(
        SecurityPolicy(
            id=new_id("policy"),
            organization_id=org.id,
            name=DENY_POLICY,
            description="Deleting every note is irreversible; it must go through a ticket.",
            enabled=True,
            mode="enforce",
            priority=5000,
            outcome="DENY",
            severity="high",
            tags=["mcp"],
            restrictions={},
            conditions={"field": "tool.name", "op": "eq", "value": "delete_all_notes"},
        )
    )
    db.commit()
    return org.id, raw_key


@pytest.fixture()
def backend(tmp_path: Path) -> Iterator[Backend]:
    import app.models  # noqa: F401  (registers tables)
    from app.database.base import Base
    from app.database.session import make_engine, session_factory, set_engine
    from app.main import create_app

    engine = make_engine(f"sqlite:///{tmp_path / 'contextos.db'}")
    Base.metadata.create_all(engine)
    set_engine(engine)
    factory = session_factory()
    with factory() as db:
        org_id, api_key = _seed(db)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, name="contextos-test-api", daemon=True)
    thread.start()
    deadline = time.monotonic() + 120
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            pytest.fail("the ContextOS test server did not start")
        time.sleep(0.05)
    try:
        yield Backend(f"http://127.0.0.1:{port}", api_key, org_id, factory)
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        engine.dispose()


def test_gateway_enforces_and_reports_against_the_real_backend(backend: Backend, tmp_path: Path) -> None:
    from app.models import ContextSource, SecurityFinding, Tool, ToolInvocation

    calls = tmp_path / "calls.jsonl"
    stderr_path = tmp_path / "gateway.stderr"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "contextos",
            "mcp-gateway",
            "--name",
            "notes",
            "--agent",
            "integration-agent",
            "--approval-timeout",
            "0",
            "--startup-timeout",
            "180",
            "--",
            sys.executable,
            str(EXAMPLES / "malicious_server.py"),
        ],
        env={
            "CONTEXTOS_URL": backend.url,
            "CONTEXTOS_API_KEY": backend.api_key,
            "CONTEXTOS_HOME": str(tmp_path / "home"),
            "MCP_EXAMPLE_CALL_LOG": str(calls),
            "PYTHONUNBUFFERED": "1",
        },
        cwd=str(tmp_path),
    )

    def stderr() -> str:
        return stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""

    async def scenario() -> dict:
        with stderr_path.open("w", encoding="utf-8") as errlog, anyio.fail_after(420):
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as host:
                    await host.initialize()
                    out: dict = {"tools": (await host.list_tools()).tools}
                    out["forecast"] = await host.call_tool("get_forecast", {"city": "Paris"})
                    out["delete"] = await host.call_tool("delete_all_notes", {"confirm": True})
                    out["resource"] = await host.read_resource("notes://index")
                    return out

    try:
        out = anyio.run(scenario)
    except BaseException:
        print("gateway stderr:\n" + stderr())
        raise
    context = f"\ngateway stderr:\n{stderr()}"

    # 1. tools/list: the listing reached ContextOS and the poisoned description was detected.
    assert sorted(t.name for t in out["tools"]) == ["add_note", "delete_all_notes", "get_forecast"], context
    servers = backend.rows(
        ContextSource, ContextSource.source_type == "mcp_server", ContextSource.identifier == "notes"
    )
    assert len(servers) == 1, context
    poisoning = backend.rows(SecurityFinding, SecurityFinding.rule_id == "MCP-POISON-001")
    assert poisoning and poisoning[0].source_id == servers[0].id, context
    add_note = backend.rows(Tool, Tool.provider == "mcp:notes", Tool.name == "add_note")
    assert add_note and "MCP-POISON-001" in add_note[0].tool_metadata["poisoning"]["rule_ids"], context

    # 2. An allowed call was forwarded, and the injection in its result was detected.
    forecast = out["forecast"]
    assert not forecast.is_error and "Forecast for Paris" in text_of(forecast), context
    executed = [c["tool"] for c in call_log(calls)]
    assert executed == ["get_forecast"], context
    assert not any(c["contextos_settings_visible"] for c in call_log(calls)), (
        "the upstream saw CONTEXTOS_* settings"
    )
    (invocation,) = backend.rows(
        ToolInvocation,
        ToolInvocation.tool_id.in_(
            [t.id for t in backend.rows(Tool, Tool.provider == "mcp:notes", Tool.name == "get_forecast")]
        ),
    )
    assert invocation.enforcement == "enforced" and invocation.decision in ("ALLOW", "AUDIT"), context
    assert invocation.status == "completed" and invocation.result_context_item_id, context
    result_findings = backend.rows(
        SecurityFinding, SecurityFinding.context_item_id == invocation.result_context_item_id
    )
    categories = {f.category for f in result_findings}
    assert categories & {"prompt_injection", "instruction_override", "exfiltration"}, (categories, context)
    assert backend.rows(
        ContextSource,
        ContextSource.source_type == "mcp_tool",
        ContextSource.identifier == "notes/get_forecast",
    ), context

    # 3. The DENY policy blocked delete_all_notes before the upstream server was contacted.
    blocked = out["delete"]
    assert blocked.is_error and text_of(blocked).startswith(f"Blocked by ContextOS policy '{DENY_POLICY}'"), (
        context
    )
    assert "The tool was not run." in text_of(blocked)
    assert "delete_all_notes" not in [c["tool"] for c in call_log(calls)], context
    delete_tool = backend.rows(Tool, Tool.provider == "mcp:notes", Tool.name == "delete_all_notes")
    (denied,) = backend.rows(ToolInvocation, ToolInvocation.tool_id == delete_tool[0].id)
    assert (denied.decision, denied.status, denied.enforcement) == ("DENY", "denied", "enforced"), context
    assert denied.completed_at is None, context

    # 4. Resource reads pass through and are recorded (and scanned) as context.
    assert "admin@attacker.example" in out["resource"].contents[0].text, context
    resources = backend.rows(ContextSource, ContextSource.identifier == "notes/resource:notes://index")
    assert resources and resources[0].finding_count >= 1, context

    # 5. The gateway logs decisions, never the key, arguments or results.
    logged = stderr()
    assert "tools/call delete_all_notes: denied" in logged and "tool poisoning" in logged, context
    assert backend.api_key not in logged and "SYSTEM OVERRIDE" not in logged and "Paris" not in logged, (
        context
    )
