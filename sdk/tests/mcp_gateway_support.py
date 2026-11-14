"""Helpers for the MCP gateway tests: example servers, in-memory MCP chains and a fake clock.

The in-memory chain is the real MCP stack end to end, without subprocesses:

    downstream ClientSession ──memory──▶ Gateway's mcp Server ──(Gateway)──▶ upstream ClientSession
        ──memory──▶ examples/mcp/<server>.py (MCPServer)

ContextOS is the ``FakeServer`` from ``sdk_fakes`` (httpx MockTransport), so every request the
gateway makes is recorded.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import mcp.types as types
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport

from contextos.client import ContextOSClient
from contextos.integrations.mcp_gateway.proxy import Gateway, GatewaySettings

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "mcp"
_COUNTER = itertools.count()


def load_example(name: str) -> ModuleType:
    """A fresh copy of ``examples/mcp/<name>.py`` (module state such as stored notes is not shared)."""
    path = EXAMPLES / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mcp_example_{name}_{next(_COUNTER)}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@asynccontextmanager
async def connected(server: Any, **session_kwargs: Any) -> AsyncIterator[ClientSession]:
    """An initialized ClientSession talking to ``server`` (an MCPServer or a lowlevel Server) in memory."""
    async with InMemoryTransport(server) as (read, write):
        async with ClientSession(read, write, **session_kwargs) as session:
            await session.initialize()
            yield session


@dataclass
class Chain:
    host: ClientSession
    gateway: Gateway
    example: ModuleType
    notifications: list[Any] = field(default_factory=list)


@asynccontextmanager
async def gateway_chain(
    client: ContextOSClient,
    settings: GatewaySettings | None = None,
    *,
    example: str = "malicious_server",
    host_name: str = "test-host",
) -> AsyncIterator[Chain]:
    module = load_example(example)
    settings = settings or GatewaySettings(server_name="notes", session_id="ses_test")
    async with connected(module.server) as upstream:
        info = upstream.initialize_result
        gateway = Gateway(upstream, client, settings, upstream_info=info)
        server = gateway.build_server()
        received: list[Any] = []

        async def on_message(message: Any) -> None:
            received.append(message)

        async with connected(
            server,
            message_handler=on_message,
            client_info=types.Implementation(name=host_name, version="1.2.3"),
        ) as host:
            yield Chain(host, gateway, module, received)


def text_of(result: types.CallToolResult) -> str:
    return "\n".join(b.text for b in result.content if isinstance(b, types.TextContent))


def call_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class FakeClock:
    """Monotonic clock whose async ``sleep`` advances time instantly."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
