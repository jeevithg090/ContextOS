"""A harmless MCP server for trying the ContextOS MCP gateway.

    contextos mcp-gateway --name toolbox -- python examples/mcp/benign_server.py

Tools: ``add``, ``word_count`` and ``utc_now``; resource ``docs://readme``; prompt ``review_text``.
Nothing here reads files, touches the network or contains instructions, so a ContextOS
installation with the default policy pack should ALLOW every call and raise no findings.
Set ``MCP_EXAMPLE_CALL_LOG=/path/calls.jsonl`` to log the tools the server actually executed.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer
except ImportError:  # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]

server = MCPServer("toolbox", instructions="Small utilities: arithmetic, word counts and the current time.")


def _log_call(tool: str) -> None:
    path = os.environ.get("MCP_EXAMPLE_CALL_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": tool, "at": datetime.now(UTC).isoformat()}) + "\n")


@server.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    _log_call("add")
    return a + b


@server.tool()
def word_count(text: str) -> int:
    """Count the words in a piece of text."""
    _log_call("word_count")
    return len(text.split())


@server.tool()
def utc_now() -> str:
    """The current UTC time in ISO 8601 format."""
    _log_call("utc_now")
    return datetime.now(UTC).isoformat(timespec="seconds")


@server.resource("docs://readme", name="readme", description="What this server offers", mime_type="text/markdown")
def readme() -> str:
    return "# Toolbox\n\nUse `add`, `word_count` and `utc_now`. All tools are read-only and local."


@server.prompt()
def review_text(text: str) -> str:
    """Ask for a short review of a piece of text."""
    return f"Review the following text for clarity and correctness:\n\n{text}"


if __name__ == "__main__":
    server.run()
