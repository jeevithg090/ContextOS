"""ContextOS MCP security gateway: a stdio proxy that enforces ContextOS decisions on MCP ``tools/call``.

    contextos mcp-gateway --name <server-name> [--agent <name>] -- <upstream command> [args...]

The gateway starts the upstream MCP server as a child process, connects to it as an MCP client,
and serves the same tools, resources and prompts to the host (Claude Code, Claude Desktop,
Cursor, ...) on its own stdin/stdout:

- ``tools/list``  — upstream tools are reported to ContextOS (``mcp.server_connected``) so their
  descriptions are scanned for tool poisoning, then re-exposed unchanged.
- ``tools/call``  — a ``tool.requested`` event goes to ``POST /decide`` BEFORE the upstream is
  contacted. DENY (and unresolved approvals, unappliable restrictions, unreachable ContextOS in
  the default fail-closed mode) return an error result without calling the upstream tool. This is
  enforced: the call never reaches the upstream server.
- results       — reported as ``tool.completed`` / ``tool.failed``; ContextOS records the result
  as context from an ``mcp_tool`` source and scans it for prompt injection (observed).
- resources and prompts are passed through; what they return is reported as ``context.ingested``
  (observed, never blocked).

Modules: :mod:`.mapping` (MCP objects ↔ ContextOS events, pure), :mod:`.enforcement` (decision
handling and fail modes), :mod:`.proxy` (the MCP server/client wiring) and :mod:`.cli`.
Requires the optional ``mcp`` dependency (``pip install 'contextos[mcp]'``, MCP Python SDK 2.x).
"""

from __future__ import annotations

__all__ = ["cli", "enforcement", "mapping", "proxy"]
