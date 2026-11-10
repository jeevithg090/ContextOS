"""Framework integrations built on the SDK (each talks to ContextOS over HTTP only).

- ``contextos.integrations.claude_code`` — Claude Code hooks (PreToolUse enforcement, observation hooks).
- ``contextos.integrations.mcp_gateway`` — MCP proxy that enforces decisions on ``tools/call``.

Subpackages are imported lazily by the CLI so a missing optional dependency never breaks
``contextos`` itself.
"""
