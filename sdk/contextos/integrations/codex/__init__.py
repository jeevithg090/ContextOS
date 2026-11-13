"""OpenAI Codex integration: hooks that report what Codex does and enforce policy before tools run.

- ``hook.main(event_name)`` — the ``contextos codex-hook <Event>`` command Codex runs. PreToolUse
  asks ``POST /decide`` and blocks with exit code 2 (never ``ask``; ``allow`` only to carry a
  RESTRICT-masked input); the other hooks report sessions, prompts and tool results and never block.
- ``install.install_hooks`` / ``uninstall_hooks`` / ``hooks_status`` — manage the hooks in
  ``<project>/.codex/hooks.json`` or ``$CODEX_HOME/hooks.json``. Codex runs them only after the user
  trusts them in Codex (``/hooks``).
- ``mapping`` — pure payload → event-envelope mapping; ``enforce`` — decision → hook answer.

Codex's MCP servers can additionally run behind the MCP gateway (``contextos mcp-gateway``) from
``[mcp_servers.<name>]`` in ``config.toml``. See docs/integrations/codex.md for the verified hook
contract, what is enforced versus observed, and the limitations.
"""

from .install import hooks_status, install_hooks, uninstall_hooks

__all__ = ["hooks_status", "install_hooks", "uninstall_hooks"]
