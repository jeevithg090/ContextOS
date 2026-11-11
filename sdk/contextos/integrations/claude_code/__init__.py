"""Claude Code integration: hooks that report what Claude Code does and enforce policy before tools run.

- ``hook.main(event_name)`` — the ``contextos hook <Event>`` command Claude Code runs.
  PreToolUse asks ``POST /decide`` and answers ``deny`` / ``ask`` (never ``allow``); the other hooks
  report sessions, prompts and tool results and never block.
- ``install.install_hooks`` / ``uninstall_hooks`` / ``hooks_status`` — manage the hooks in
  ``.claude/settings.json``, ``.claude/settings.local.json`` or ``~/.claude/settings.json``.
- ``mapping`` — pure payload → event-envelope mapping; ``enforce`` — decision → hook answer.

See docs/integrations/claude-code.md for the verified hook contract, what is enforced versus
observed, and the limitations.
"""

from .install import hooks_status, install_hooks, uninstall_hooks

__all__ = ["hooks_status", "install_hooks", "uninstall_hooks"]
