"""Small records shared between hook processes.

Every Claude Code hook runs as its own process, so facts learned in one hook that a later hook
needs are kept as tiny JSON files under ``~/.contextos/claude_code/<kind>/`` (directory 0700,
files 0600). Records hold ids, names and reasons only — never tool input, results or secrets — and
expire after a day.

Kinds in use:
- ``host_prompts``: the PreToolUse hook answered ``ask`` for a call (see ``approval``).
- ``delegations``: an ``Agent``/``Task`` call was reported as a delegation (keyed by tool_use_id,
  and by the subagent's ``agentId`` once PostToolUse reveals it) so SubagentStop and the
  ``<task-notification>`` that carries a background subagent's result can be attributed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from contextos.integrations.hookkit import MAX_RECORD_AGE_S, Records

MAX_AGE_S = MAX_RECORD_AGE_S
_RECORDS = Records("claude_code")


def state_dir(kind: str) -> Path:
    return _RECORDS.directory(kind)


def put(kind: str, key: str, record: dict[str, Any]) -> None:
    """Store ``record`` (JSON-safe ids/names only) under ``key``. Failures are logged, never raised."""
    _RECORDS.put(kind, key, record)


def get(kind: str, key: str, *, remove: bool = False) -> dict[str, Any] | None:
    """The record for ``key`` (``None`` when absent, unreadable or expired); ``remove`` deletes it."""
    return _RECORDS.get(kind, key, remove=remove)


__all__ = ["MAX_AGE_S", "get", "put", "state_dir"]
