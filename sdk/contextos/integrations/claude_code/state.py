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

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from contextos.config import contextos_home

log = logging.getLogger("contextos.claude_code.state")

MAX_AGE_S = 24 * 3600


def state_dir(kind: str) -> Path:
    return contextos_home() / "claude_code" / kind


def _path(kind: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:40]
    return state_dir(kind) / f"{digest}.json"


def put(kind: str, key: str, record: dict[str, Any]) -> None:
    """Store ``record`` (JSON-safe ids/names only) under ``key``. Failures are logged, never raised."""
    directory = state_dir(kind)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        fd = os.open(_path(kind, key), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({**{k: v for k, v in record.items() if v is not None}, "_at": time.time()}, handle)
        _prune(directory)
    except OSError as exc:
        log.debug("Could not store %s record: %s", kind, exc.strerror or exc)


def get(kind: str, key: str, *, remove: bool = False) -> dict[str, Any] | None:
    """The record for ``key`` (``None`` when absent, unreadable or expired); ``remove`` deletes it."""
    path = _path(kind, key)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if remove:
        path.unlink(missing_ok=True)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or time.time() - float(data.get("_at") or 0) > MAX_AGE_S:
        return None
    data.pop("_at", None)
    return data


def _prune(directory: Path) -> None:
    cutoff = time.time() - MAX_AGE_S
    for entry in directory.glob("*.json"):
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink(missing_ok=True)
        except OSError:
            continue


__all__ = ["MAX_AGE_S", "get", "put", "state_dir"]
