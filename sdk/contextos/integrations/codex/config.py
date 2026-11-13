"""Settings for the Codex hook.

The hook reuses the SDK configuration (server URL, API key, timeouts, environment, spool size; see
:mod:`contextos.config`) and adds a few settings of its own. Each one resolves in this order, and
the first match wins:

1. Environment: ``CONTEXTOS_CODEX_FAIL_MODE``, ``CONTEXTOS_CODEX_APPROVAL_WAIT_S``,
   ``CONTEXTOS_CODEX_AGENT_NAME``, ``CONTEXTOS_CODEX_HOOK_TIMEOUT_S``,
   ``CONTEXTOS_CODEX_MAX_RESULT_CHARS``
2. The ``"codex"`` object in the project file ``.contextos/config.json``
3. The ``"codex"`` object in the user file ``~/.contextos/config.json``
4. Defaults: fail mode ``closed``, approval wait 45 s, agent name ``codex@<project directory
   name>``, hook timeout 60 s, results cut at 60,000 characters

Codex's PreToolUse hook can block a call or let it continue; it cannot hand the call to a person
(``permissionDecision: "ask"`` is rejected by Codex as unsupported output, and a rejected answer
lets the tool run). So the fail mode ``ask`` is accepted for symmetry with the other integrations
but behaves exactly like ``closed``, and an approval nobody decided in time always blocks.

The project directory is ``CONTEXTOS_CODEX_PROJECT_DIR`` when set, otherwise the nearest directory
at or above the hook's ``cwd`` that holds a project ``.contextos/config.json``, then the nearest
one with ``.git``, then ``cwd`` itself (Codex sets no project-directory variable for hooks).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contextos.config import (
    CONFIG_FILE_NAME,
    PROJECT_DIR_NAME,
    Config,
    ConfigError,
    find_project_config,
    load_config,
    user_config_path,
)

SECTION = "codex"
HOOK_FAIL_MODES = ("closed", "open", "ask")
DEFAULT_FAIL_MODE = "closed"
DEFAULT_APPROVAL_WAIT_S = 45.0
DEFAULT_HOOK_TIMEOUT_S = 60.0  # what install_hooks writes for PreToolUse
DEFAULT_MAX_RESULT_CHARS = 60_000  # keeps one tool.completed event well under the server's 512 kB limit
EVENT_BUDGET_S = 8.0  # observation hooks (never block) give up after this long
SESSION_END_BUDGET_S = 1.5  # Codex kills SessionEnd hooks after at most 3 s
POLL_S = 1.5
MAX_STDIN_BYTES = 8 * 1024 * 1024
_HOOK_MARGIN_S = 3.0  # answer this long before Codex would kill the hook

_ENV = {
    "fail_mode": "CONTEXTOS_CODEX_FAIL_MODE",
    "approval_wait_s": "CONTEXTOS_CODEX_APPROVAL_WAIT_S",
    "agent_name": "CONTEXTOS_CODEX_AGENT_NAME",
    "hook_timeout_s": "CONTEXTOS_CODEX_HOOK_TIMEOUT_S",
    "max_result_chars": "CONTEXTOS_CODEX_MAX_RESULT_CHARS",
}
PROJECT_DIR_ENV = "CONTEXTOS_CODEX_PROJECT_DIR"


@dataclass(frozen=True)
class CodexHookConfig:
    base: Config
    project_dir: Path
    agent_name: str
    fail_mode: str = DEFAULT_FAIL_MODE
    approval_wait_s: float = DEFAULT_APPROVAL_WAIT_S
    hook_timeout_s: float = DEFAULT_HOOK_TIMEOUT_S
    max_result_chars: int = DEFAULT_MAX_RESULT_CHARS
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def blocks_when_undecided(self) -> bool:
        """``closed`` and ``ask`` both block (Codex cannot ask); only ``open`` lets the call run."""
        return self.fail_mode != "open"

    @property
    def decide_budget_s(self) -> float:
        """Hard limit for a PreToolUse hook: always answer before Codex's own timeout.

        Codex treats a hook it had to kill (or one that crashed) as a failed hook and runs the tool,
        so the hook must produce its own answer, per the fail mode, first.
        """
        return max(2.0, self.hook_timeout_s - _HOOK_MARGIN_S)

    @property
    def effective_approval_wait_s(self) -> float:
        """Approval wait, capped so the decision request plus the wait fit in :attr:`decide_budget_s`."""
        room = self.decide_budget_s - self.base.timeout_s - 2.0
        return max(0.0, min(self.approval_wait_s, room))

    def describe(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "fail_mode": self.fail_mode,
            "approval_wait_s": self.effective_approval_wait_s,
            "hook_timeout_s": self.hook_timeout_s,
            "max_result_chars": self.max_result_chars,
            "project_dir": str(self.project_dir),
            "sources": dict(self.sources),
            "server": self.base.describe(),
        }


def default_agent_name(project_dir: Path) -> str:
    return f"codex@{project_dir.name or 'project'}"[:200]


def project_dir_for(cwd: str | os.PathLike[str] | None, env: Mapping[str, str] | None = None) -> Path:
    """The project a Codex hook runs for (see the module docstring)."""
    environ = os.environ if env is None else env
    override = (environ.get(PROJECT_DIR_ENV) or "").strip()
    if override and Path(override).expanduser().is_dir():
        return Path(override).expanduser().resolve()
    start = Path(cwd).expanduser() if cwd else Path.cwd()
    if not start.is_dir():
        return Path.cwd().resolve()
    start = start.resolve()
    user_file = user_config_path().resolve()
    for directory in (start, *start.parents):
        candidate = directory / PROJECT_DIR_NAME / CONFIG_FILE_NAME
        if candidate.is_file() and candidate.resolve() != user_file:
            return directory
    for directory in (start, *start.parents):
        if (directory / ".git").exists():
            return directory
    return start


def _section(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON (line {exc.lineno}): fix or delete it") from None
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc.strerror}") from None
    section = data.get(SECTION) if isinstance(data, dict) else None
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ConfigError(f"'{SECTION}' in {path} must be a JSON object")
    return {k: v for k, v in section.items() if k in _ENV}


def _number(name: str, raw: Any, *, minimum: float, maximum: float) -> float:
    if isinstance(raw, bool):
        raise ConfigError(f"{SECTION}.{name} must be a number, got {raw!r}")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{SECTION}.{name} must be a number, got {raw!r}") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{SECTION}.{name} must be between {minimum:g} and {maximum:g} (got {value:g})")
    return value


def _choice(name: str, raw: Any, choices: tuple[str, ...]) -> str:
    value = str(raw).strip().lower()
    if value not in choices:
        raise ConfigError(f"{SECTION}.{name} must be one of {', '.join(choices)} (got {raw!r})")
    return value


def fail_mode_from_env(env: Mapping[str, str] | None = None) -> str:
    """Fail mode when the configuration itself cannot be loaded: the env override, else ``closed``."""
    raw = (os.environ if env is None else env).get(_ENV["fail_mode"], "").strip().lower()
    return raw if raw in HOOK_FAIL_MODES else DEFAULT_FAIL_MODE


def load_hook_config(project_dir: Path, *, env: Mapping[str, str] | None = None) -> CodexHookConfig:
    """Resolve the SDK configuration plus the Codex hook settings for ``project_dir``."""
    environ = os.environ if env is None else env
    project = project_dir.resolve()
    base = load_config(project, env=dict(environ))
    layers: list[tuple[str, dict[str, Any]]] = [
        ("env", {k: environ[v] for k, v in _ENV.items() if environ.get(v, "").strip()}),
        ("project", _section(find_project_config(project))),
        ("user", _section(user_config_path())),
    ]
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for origin, layer in layers:
        for key, value in layer.items():
            if key not in values and value not in (None, ""):
                values[key] = value
                sources[key] = origin
    for key in _ENV:
        sources.setdefault(key, "default")

    agent_name = str(values.get("agent_name") or default_agent_name(project)).strip()[:200]
    if not agent_name:
        raise ConfigError(f"{SECTION}.agent_name must not be empty")
    max_chars = _number("max_result_chars", values.get("max_result_chars", DEFAULT_MAX_RESULT_CHARS),
                        minimum=1_000, maximum=200_000)
    return CodexHookConfig(
        base=base,
        project_dir=project,
        agent_name=agent_name,
        fail_mode=_choice("fail_mode", values.get("fail_mode", DEFAULT_FAIL_MODE), HOOK_FAIL_MODES),
        approval_wait_s=_number("approval_wait_s", values.get("approval_wait_s", DEFAULT_APPROVAL_WAIT_S),
                                minimum=0, maximum=3600),
        hook_timeout_s=_number("hook_timeout_s", values.get("hook_timeout_s", DEFAULT_HOOK_TIMEOUT_S),
                               minimum=5, maximum=600),
        max_result_chars=int(max_chars),
        sources=sources,
    )


__all__ = [
    "DEFAULT_APPROVAL_WAIT_S",
    "DEFAULT_FAIL_MODE",
    "DEFAULT_HOOK_TIMEOUT_S",
    "EVENT_BUDGET_S",
    "HOOK_FAIL_MODES",
    "MAX_STDIN_BYTES",
    "POLL_S",
    "PROJECT_DIR_ENV",
    "SECTION",
    "SESSION_END_BUDGET_S",
    "CodexHookConfig",
    "default_agent_name",
    "fail_mode_from_env",
    "load_hook_config",
    "project_dir_for",
]
