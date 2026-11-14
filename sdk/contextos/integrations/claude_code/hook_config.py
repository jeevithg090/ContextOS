"""Settings for the Claude Code hook.

The hook reuses the SDK configuration (server URL, API key, timeouts, environment, spool size; see
:mod:`contextos.config`) and adds a few settings of its own. Each one resolves in this order, and
the first match wins:

1. Environment: ``CONTEXTOS_HOOK_FAIL_MODE``, ``CONTEXTOS_HOOK_APPROVAL_WAIT_S``,
   ``CONTEXTOS_HOOK_ON_APPROVAL_TIMEOUT``, ``CONTEXTOS_HOOK_AGENT_NAME``, ``CONTEXTOS_HOOK_TIMEOUT_S``,
   ``CONTEXTOS_HOOK_MAX_RESULT_CHARS``
2. The ``"claude_code"`` object in the project file ``.contextos/config.json``
3. The ``"claude_code"`` object in the user file ``~/.contextos/config.json``
4. Defaults: fail mode ``ask``, approval wait 45 s, on approval timeout ``ask``, agent name
   ``claude-code@<project directory name>``, hook timeout 60 s, results cut at 60,000 characters

The general ``fail_mode`` setting is deliberately NOT used here: it governs ``guard()``, where no
human is at hand. Claude Code has its own permission prompt, so the hook defaults to ``ask`` — when
ContextOS cannot decide, the person at the keyboard does.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contextos.config import (
    Config,
    ConfigError,
    find_project_config,
    load_config,
    user_config_path,
)

SECTION = "claude_code"
HOOK_FAIL_MODES = ("closed", "open", "ask")
APPROVAL_TIMEOUT_ACTIONS = ("ask", "deny")

DEFAULT_FAIL_MODE = "ask"
DEFAULT_APPROVAL_WAIT_S = 45.0
DEFAULT_ON_APPROVAL_TIMEOUT = "ask"
DEFAULT_HOOK_TIMEOUT_S = 60.0  # what install_hooks writes for PreToolUse
DEFAULT_MAX_RESULT_CHARS = 60_000  # keeps one tool.completed event well under the server's 512 kB limit
EVENT_BUDGET_S = 8.0  # observation hooks (never block) give up after this long
POLL_S = 1.5
MAX_STDIN_BYTES = 8 * 1024 * 1024
_HOOK_MARGIN_S = 3.0  # answer this long before Claude Code would kill the hook

_ENV = {
    "fail_mode": "CONTEXTOS_HOOK_FAIL_MODE",
    "approval_wait_s": "CONTEXTOS_HOOK_APPROVAL_WAIT_S",
    "on_approval_timeout": "CONTEXTOS_HOOK_ON_APPROVAL_TIMEOUT",
    "agent_name": "CONTEXTOS_HOOK_AGENT_NAME",
    "hook_timeout_s": "CONTEXTOS_HOOK_TIMEOUT_S",
    "max_result_chars": "CONTEXTOS_HOOK_MAX_RESULT_CHARS",
}


@dataclass(frozen=True)
class HookConfig:
    base: Config
    project_dir: Path
    agent_name: str
    fail_mode: str = DEFAULT_FAIL_MODE
    approval_wait_s: float = DEFAULT_APPROVAL_WAIT_S
    on_approval_timeout: str = DEFAULT_ON_APPROVAL_TIMEOUT
    hook_timeout_s: float = DEFAULT_HOOK_TIMEOUT_S
    max_result_chars: int = DEFAULT_MAX_RESULT_CHARS
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def decide_budget_s(self) -> float:
        """Hard limit for a PreToolUse hook: always answer before Claude Code's own timeout.

        A hook that Claude Code kills counts as a non-blocking error and the tool would run, so the
        hook must produce its own answer (per the fail mode) first.
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
            "on_approval_timeout": self.on_approval_timeout,
            "hook_timeout_s": self.hook_timeout_s,
            "max_result_chars": self.max_result_chars,
            "sources": dict(self.sources),
            "server": self.base.describe(),
        }


def default_agent_name(project_dir: Path) -> str:
    return f"claude-code@{project_dir.name or 'project'}"[:200]


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


def hook_fail_mode_from_env(env: Mapping[str, str] | None = None) -> str:
    """Fail mode when the configuration itself cannot be loaded: the env override, else ``ask``."""
    raw = (os.environ if env is None else env).get(_ENV["fail_mode"], "").strip().lower()
    return raw if raw in HOOK_FAIL_MODES else DEFAULT_FAIL_MODE


def load_hook_config(project_dir: Path, *, env: Mapping[str, str] | None = None) -> HookConfig:
    """Resolve the SDK configuration plus the hook settings for ``project_dir``."""
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
    max_chars = _number(
        "max_result_chars",
        values.get("max_result_chars", DEFAULT_MAX_RESULT_CHARS),
        minimum=1_000,
        maximum=200_000,
    )
    return HookConfig(
        base=base,
        project_dir=project,
        agent_name=agent_name,
        fail_mode=_choice("fail_mode", values.get("fail_mode", DEFAULT_FAIL_MODE), HOOK_FAIL_MODES),
        approval_wait_s=_number(
            "approval_wait_s", values.get("approval_wait_s", DEFAULT_APPROVAL_WAIT_S), minimum=0, maximum=3600
        ),
        on_approval_timeout=_choice(
            "on_approval_timeout",
            values.get("on_approval_timeout", DEFAULT_ON_APPROVAL_TIMEOUT),
            APPROVAL_TIMEOUT_ACTIONS,
        ),
        hook_timeout_s=_number(
            "hook_timeout_s", values.get("hook_timeout_s", DEFAULT_HOOK_TIMEOUT_S), minimum=5, maximum=600
        ),
        max_result_chars=int(max_chars),
        sources=sources,
    )


__all__ = [
    "APPROVAL_TIMEOUT_ACTIONS",
    "DEFAULT_APPROVAL_WAIT_S",
    "DEFAULT_FAIL_MODE",
    "DEFAULT_HOOK_TIMEOUT_S",
    "EVENT_BUDGET_S",
    "HOOK_FAIL_MODES",
    "MAX_STDIN_BYTES",
    "POLL_S",
    "SECTION",
    "HookConfig",
    "default_agent_name",
    "hook_fail_mode_from_env",
    "load_hook_config",
]
