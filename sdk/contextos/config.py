"""SDK / CLI configuration.

Resolution order, per setting (first match wins):

1. Environment: ``CONTEXTOS_URL``, ``CONTEXTOS_API_KEY``, ``CONTEXTOS_AGENT_NAME``,
   ``CONTEXTOS_FAIL_MODE`` (``closed`` | ``open`` | ``ask``), ``CONTEXTOS_TIMEOUT_S``,
   ``CONTEXTOS_APPROVAL_TIMEOUT_S``, ``CONTEXTOS_ENVIRONMENT``.
2. Project file ``.contextos/config.json``, searched upward from the working directory.
3. User file ``~/.contextos/config.json`` (``CONTEXTOS_HOME`` overrides ``~/.contextos``).
4. Built-in defaults.

The API key is never logged or printed: ``repr(Config)`` and :func:`mask_key` show only its prefix.
Files that hold a key are written with mode 0600.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

FailMode = Literal["closed", "open", "ask"]
FAIL_MODES: tuple[str, ...] = ("closed", "open", "ask")

DEFAULT_URL = "http://localhost:8000"
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_APPROVAL_TIMEOUT_S = 300.0
PROJECT_DIR_NAME = ".contextos"
CONFIG_FILE_NAME = "config.json"

_ENV = {
    "url": "CONTEXTOS_URL",
    "api_key": "CONTEXTOS_API_KEY",
    "agent_name": "CONTEXTOS_AGENT_NAME",
    "fail_mode": "CONTEXTOS_FAIL_MODE",
    "timeout_s": "CONTEXTOS_TIMEOUT_S",
    "approval_timeout_s": "CONTEXTOS_APPROVAL_TIMEOUT_S",
    "environment": "CONTEXTOS_ENVIRONMENT",
}
FILE_KEYS = frozenset(_ENV) | {"spool_max_bytes"}


class ConfigError(ValueError):
    """A configuration file or value is invalid (message never contains the API key)."""


def mask_key(key: str | None) -> str:
    """``ctxk_abc…`` — enough to tell keys apart, never enough to use one."""
    if not key:
        return "(not set)"
    if len(key) <= 12:
        return "****"
    return key[:8] + "…"


def contextos_home() -> Path:
    """Directory for user-level state: ``$CONTEXTOS_HOME`` or ``~/.contextos``."""
    override = os.environ.get("CONTEXTOS_HOME")
    return Path(override).expanduser() if override else Path.home() / PROJECT_DIR_NAME


def user_config_path() -> Path:
    return contextos_home() / CONFIG_FILE_NAME


def find_project_config(start: Path | None = None) -> Path | None:
    """Nearest ``.contextos/config.json`` at or above ``start`` (the user-level file is excluded)."""
    here = (start or Path.cwd()).resolve()
    user_file = user_config_path().resolve()
    for directory in (here, *here.parents):
        candidate = directory / PROJECT_DIR_NAME / CONFIG_FILE_NAME
        if candidate.is_file() and candidate.resolve() != user_file:
            return candidate
    return None


def read_config_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON (line {exc.lineno}): fix or delete it") from None
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc.strerror}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return {k: v for k, v in data.items() if k in FILE_KEYS}


def write_config_file(path: Path, values: dict[str, Any], *, merge: bool = True) -> Path:
    """Atomically write (or merge into) a config file. Mode 0600 when it contains an API key."""
    current: dict[str, Any] = {}
    if merge and path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            raise ConfigError(f"{path} is not valid JSON; fix or delete it before writing") from None
        current = loaded if isinstance(loaded, dict) else {}
    current.update({k: v for k, v in values.items() if v is not None})
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config.", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600 if current.get("api_key") else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(current, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def _as_float(name: str, raw: Any) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ConfigError(f"{name} must be greater than 0")
    return value


@dataclass(frozen=True)
class Config:
    url: str = DEFAULT_URL
    api_key: str | None = field(default=None, repr=False)
    agent_name: str | None = None
    fail_mode: FailMode = "closed"
    timeout_s: float = DEFAULT_TIMEOUT_S
    approval_timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S
    environment: str | None = None
    spool_max_bytes: int = 5 * 1024 * 1024
    project_file: Path | None = None
    user_file: Path | None = None
    sources: dict[str, str] = field(default_factory=dict)  # setting -> "env" | "project" | "user" | "default"

    @property
    def api_key_masked(self) -> str:
        return mask_key(self.api_key)

    def __repr__(self) -> str:  # explicit so the key can never leak through a default repr
        return (
            f"Config(url={self.url!r}, api_key={self.api_key_masked!r}, agent_name={self.agent_name!r}, "
            f"fail_mode={self.fail_mode!r}, timeout_s={self.timeout_s}, project_file={self.project_file})"
        )

    def describe(self) -> dict[str, Any]:
        """Display-safe summary (key masked)."""
        return {
            "url": self.url,
            "api_key": self.api_key_masked,
            "agent_name": self.agent_name,
            "fail_mode": self.fail_mode,
            "timeout_s": self.timeout_s,
            "approval_timeout_s": self.approval_timeout_s,
            "environment": self.environment,
            "project_file": str(self.project_file) if self.project_file else None,
            "user_file": str(self.user_file) if self.user_file else None,
            "sources": dict(self.sources),
        }


def load_config(cwd: Path | None = None, *, env: dict[str, str] | None = None) -> Config:
    """Resolve configuration from environment, project file and user file (see module docstring)."""
    environ = os.environ if env is None else env
    project_path = find_project_config(cwd)
    user_path = user_config_path()
    layers: list[tuple[str, dict[str, Any]]] = []
    layers.append(("env", {k: environ[v] for k, v in _ENV.items() if environ.get(v)}))
    if project_path is not None:
        layers.append(("project", read_config_file(project_path)))
    if user_path.is_file():
        layers.append(("user", read_config_file(user_path)))

    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for origin, layer in layers:
        for key, value in layer.items():
            if key not in values and value not in (None, ""):
                values[key] = value
                sources[key] = origin

    fail_mode = str(values.get("fail_mode", "closed")).strip().lower()
    if fail_mode not in FAIL_MODES:
        raise ConfigError(f"fail_mode must be one of {', '.join(FAIL_MODES)} (got {fail_mode!r})")
    url = str(values.get("url", DEFAULT_URL)).strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ConfigError(f"url must start with http:// or https:// (got {url!r})")
    api_key = values.get("api_key")
    if api_key is not None and not isinstance(api_key, str):
        raise ConfigError("api_key must be a string")
    spool_max = values.get("spool_max_bytes", 5 * 1024 * 1024)
    if isinstance(spool_max, bool) or not isinstance(spool_max, int) or spool_max < 1024:
        raise ConfigError("spool_max_bytes must be an integer >= 1024")
    for key in _ENV:
        sources.setdefault(key, "default")
    return Config(
        url=url,
        api_key=api_key.strip() if isinstance(api_key, str) else None,
        agent_name=str(values["agent_name"]).strip() if values.get("agent_name") else None,
        fail_mode=fail_mode,  # type: ignore[arg-type]
        timeout_s=_as_float("timeout_s", values.get("timeout_s", DEFAULT_TIMEOUT_S)),
        approval_timeout_s=_as_float(
            "approval_timeout_s", values.get("approval_timeout_s", DEFAULT_APPROVAL_TIMEOUT_S)
        ),
        environment=str(values["environment"]) if values.get("environment") else None,
        spool_max_bytes=spool_max,
        project_file=project_path,
        user_file=user_path if user_path.is_file() else None,
        sources=sources,
    )


__all__ = [
    "CONFIG_FILE_NAME",
    "DEFAULT_URL",
    "FAIL_MODES",
    "PROJECT_DIR_NAME",
    "Config",
    "ConfigError",
    "FailMode",
    "contextos_home",
    "find_project_config",
    "load_config",
    "mask_key",
    "read_config_file",
    "user_config_path",
    "write_config_file",
]
