"""Configuration resolution (env > project file > user file > defaults) and key masking."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from contextos.config import ConfigError, load_config, mask_key, write_config_file

KEY = "ctxk_abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    monkeypatch.setenv("CONTEXTOS_HOME", str(h))
    for var in (
        "CONTEXTOS_URL",
        "CONTEXTOS_API_KEY",
        "CONTEXTOS_AGENT_NAME",
        "CONTEXTOS_FAIL_MODE",
        "CONTEXTOS_TIMEOUT_S",
        "CONTEXTOS_APPROVAL_TIMEOUT_S",
        "CONTEXTOS_ENVIRONMENT",
    ):
        monkeypatch.delenv(var, raising=False)
    return h


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_defaults_when_nothing_is_configured(home: Path, tmp_path: Path) -> None:
    cfg = load_config(tmp_path, env={})
    assert cfg.url == "http://localhost:8000"
    assert cfg.api_key is None and cfg.fail_mode == "closed"
    assert cfg.sources["url"] == "default"


def test_precedence_env_over_project_over_user(home: Path, tmp_path: Path) -> None:
    project = tmp_path / "repo"
    nested = project / "src" / "pkg"
    nested.mkdir(parents=True)
    _write(
        home / "config.json",
        {"url": "http://user:1", "api_key": KEY, "agent_name": "user-agent", "fail_mode": "ask"},
    )
    _write(project / ".contextos" / "config.json", {"url": "http://project:2", "agent_name": "project-agent"})

    cfg = load_config(nested, env={"CONTEXTOS_AGENT_NAME": "env-agent"})
    assert cfg.agent_name == "env-agent" and cfg.sources["agent_name"] == "env"
    assert cfg.url == "http://project:2" and cfg.sources["url"] == "project"  # found by searching upward
    assert cfg.api_key == KEY and cfg.sources["api_key"] == "user"
    assert cfg.fail_mode == "ask"
    assert cfg.project_file == project / ".contextos" / "config.json"


def test_invalid_values_are_rejected_with_a_clear_message(home: Path, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="fail_mode"):
        load_config(tmp_path, env={"CONTEXTOS_FAIL_MODE": "sometimes"})
    with pytest.raises(ConfigError, match="http"):
        load_config(tmp_path, env={"CONTEXTOS_URL": "ftp://x"})
    _write(tmp_path / ".contextos" / "config.json", {"url": "http://x"})
    (tmp_path / ".contextos" / "config.json").write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(tmp_path, env={})


def test_api_key_is_masked_everywhere(home: Path, tmp_path: Path) -> None:
    cfg = load_config(tmp_path, env={"CONTEXTOS_API_KEY": KEY})
    assert mask_key(KEY) == "ctxk_abc…"
    assert KEY not in repr(cfg) and KEY not in str(cfg.describe())
    assert mask_key(None) == "(not set)" and mask_key("short") == "****"


def test_write_config_file_uses_0600_when_it_holds_a_key(tmp_path: Path) -> None:
    path = write_config_file(tmp_path / "a" / "config.json", {"url": "http://x", "api_key": KEY})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    write_config_file(path, {"agent_name": "bot"})  # merge keeps the key
    data = json.loads(path.read_text())
    assert data == {"url": "http://x", "api_key": KEY, "agent_name": "bot"}
    plain = write_config_file(tmp_path / "b" / "config.json", {"url": "http://x"})
    assert stat.S_IMODE(plain.stat().st_mode) == 0o644
