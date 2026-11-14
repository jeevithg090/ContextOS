"""install_hooks / uninstall_hooks / hooks_status on temporary projects (never the real ~/.claude)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from contextos.cli import app
from contextos.integrations.claude_code import install as inst
from contextos.integrations.claude_code.install import (
    apply_hooks,
    hooks_status,
    install_hooks,
    is_contextos_hook,
    settings_path,
    uninstall_hooks,
)

EVENTS = [
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "SessionStart",
    "SubagentStop",
    "SessionEnd",
]
USER_HOOK = {"type": "command", "command": "./scripts/lint.sh", "timeout": 30}
EXISTING = {
    "permissions": {"allow": ["Bash(npm test)"], "deny": ["Read(./.env)"]},
    "model": "opus",
    "hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [USER_HOOK]}],
        "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}],
    },
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "ctxhome"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    path = tmp_path / "shop-api"
    path.mkdir()
    return path


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def ours(settings: dict, event: str) -> list[dict]:
    return [h for g in settings["hooks"].get(event, []) for h in g.get("hooks", []) if is_contextos_hook(h)]


def test_fresh_install_writes_every_event_with_an_absolute_command(project: Path) -> None:
    path = install_hooks(project)
    assert path == project / ".claude" / "settings.json"
    settings = read(path)
    assert sorted(settings["hooks"]) == sorted(EVENTS)
    pre = settings["hooks"]["PreToolUse"][0]
    assert pre["matcher"] == "*"
    handler = pre["hooks"][0]
    assert handler["type"] == "command" and handler["timeout"] == 60
    assert handler["command"].endswith(" -m contextos hook PreToolUse")
    assert sys.executable in handler["command"]
    assert handler["statusMessage"] == "ContextOS policy check"
    assert settings["hooks"]["PostToolUse"][0]["matcher"] == "*"
    assert "matcher" not in settings["hooks"]["UserPromptSubmit"][0]
    assert settings["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"] == 15


def test_install_merges_without_clobbering_and_backs_up_the_original(project: Path) -> None:
    path = settings_path(project)
    path.parent.mkdir()
    original = json.dumps(EXISTING, indent=4)
    path.write_text(original)
    report = apply_hooks(project, command="/opt/ctx/bin/contextos")
    settings = read(path)
    assert report.changed and report.backup == path.with_name("settings.json.contextos-backup")
    assert report.backup.read_text() == original
    assert settings["permissions"] == EXISTING["permissions"] and settings["model"] == "opus"
    assert settings["hooks"]["Stop"] == EXISTING["hooks"]["Stop"]
    assert settings["hooks"]["PreToolUse"][0] == {
        "matcher": "Bash",
        "hooks": [USER_HOOK],
    }  # user's hook kept first
    assert ours(settings, "PreToolUse")[0]["command"] == "/opt/ctx/bin/contextos hook PreToolUse"


def test_install_is_idempotent(project: Path) -> None:
    first = apply_hooks(project, command="contextos")
    before = settings_path(project).read_bytes()
    second = apply_hooks(project, command="contextos")
    assert first.changed and not second.changed
    assert settings_path(project).read_bytes() == before
    assert all(len(ours(read(settings_path(project)), e)) == 1 for e in EVENTS)


def test_reinstall_with_a_new_command_replaces_ours_only(project: Path) -> None:
    apply_hooks(project, command="/old/contextos")
    path = settings_path(project)
    settings = read(path)
    settings["hooks"]["PreToolUse"].insert(0, {"matcher": "Bash", "hooks": [USER_HOOK]})
    path.write_text(json.dumps(settings))
    apply_hooks(project, command="/new/contextos", timeout=90)
    settings = read(path)
    handlers = ours(settings, "PreToolUse")
    assert [h["command"] for h in handlers] == ["/new/contextos hook PreToolUse"]
    assert handlers[0]["timeout"] == 90
    assert {"matcher": "Bash", "hooks": [USER_HOOK]} in settings["hooks"]["PreToolUse"]


def test_our_handler_in_a_shared_group_is_moved_out_and_theirs_kept(project: Path) -> None:
    path = settings_path(project)
    path.parent.mkdir()
    shared = {
        "matcher": "*",
        "hooks": [USER_HOOK, {"type": "command", "command": "contextos hook PreToolUse"}],
    }
    path.write_text(json.dumps({"hooks": {"PreToolUse": [shared]}}))
    apply_hooks(project, command="contextos")
    groups = read(path)["hooks"]["PreToolUse"]
    assert groups[0] == {"matcher": "*", "hooks": [USER_HOOK]}
    assert len(ours(read(path), "PreToolUse")) == 1


def test_uninstall_removes_only_contextos_hooks(project: Path) -> None:
    path = settings_path(project)
    path.parent.mkdir()
    path.write_text(json.dumps(EXISTING))
    apply_hooks(project)
    report = uninstall_hooks(project)
    assert report.changed and sorted(report.events) == sorted(EVENTS)
    assert read(path) == EXISTING
    assert not uninstall_hooks(project).changed  # nothing left to remove


def test_uninstall_drops_the_hooks_key_when_only_ours_were_there(project: Path) -> None:
    apply_hooks(project)
    uninstall_hooks(project)
    assert read(settings_path(project)) == {}


@pytest.mark.parametrize(
    ("scope", "relative"), [("local", ".claude/settings.local.json"), ("project", ".claude/settings.json")]
)
def test_project_scopes(project: Path, scope: str, relative: str) -> None:
    assert install_hooks(project, scope) == project / relative


def test_user_scope_writes_under_the_given_home(project: Path, tmp_path: Path) -> None:
    path = install_hooks(project, "user", home=tmp_path / "fakehome")
    assert path == tmp_path / "fakehome" / ".claude" / "settings.json"
    assert hooks_status(project, home=tmp_path / "fakehome")["scopes"]["user"]["events"] == sorted(EVENTS)


def test_claude_config_dir_is_honoured_for_user_scope(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfgdir"))
    assert settings_path(project, "user") == tmp_path / "cfgdir" / "settings.json"


def test_invalid_scope_and_timeout_are_rejected(project: Path) -> None:
    with pytest.raises(ValueError, match="scope"):
        install_hooks(project, "global")
    with pytest.raises(ValueError, match="timeout"):
        install_hooks(project, timeout=5)


@pytest.mark.parametrize(
    "content", ["{not json", json.dumps({"hooks": []}), json.dumps({"hooks": {"PreToolUse": {}}})]
)
def test_malformed_settings_are_never_overwritten(project: Path, content: str) -> None:
    path = settings_path(project)
    path.parent.mkdir()
    path.write_text(content)
    with pytest.raises(ValueError):
        install_hooks(project)
    assert path.read_text() == content


def test_recognises_contextos_commands_only() -> None:
    assert is_contextos_hook({"type": "command", "command": "contextos hook PreToolUse"}) == "PreToolUse"
    assert (
        is_contextos_hook({"type": "command", "command": "/usr/bin/python3 -m contextos hook SessionEnd"})
        == "SessionEnd"
    )
    assert (
        is_contextos_hook({"type": "command", "command": "'/a b/contextos' hook PostToolUse"})
        == "PostToolUse"
    )
    assert is_contextos_hook({"type": "command", "command": "./scripts/mycontextos hook PreToolUse"}) is None
    assert is_contextos_hook({"type": "command", "command": "echo contextos hook PreToolUse && rm x"}) is None
    assert is_contextos_hook({"type": "prompt", "prompt": "contextos hook PreToolUse"}) is None


# -- status ----------------------------------------------------------------------------------------


def test_status_when_nothing_is_installed(project: Path, tmp_path: Path) -> None:
    status = hooks_status(project, home=tmp_path / "fakehome")
    assert status["installed"] is False and "not installed" in status["detail"]


def test_status_when_installed(project: Path, tmp_path: Path) -> None:
    install_hooks(project)
    status = hooks_status(project, home=tmp_path / "fakehome")
    assert status["installed"] is True and status["ok"] is True
    assert status["detail"] == "enforcing via PreToolUse (project scope)"
    assert status["scopes"]["project"]["pre_tool_use_timeout"] == 60


def test_status_flags_a_command_that_cannot_start(project: Path, tmp_path: Path) -> None:
    apply_hooks(project, command="/nonexistent/venv/bin/contextos")
    status = hooks_status(project, home=tmp_path / "fakehome")
    assert status["installed"] is False and status["ok"] is False
    assert "cannot be started" in status["detail"]


def test_status_flags_disable_all_hooks(project: Path, tmp_path: Path) -> None:
    install_hooks(project)
    local = settings_path(project, "local")
    local.write_text(json.dumps({"disableAllHooks": True}))
    status = hooks_status(project, home=tmp_path / "fakehome")
    assert status["installed"] is False and "disableAllHooks" in status["detail"]


def test_status_reports_observation_only_installs(project: Path, tmp_path: Path) -> None:
    install_hooks(project)
    path = settings_path(project)
    settings = read(path)
    del settings["hooks"]["PreToolUse"]
    path.write_text(json.dumps(settings))
    status = hooks_status(project, home=tmp_path / "fakehome")
    assert status["installed"] is False and "PreToolUse (enforcement) is not installed" in status["detail"]


# -- command-line entry points ---------------------------------------------------------------------


def test_module_cli_install_status_uninstall(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert inst._cli(["install", "--project-dir", str(project)]) == 0
    assert "updated" in capsys.readouterr().out
    assert inst._cli(["status", "--project-dir", str(project)]) == 0
    assert json.loads(capsys.readouterr().out)["installed"] is True
    assert inst._cli(["uninstall", "--project-dir", str(project)]) == 0
    assert "Removed ContextOS hooks" in capsys.readouterr().out


def test_contextos_init_claude_code_installs_the_hooks(project: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "init",
            "--url",
            "http://localhost:18999",
            "--api-key",
            "ctxk_test_0123456789abcdefghijklmnop",
            "--skip-verify",
            "--claude-code",
            "--project-dir",
            str(project),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Claude Code hooks installed" in result.output
    assert ours(read(settings_path(project)), "PreToolUse")
