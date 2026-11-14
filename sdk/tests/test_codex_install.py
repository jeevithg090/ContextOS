"""Installing the Codex hooks into hooks.json, their status for ``contextos doctor``, and the CLI wiring."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from contextos._cli import common, delegates
from contextos.cli import app
from contextos.client import ContextOSClient
from contextos.integrations.codex import install
from contextos.spool import Spool

from .sdk_fakes import API_KEY, BASE_URL, FakeServer

runner = CliRunner(env={"COLUMNS": "240"})
CMD = "/opt/venv/bin/python -m contextos"


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(install, "login_shell_prints_to_stdout", lambda *a, **k: False)
    return tmp_path / "home"


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def user_hooks(home: Path) -> Path:
    return home / ".codex" / "hooks.json"


def test_install_writes_every_event_with_codex_limits(project: Path, home: Path) -> None:
    report = install.apply_hooks(project, "user", command=CMD, home=home)
    assert report.changed and report.path == user_hooks(home)
    data = json.loads(report.path.read_text())
    assert set(data) == {"hooks"}  # Codex's HooksFile rejects unknown top-level keys
    hooks = data["hooks"]
    assert set(hooks) == {
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SessionStart",
        "SubagentStop",
        "SessionEnd",
    }
    assert hooks["PreToolUse"] == [
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{CMD} codex-hook PreToolUse",
                    "timeout": 60,
                    "statusMessage": "ContextOS policy check",
                }
            ],
        }
    ]
    assert hooks["SessionEnd"][0]["hooks"][0]["timeout"] == 3 and "matcher" not in hooks["SessionEnd"][0]
    assert hooks["PostToolUse"][0]["hooks"][0]["timeout"] == 15
    assert any("/hooks" in w for w in report.warnings)  # trust is the user's step, in Codex


def test_install_preserves_user_hooks_and_their_position(project: Path, home: Path) -> None:
    path = user_hooks(home)
    path.parent.mkdir(parents=True)
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 policy.py", "timeout": 30}]}
    path.write_text(json.dumps({"description": "team hooks", "hooks": {"PreToolUse": [mine]}}))
    install.apply_hooks(project, "user", command=CMD, home=home)
    data = json.loads(path.read_text())
    assert data["description"] == "team hooks"
    assert data["hooks"]["PreToolUse"][0] == mine  # index 0 kept: Codex's recorded trust for it stays valid
    assert install.is_contextos_hook(data["hooks"]["PreToolUse"][1]["hooks"][0]) == "PreToolUse"
    backup = path.with_name("hooks.json.contextos-backup")
    assert json.loads(backup.read_text())["hooks"]["PreToolUse"] == [mine]


def test_install_is_idempotent_and_updates_in_place(project: Path, home: Path) -> None:
    install.apply_hooks(project, "user", command=CMD, home=home)
    path = user_hooks(home)
    before = path.read_text()
    assert not install.apply_hooks(project, "user", command=CMD, home=home).changed
    assert path.read_text() == before
    data = json.loads(before)
    later = {"hooks": [{"type": "command", "command": "python3 audit.py"}]}
    data["hooks"]["PreToolUse"].append(later)  # the user added a hook after ours
    path.write_text(json.dumps(data))
    install.apply_hooks(project, "user", command="/new/python -m contextos", home=home)
    groups = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert groups[0]["hooks"][0]["command"] == "/new/python -m contextos codex-hook PreToolUse"
    assert groups[1] == later  # still at index 1


def test_project_scope_and_invalid_input(project: Path, home: Path) -> None:
    report = install.apply_hooks(project, "project", command=CMD, home=home)
    assert report.path == project.resolve() / ".codex" / "hooks.json"
    assert any("trusts the project" in w for w in report.warnings)
    with pytest.raises(ValueError, match="scope"):
        install.hooks_path(project, "local")
    with pytest.raises(ValueError, match="timeout"):
        install.apply_hooks(project, "user", command=CMD, timeout=5, home=home)
    bad = user_hooks(home)
    bad.parent.mkdir(parents=True)
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        install.apply_hooks(project, "user", command=CMD, home=home)
    bad.write_text(json.dumps({"hooks": {"PreToolUse": {"oops": 1}}}))
    with pytest.raises(ValueError, match="not a list"):
        install.apply_hooks(project, "user", command=CMD, home=home)


def test_uninstall_removes_only_contextos_hooks(project: Path, home: Path) -> None:
    path = user_hooks(home)
    path.parent.mkdir(parents=True)
    mine = {"hooks": [{"type": "command", "command": "python3 notify.py"}]}
    path.write_text(json.dumps({"hooks": {"Stop": [mine]}}))
    install.apply_hooks(project, "user", command=CMD, home=home)
    report = install.uninstall_hooks(project, "user", home=home)
    assert report.changed and "PreToolUse" in report.events
    assert json.loads(path.read_text()) == {"hooks": {"Stop": [mine]}}
    assert not install.uninstall_hooks(project, "user", home=home).changed


def _trust(home: Path, keys: dict[str, dict], extra: str = "") -> None:
    lines = [extra]
    for key, state in keys.items():
        lines.append(f'[hooks.state."{key}"]')
        lines += [f"{k} = {json.dumps(v)}" for k, v in state.items()]
    (home / ".codex" / "config.toml").write_text("\n".join(lines) + "\n")


def test_status_reports_trust_recorded_by_codex(project: Path, home: Path, tmp_path: Path) -> None:
    exe = tmp_path / "bin" / "python"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    command = f"{exe} -m contextos"
    report = install.apply_hooks(project, "user", command=command, home=home)
    status = install.hooks_status(project, home=home)
    assert not status["installed"] and status["ok"] and status["warning"]
    assert "Codex skips untrusted hooks" in status["detail"]

    events = [e for e, _, _ in install.HOOK_EVENTS]
    labels = {e: label for e, _, label in install.HOOK_EVENTS}
    _trust(home, {f"{report.path}:{labels[e]}:0:0": {"trusted_hash": "sha256:x"} for e in events})
    status = install.hooks_status(project, home=home)
    assert status["installed"] and status["ok"] and not status["warning"]
    assert status["detail"].startswith("enforcing via PreToolUse (user scope; trusted in Codex)")
    assert status["scopes"]["user"]["trust"]["PreToolUse"] == "trusted"

    _trust(
        home,
        {
            f"{report.path}:pre_tool_use:0:0": {"trusted_hash": "sha256:x"},
            f"{report.path}:post_tool_use:0:0": {"trusted_hash": "sha256:x", "enabled": False},
        },
    )
    status = install.hooks_status(project, home=home)
    assert status["installed"] and status["warning"] and "not yet trusted in /hooks" in status["detail"]
    assert status["scopes"]["user"]["trust"]["PostToolUse"] == "disabled"


def test_status_errors_when_codex_would_not_run_the_hooks(project: Path, home: Path, tmp_path: Path) -> None:
    install.apply_hooks(project, "user", command="/missing/python -m contextos", home=home)
    status = install.hooks_status(project, home=home)
    assert not status["ok"] and "cannot be started" in status["detail"]

    install.apply_hooks(project, "user", command=f"{sys.executable} -m contextos", home=home)
    _trust(home, {}, extra="[features]\nhooks = false")
    status = install.hooks_status(project, home=home)
    assert not status["ok"] and "[features] hooks = false" in status["detail"]

    install.uninstall_hooks(project, "user", home=home)
    report = install.apply_hooks(project, "project", command=f"{sys.executable} -m contextos", home=home)
    _trust(
        home,
        {f"{report.path}:pre_tool_use:0:0": {"trusted_hash": "sha256:x"}},
        extra=f'[projects."{project.resolve()}"]\ntrust_level = "untrusted"',
    )
    status = install.hooks_status(project, home=home)
    assert status["project_trust"] == "untrusted" and not status["ok"]
    assert "project hooks do not load" in status["detail"]


def test_status_warns_when_the_login_shell_prints_to_stdout(
    project: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = install.apply_hooks(project, "user", command=f"{sys.executable} -m contextos", home=home)
    _trust(home, {f"{report.path}:pre_tool_use:0:0": {"trusted_hash": "sha256:x"}})
    monkeypatch.setattr(install, "login_shell_prints_to_stdout", lambda *a, **k: True)
    status = install.hooks_status(project, home=home)
    assert status["ok"] and status["warning"] and "RESTRICT rewrites would not apply" in status["detail"]


def test_login_shell_check_runs_the_real_shell(tmp_path: Path) -> None:
    quiet = tmp_path / "quiet.sh"
    quiet.write_text("#!/bin/sh\nexit 0\n")
    noisy = tmp_path / "noisy.sh"
    noisy.write_text("#!/bin/sh\necho 'Welcome back!'\n")
    for script in (quiet, noisy):
        script.chmod(0o755)
    from contextos.integrations.codex.install import (
        login_shell_prints_to_stdout as real_check,
    )

    assert real_check({"SHELL": str(quiet), "PATH": "/usr/bin:/bin"}) is False
    assert real_check({"SHELL": str(noisy), "PATH": "/usr/bin:/bin"}) is True
    assert real_check({"SHELL": str(tmp_path / "missing")}) is None


# -- CLI -------------------------------------------------------------------------------------------


@pytest.fixture()
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    fake = FakeServer()
    ctx_home = tmp_path / "ctxhome"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("CONTEXTOS_HOME", str(ctx_home))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setattr(install, "login_shell_prints_to_stdout", lambda *a, **k: False)
    for var in ("CONTEXTOS_URL", "CONTEXTOS_API_KEY", "CONTEXTOS_AGENT_NAME", "CONTEXTOS_FAIL_MODE"):
        monkeypatch.delenv(var, raising=False)

    def factory(cfg):
        return ContextOSClient(
            cfg.url,
            cfg.api_key,
            transport=fake.transport(),
            sleep=lambda _s: None,
            spool=Spool(ctx_home / "spool" / "cli.jsonl"),
        )

    monkeypatch.setattr(common, "client_factory", factory)
    fake.route("GET", "/api/v1/agents", {"items": [], "total": 0, "limit": 1, "offset": 0})
    fake.route(
        "POST", "/api/v1/events", {"error": {"code": "validation_failed", "message": "empty"}}, status=422
    )
    fake.route(
        "POST", "/api/v1/decide", {"error": {"code": "validation_failed", "message": "empty"}}, status=422
    )
    return fake


def test_init_codex_installs_the_hooks_and_explains_trust(server: FakeServer, tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--codex"])
    assert result.exit_code == 0, result.output
    assert "Codex hooks installed (project scope)" in result.output and "/hooks" in result.output
    hooks = json.loads((tmp_path / "work" / ".codex" / "hooks.json").read_text())["hooks"]
    command = hooks["PreToolUse"][0]["hooks"][0]["command"]
    assert command.endswith(" -m contextos codex-hook PreToolUse") and sys.executable in command
    assert API_KEY not in result.output

    user = runner.invoke(app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--codex", "--scope", "user"])
    assert user.exit_code == 0, user.output
    assert (tmp_path / "codex-home" / "hooks.json").is_file()


def test_init_codex_rejects_the_claude_only_local_scope_before_writing(
    server: FakeServer, tmp_path: Path
) -> None:
    result = runner.invoke(
        app, ["init", "--url", BASE_URL, "--api-key", API_KEY, "--codex", "--scope", "local"]
    )
    assert result.exit_code == 1 and "--scope for --codex" in result.output
    assert not (tmp_path / "work" / ".contextos").exists()


def test_doctor_reports_the_codex_hooks(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CONTEXTOS_URL", BASE_URL)
    monkeypatch.setenv("CONTEXTOS_API_KEY", API_KEY)
    result = runner.invoke(app, ["doctor"])
    assert "Codex hooks" in result.output and "contextos init --codex" in result.output
    install.apply_hooks(tmp_path / "work", "project", command="/missing/python -m contextos")
    broken = runner.invoke(app, ["doctor"])
    assert broken.exit_code == 1 and "cannot be started" in broken.output


def test_codex_hook_command_delegates_and_fails_closed_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    import types

    fake = types.ModuleType("contextos.integrations.codex.hook")
    fake.main = lambda event_name: seen.append(event_name) or 2
    monkeypatch.setitem(sys.modules, "contextos.integrations.codex.hook", fake)
    result = runner.invoke(app, ["codex-hook", "PreToolUse"])
    assert seen == ["PreToolUse"] and result.exit_code == 2
    monkeypatch.delitem(sys.modules, "contextos.integrations.codex.hook")

    def missing(name: str):
        raise ModuleNotFoundError(f"No module named {name!r}", name="contextos.integrations.codex")

    monkeypatch.setattr(delegates.importlib, "import_module", missing)
    pre = runner.invoke(app, ["codex-hook", "PreToolUse"])
    # Codex blocks on exit 2 only when stderr carries a reason: both are required.
    assert pre.exit_code == delegates.CODEX_BLOCK_EXIT == 2 and "blocked (fail closed)" in pre.output
    assert runner.invoke(app, ["codex-hook", "PostToolUse"]).exit_code == 0
