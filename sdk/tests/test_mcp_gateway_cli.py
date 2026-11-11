"""``contextos mcp-gateway`` argument handling, configuration checks and upstream environment."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("mcp")

from contextos.integrations.mcp_gateway import cli  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))
    for name in ("CONTEXTOS_API_KEY", "CONTEXTOS_URL", "CONTEXTOS_FAIL_MODE", "CONTEXTOS_AGENT_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize("argv", [
    ["--name", "notes", "--", "python", "server.py", "--flag"],
    ["--name", "notes", "python", "server.py", "--flag"],  # `contextos` (Click) drops the first "--"
    ["--name=notes", "python", "server.py", "--flag"],
])
def test_the_upstream_command_starts_after_the_gateway_options(argv: list[str]) -> None:
    invocation = cli.parse(argv)
    assert invocation.options.name == "notes" and invocation.command == ["python", "server.py", "--flag"]


def test_options_with_values_and_flags() -> None:
    invocation = cli.parse(["--name", "gh", "--agent", "claude-code", "--fail-mode", "open", "--approval-timeout", "30",
                            "--hide-blocked-tools", "--no-context-reports", "npx", "-y", "server", "--", "x"])
    opts = invocation.options
    assert (opts.agent, opts.fail_mode, opts.approval_timeout) == ("claude-code", "open", 30.0)
    assert opts.hide_blocked_tools and opts.no_context_reports
    assert invocation.command == ["npx", "-y", "server", "--", "x"]


def test_usage_errors_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--name", "notes"]) == cli.EXIT_USAGE  # no upstream command
    assert "no upstream MCP server command" in capsys.readouterr().err
    assert cli.main(["--name", "notes", "--bogus", "python", "s.py"]) == cli.EXIT_USAGE
    assert "unknown gateway option '--bogus'" in capsys.readouterr().err
    assert cli.main(["python", "s.py"]) == cli.EXIT_USAGE  # --name is required
    assert cli.main(["--name", "a/b", "python", "s.py"]) == cli.EXIT_USAGE  # would be attributed to server "a"
    assert cli.main(["--name", "notes", "--fail-mode", "maybe", "python", "s.py"]) == cli.EXIT_USAGE


def test_help_exits_0_and_documents_the_form(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "contextos mcp-gateway --name NAME [options] -- COMMAND [ARGS...]" in out and "--fail-mode" in out


def test_refuses_to_start_without_an_api_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--name", "notes", "python", "s.py"]) == cli.EXIT_ERROR
    assert "No ContextOS API key" in capsys.readouterr().err


def test_invalid_configuration_is_reported(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("CONTEXTOS_API_KEY", "ctxk_test_key_0123456789")
    monkeypatch.setenv("CONTEXTOS_URL", "ftp://nope")
    assert cli.main(["--name", "notes", "python", "s.py"]) == cli.EXIT_ERROR
    assert "Invalid ContextOS configuration" in capsys.readouterr().err


def test_a_missing_upstream_command_is_a_clear_error(monkeypatch: pytest.MonkeyPatch,
                                                     capfd: pytest.CaptureFixture[str]) -> None:
    # capfd: the upstream's stderr is wired to the gateway's real stderr file descriptor
    monkeypatch.setenv("CONTEXTOS_API_KEY", "ctxk_test_key_0123456789")
    monkeypatch.setenv("CONTEXTOS_URL", "http://127.0.0.1:9")
    code = cli.main(["--name", "notes", "--startup-timeout", "20", "definitely-not-a-command-xyz"])
    assert code == cli.EXIT_ERROR
    assert "Cannot start the upstream MCP server 'definitely-not-a-command-xyz'" in capfd.readouterr().err


def test_upstream_never_inherits_contextos_settings() -> None:
    env = cli.upstream_environment({"PATH": "/bin", "CONTEXTOS_API_KEY": "ctxk_secret", "contextos_url": "x",
                                    "GITHUB_TOKEN": "kept-for-the-upstream"})
    assert env == {"PATH": "/bin", "GITHUB_TOKEN": "kept-for-the-upstream"}


def test_the_contextos_cli_delegates_to_this_main(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from contextos.cli import app

    seen: list[list[str]] = []
    monkeypatch.setattr(cli, "main", lambda argv: seen.append(list(argv)) or 0)
    result = CliRunner().invoke(app, ["mcp-gateway", "--name", "notes", "--", "python", "server.py", "-v"])
    assert result.exit_code == 0
    assert cli.parse(seen[0]).command == ["python", "server.py", "-v"]
