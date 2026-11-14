"""Setup and health commands: init, status, doctor, flush."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape
from rich.table import Table

from contextos._cli.common import EXIT_ERROR, cli_errors, err, get_client, get_config, out, text
from contextos._cli.delegates import load_optional
from contextos.client import sends_credentials_in_clear
from contextos.config import (
    CONFIG_FILE_NAME,
    FAIL_MODES,
    PROJECT_DIR_NAME,
    Config,
    ConfigError,
    load_config,
    mask_key,
    user_config_path,
    write_config_file,
)
from contextos.errors import AuthError, ContextOSError, Unreachable

FAIL_MODE_MEANING = {
    "closed": "guarded tools are denied",
    "open": "guarded tools run unguarded",
    "ask": "a human is asked",
}

SCOPE_PURPOSE = {
    "ingest": "report events (sessions, context, tool results); run Simulation Lab scenarios (contextos simulate)",
    "decide": "enforce policy before tools run (guard(), Claude Code and Codex PreToolUse, MCP gateway)",
    "read": "CLI data commands (agents, events, policies, incidents, replay, simulate --list) and scan",
}


def _scope_lines(scopes: dict[str, bool | None]) -> list[str]:
    lines = []
    for scope, purpose in SCOPE_PURPOSE.items():
        state = scopes.get(scope)
        mark = "[green]✓[/green]" if state else "[red]✗[/red]" if state is False else "[yellow]?[/yellow]"
        lines.append(f"  {mark} {scope:<7} {purpose}")
    return lines


def init(
    url: str | None = typer.Option(
        None, "--url", help="ContextOS server URL (default: current config or http://localhost:8000)."
    ),
    api_key: str | None = typer.Option(
        None, "--api-key", help="API key (ctxk_…). Prompted for when not configured."
    ),
    agent_name: str | None = typer.Option(None, "--agent-name", help="Name this project's agent reports as."),
    fail_mode: str | None = typer.Option(
        None, "--fail-mode", help="When the server is unreachable: closed (deny), open (run), ask."
    ),
    project_dir: Path = typer.Option(
        Path("."), "--project-dir", help="Project root to configure.", file_okay=False
    ),
    key_location: str = typer.Option(
        "user", "--key-location", help="Where to store the key: user (~/.contextos, default) or project."
    ),
    skip_verify: bool = typer.Option(
        False, "--skip-verify", help="Write the config without contacting the server."
    ),
    claude_code: bool = typer.Option(
        False, "--claude-code", help="Also install the Claude Code hooks for this project."
    ),
    codex: bool = typer.Option(
        False, "--codex", help="Also install the OpenAI Codex hooks (.codex/hooks.json) for this project."
    ),
    scope: str = typer.Option(
        "project",
        "--scope",
        help="Hook scope: project, local or user for --claude-code; project or user for --codex.",
    ),
) -> None:
    """Configure this project for ContextOS and verify the server and API key."""
    if fail_mode is not None and fail_mode not in FAIL_MODES:
        err().print(f"[red]--fail-mode must be one of {', '.join(FAIL_MODES)}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if codex and scope not in ("project", "user"):
        err().print(
            "[red]--scope for --codex must be 'project' (.codex/hooks.json) or 'user' (~/.codex/hooks.json)[/red]"
        )
        raise typer.Exit(EXIT_ERROR)
    if key_location not in ("user", "project"):
        err().print("[red]--key-location must be 'user' or 'project'[/red]")
        raise typer.Exit(EXIT_ERROR)
    project = project_dir.resolve()
    project.mkdir(parents=True, exist_ok=True)
    current = get_config()
    resolved_url = (url or current.url).rstrip("/")
    key = api_key or current.api_key
    if not key and sys.stdin.isatty():
        key = typer.prompt("ContextOS API key (ctxk_…)", hide_input=True).strip()
    if not key:
        err().print(
            "[red]An API key is required.[/red] Create one in Settings → API keys, then pass --api-key."
        )
        raise typer.Exit(EXIT_ERROR)
    name = agent_name or current.agent_name or project.name
    mode = fail_mode or current.fail_mode
    console = out()

    if not skip_verify:
        cfg = Config(
            url=resolved_url, api_key=key, agent_name=name, fail_mode=mode, timeout_s=current.timeout_s
        )  # type: ignore[arg-type]
        client = get_client(cfg)
        with cli_errors(resolved_url):
            client.health()
            try:
                scopes = client.probe_scopes()
            except AuthError as exc:
                err().print(
                    f"[red]The API key was rejected:[/red] {escape(exc.message)}. Nothing was written."
                )
                raise typer.Exit(EXIT_ERROR) from None
        console.print(f"[green]✓[/green] Connected to {escape(resolved_url)} with key {mask_key(key)}")
        for line in _scope_lines(scopes):
            console.print(line)
        if not any(scopes.values()):
            err().print(
                "[red]This key has none of the ingest, decide or read scopes.[/red] Nothing was written."
            )
            raise typer.Exit(EXIT_ERROR)
        if scopes.get("decide") is False:
            console.print(
                "[yellow]Without 'decide', tool calls cannot be enforced; with fail mode "
                f"'{mode}' guarded tools will be {'denied' if mode == 'closed' else 'unguarded'}.[/yellow]"
            )

    project_file = project / PROJECT_DIR_NAME / CONFIG_FILE_NAME
    project_values: dict[str, Any] = {"url": resolved_url, "agent_name": name, "fail_mode": mode}
    store_key = api_key is not None or current.sources.get("api_key") not in ("env",)
    try:
        if key_location == "project":
            project_values["api_key"] = key
            write_config_file(project_file, project_values)
            gitignore = project_file.parent / ".gitignore"
            if not gitignore.exists():
                gitignore.write_text(
                    f"# Holds an API key — never commit it\n{CONFIG_FILE_NAME}\n", encoding="utf-8"
                )
        else:
            write_config_file(project_file, project_values)
            if store_key:
                write_config_file(user_config_path(), {"api_key": key})
    except (OSError, ConfigError, ValueError) as exc:
        err().print(f"[red]Could not write configuration:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from None
    console.print(
        f"[green]✓[/green] Wrote {escape(str(project_file))} (agent '{escape(name)}', fail mode '{mode}')"
    )
    if key_location == "user" and store_key:
        console.print(f"[green]✓[/green] Stored the API key in {escape(str(user_config_path()))} (mode 600)")
    elif key_location == "project":
        console.print(
            "[yellow]The API key is stored in the project file (mode 600, git-ignored). Do not commit it.[/yellow]"
        )

    if claude_code:
        install = load_optional(
            "contextos.integrations.claude_code.install", "install_hooks", "Claude Code hooks"
        )
        if install is None:
            raise typer.Exit(EXIT_ERROR)
        try:
            result = install(project, scope)
        except (OSError, ValueError, ContextOSError) as exc:
            err().print(f"[red]Installing the Claude Code hooks failed:[/red] {escape(str(exc))}")
            raise typer.Exit(EXIT_ERROR) from None
        console.print(
            f"[green]✓[/green] Claude Code hooks installed ({escape(scope)} scope)"
            + (f": {escape(str(result))}" if isinstance(result, (str, Path)) else "")
        )
    if codex:
        _install_codex(project, scope)
    console.print(
        "Next: [bold]contextos doctor[/bold] to re-check, or wrap tools with [bold]@contextos.guard(...)[/bold]."
    )


def _install_codex(project: Path, scope: str) -> None:
    install = load_optional("contextos.integrations.codex.install", "install_hooks", "Codex hooks")
    if install is None:
        raise typer.Exit(EXIT_ERROR)
    try:
        report = install(project, scope)
    except (OSError, ValueError, ContextOSError) as exc:
        err().print(f"[red]Installing the Codex hooks failed:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from None
    console = out()
    console.print(f"[green]✓[/green] Codex hooks installed ({escape(scope)} scope): {escape(str(report))}")
    if getattr(report, "backup", None):
        console.print(f"  original file kept at {escape(str(report.backup))}")
    for warning in getattr(report, "warnings", []):
        console.print(f"[yellow]![/yellow] {escape(warning)}")


def status() -> None:
    """Show the active configuration and whether the server is reachable."""
    cfg = get_config()
    client = get_client(cfg)
    console = out()
    console.print(f"Server      {escape(cfg.url)}  [dim](from {cfg.sources.get('url', 'default')})[/dim]")
    console.print(
        f"API key     {mask_key(cfg.api_key)}  [dim](from {cfg.sources.get('api_key', 'default')})[/dim]"
    )
    console.print(f"Agent       {escape(client.agent.name)}")
    console.print(
        f"Fail mode   {cfg.fail_mode}  [dim](when the server is unreachable: {FAIL_MODE_MEANING[cfg.fail_mode]})[/dim]"
    )
    if client.spool is not None:
        stats = client.spool.stats()
        console.print(f"Spool       {stats.events} event(s) waiting  [dim]({escape(str(stats.path))})[/dim]")
    try:
        started = time.perf_counter()
        client.health()
        console.print(f"Reachable   [green]yes[/green] ({(time.perf_counter() - started) * 1000:.0f} ms)")
    except ContextOSError as exc:
        console.print(f"Reachable   [red]no[/red] — {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from None


def _hooks_check(project: Path) -> tuple[bool | None, str]:
    hooks_status = load_optional(
        "contextos.integrations.claude_code.install", "hooks_status", "Claude Code hooks", quiet=True
    )
    if hooks_status is None:
        return None, "Claude Code integration is not available in this SDK build"
    try:
        result = hooks_status(project)
    except (OSError, ValueError) as exc:
        return False, f"could not read Claude Code settings: {exc}"
    installed = (
        result
        if isinstance(result, bool)
        else (result.get("installed") if isinstance(result, dict) else getattr(result, "installed", None))
    )
    detail = result.get("detail") or result.get("message") if isinstance(result, dict) else None
    if installed:
        return True, str(detail or "hooks installed")
    return None, str(detail or "not installed (optional): contextos init --claude-code")


def _codex_check(project: Path) -> tuple[bool | None, str]:
    hooks_status = load_optional(
        "contextos.integrations.codex.install", "hooks_status", "Codex hooks", quiet=True
    )
    if hooks_status is None:
        return None, "Codex integration is not available in this SDK build"
    try:
        result = hooks_status(project)
    except (OSError, ValueError) as exc:
        return False, f"could not read the Codex hooks: {exc}"
    detail = str(result.get("detail") or "")
    if not result.get("ok", True):
        return False, detail
    if result.get("installed") and not result.get("warning"):
        return True, detail
    return None, detail or "not installed (optional): contextos init --codex"


def doctor(
    project_dir: Path = typer.Option(Path("."), "--project-dir", help="Project to check.", file_okay=False),
) -> None:
    """Diagnose configuration, connectivity, key scopes, the offline spool, and the Claude Code and Codex hooks."""
    project = project_dir.resolve()
    checks: list[tuple[str, bool | None, str]] = []  # (check, ok / None = warning, detail)
    try:
        cfg = load_config(project)
        found = [str(p) for p in (cfg.project_file, cfg.user_file) if p]
        env_keys = [k for k, v in cfg.sources.items() if v == "env"]
        detail = ", ".join(found) if found else "no config files"
        checks.append(
            (
                "Configuration",
                bool(found or env_keys),
                detail + (f"; env: {', '.join(env_keys)}" if env_keys else ""),
            )
        )
    except ConfigError as exc:
        checks.append(("Configuration", False, str(exc)))
        _print_checks(checks)
        raise typer.Exit(EXIT_ERROR) from None

    client = get_client(cfg)
    if sends_credentials_in_clear(cfg.url):
        checks.append(
            (
                "Transport",
                None,
                f"{cfg.url} is plain HTTP to another host: the API key and events travel "
                "unencrypted. Use https://.",
            )
        )
    reachable = False
    try:
        started = time.perf_counter()
        client.health()
        reachable = True
        checks.append(
            ("Server reachable", True, f"{cfg.url} ({(time.perf_counter() - started) * 1000:.0f} ms)")
        )
    except Unreachable as exc:
        checks.append(("Server reachable", False, f"{cfg.url}: {exc}"))
    except ContextOSError as exc:
        checks.append(("Server reachable", False, f"{cfg.url} answered with an error: {exc}"))

    if not cfg.api_key:
        checks.append(("API key", False, "not configured (CONTEXTOS_API_KEY or contextos init)"))
    elif reachable:
        try:
            scopes = client.probe_scopes()
            checks.append(("API key", True, f"{mask_key(cfg.api_key)} accepted"))
            for scope, purpose in SCOPE_PURPOSE.items():
                state = scopes.get(scope)
                note = "granted" if state else "missing" if state is False else "could not be determined"
                # A deliberately narrow key is valid, so a missing scope is a warning, not a failure.
                checks.append((f"Scope '{scope}'", True if state else None, f"{note} — {purpose}"))
        except AuthError as exc:
            checks.append(("API key", False, f"{mask_key(cfg.api_key)} rejected: {exc.message}"))
        except ContextOSError as exc:
            checks.append(("API key", None, f"could not be verified: {exc}"))
    else:
        checks.append(("API key", None, f"{mask_key(cfg.api_key)} (not verified: server unreachable)"))

    if client.spool is not None:
        stats = client.spool.stats()
        mb = stats.bytes / (1024 * 1024)
        spool_ok: bool | None = True if stats.events == 0 else None
        detail = f"{stats.events} event(s), {mb:.2f} MiB of {cfg.spool_max_bytes / (1024 * 1024):.0f} MiB at {stats.path}"
        if stats.events:
            detail += " — run `contextos flush` once the server is reachable"
        checks.append(("Offline spool", spool_ok, detail))
    ok, detail = _hooks_check(project)
    checks.append(("Claude Code hooks", ok, detail))
    ok, detail = _codex_check(project)
    checks.append(("Codex hooks", ok, detail))

    _print_checks(checks)
    if any(ok is False for _, ok, _ in checks):
        raise typer.Exit(EXIT_ERROR)


def _print_checks(checks: list[tuple[str, bool | None, str]]) -> None:
    table = Table(title="ContextOS doctor", title_justify="left", show_header=True)
    table.add_column("", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Detail")
    for name, ok, detail in checks:
        mark = "[green]✓[/green]" if ok else "[red]✗[/red]" if ok is False else "[yellow]![/yellow]"
        table.add_row(mark, name, text(detail))
    out().print(table)


def flush() -> None:
    """Send events waiting in the offline spool now."""
    cfg = get_config()
    client = get_client(cfg)
    if client.spool is None:
        out().print("Spooling is disabled.")
        return
    before = client.spool.stats().events
    if before == 0:
        out().print("The spool is empty.")
        return
    with cli_errors(cfg.url):
        delivered = client.flush_spool()
    left = client.spool.stats().events
    out().print(f"Delivered {delivered} of {before} spooled event(s); {left} still waiting.")
    if left:
        raise typer.Exit(EXIT_ERROR)


__all__ = ["doctor", "flush", "init", "status"]
