"""Subcommands implemented by integration packages, imported lazily.

``contextos hook <EventName>`` → ``contextos.integrations.claude_code.hook:main(event_name)``
``contextos codex-hook <EventName>`` → ``contextos.integrations.codex.hook:main(event_name)``
``contextos mcp-gateway ...`` → ``contextos.integrations.mcp_gateway.cli:main(args)``

A missing integration (or one of its optional dependencies) produces a clear message instead of
breaking the rest of the CLI. If an enforcement hook itself cannot load, its ``PreToolUse`` call
exits with code 2 and a reason on stderr — the "block this tool call" signal of both Claude Code
and Codex (Codex blocks on exit 2 only when stderr is not empty) — so a broken install fails
closed rather than silently letting tools run.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any

import typer
from rich.markup import escape

from contextos._cli.common import EXIT_ERROR, err

CLAUDE_BLOCK_EXIT = 2
CODEX_BLOCK_EXIT = 2
_OPTIONAL_DEPS = {"mcp": "contextos[mcp]"}


def load_optional(module: str, attribute: str, feature: str, *, quiet: bool = False) -> Callable[..., Any] | None:
    """Import ``module.attribute``; print why it is unavailable (unless ``quiet``) and return None."""
    try:
        target = getattr(importlib.import_module(module), attribute)
    except ModuleNotFoundError as exc:
        missing = (exc.name or "").split(".")[0]
        if not quiet:
            if exc.name and exc.name.startswith("contextos"):
                err().print(f"[red]{feature} unavailable in this installation[/red] (module {escape(exc.name)} not found). "
                            "Upgrade the contextos package.")
            else:
                extra = _OPTIONAL_DEPS.get(missing)
                hint = f" Install it with: pip install '{escape(extra)}'" if extra else ""
                err().print(f"[red]{feature} unavailable: optional dependency '{escape(missing)}' is not installed.[/red]{hint}")
        return None
    except AttributeError:
        if not quiet:
            err().print(f"[red]{feature}: {escape(module)} has no '{escape(attribute)}'.[/red] Upgrade the contextos package.")
        return None
    return target if callable(target) else None


def _exit_code(result: Any) -> int:
    if result is None or result is True:
        return 0
    if isinstance(result, bool):
        return EXIT_ERROR
    return result if isinstance(result, int) else 0


def hook(event_name: str = typer.Argument(..., help="Claude Code hook event, e.g. PreToolUse, PostToolUse, SessionStart.")) -> None:
    """Claude Code hook entry point (reads the hook payload from stdin). Installed by `contextos init --claude-code`."""
    main = load_optional("contextos.integrations.claude_code.hook", "main", "Claude Code hooks")
    if main is None:
        raise typer.Exit(CLAUDE_BLOCK_EXIT if event_name == "PreToolUse" else EXIT_ERROR)
    raise typer.Exit(_exit_code(main(event_name)))


def codex_hook(event_name: str = typer.Argument(..., help="Codex hook event, e.g. PreToolUse, PostToolUse, SessionStart.")) -> None:
    """Codex hook entry point (reads the hook payload from stdin). Installed by `contextos init --codex`."""
    main = load_optional("contextos.integrations.codex.hook", "main", "Codex hooks")
    if main is None:
        if event_name == "PreToolUse":
            err().print("ContextOS could not load its Codex hook, so this tool call was blocked (fail closed). "
                        "Run `contextos doctor`.")
            raise typer.Exit(CODEX_BLOCK_EXIT)
        raise typer.Exit(0)  # observation hooks never break the session
    raise typer.Exit(_exit_code(main(event_name)))


def mcp_gateway(ctx: typer.Context) -> None:
    """Run the MCP gateway (enforces decisions on MCP tools/call). Arguments are passed through."""
    main = load_optional("contextos.integrations.mcp_gateway.cli", "main", "MCP gateway")
    if main is None:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(_exit_code(main(list(ctx.args))))


__all__ = ["CLAUDE_BLOCK_EXIT", "CODEX_BLOCK_EXIT", "codex_hook", "hook", "load_optional", "mcp_gateway"]
