"""Shared CLI plumbing: configuration, client construction, error → exit-code mapping, rendering."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape

from contextos.client import ContextOSClient, default_agent_ref
from contextos.config import Config, ConfigError, load_config
from contextos.errors import APIError, AuthError, ContextOSError, Unreachable

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3


def out() -> Console:
    """Console created per call so it honours the current terminal / test environment."""
    return Console(highlight=False, soft_wrap=False)


def err() -> Console:
    return Console(stderr=True, highlight=False)


def _build_client(cfg: Config) -> ContextOSClient:
    return ContextOSClient(
        cfg.url,
        cfg.api_key,
        timeout=cfg.timeout_s,
        agent=default_agent_ref(cfg),
        spool_max_bytes=cfg.spool_max_bytes,
    )


# Tests replace this to inject a mocked transport.
client_factory: Callable[[Config], ContextOSClient] = _build_client


def get_config() -> Config:
    try:
        return load_config()
    except ConfigError as exc:
        err().print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from None


def get_client(cfg: Config | None = None) -> ContextOSClient:
    return client_factory(cfg or get_config())


@contextmanager
def cli_errors(url: str | None = None) -> Iterator[None]:
    """Turn SDK errors into one-line explanations and a non-zero exit code."""
    try:
        yield
    except Unreachable as exc:
        err().print(
            f"[red]Cannot reach ContextOS[/red]{f' at {escape(url)}' if url else ''}: {escape(str(exc))}\n"
            "Is the server running? Check the URL with [bold]contextos status[/bold] or [bold]contextos doctor[/bold]."
        )
        raise typer.Exit(EXIT_ERROR) from None
    except AuthError as exc:
        hint = (
            "The API key lacks the scope this command needs."
            if exc.status_code == 403
            else "Set CONTEXTOS_API_KEY or run [bold]contextos init[/bold]."
        )
        err().print(f"[red]Not authorised:[/red] {escape(exc.message)}. {hint}")
        raise typer.Exit(EXIT_ERROR) from None
    except APIError as exc:
        if exc.status_code == 404:
            err().print(f"[red]Not found:[/red] {escape(exc.message)}")
        else:
            err().print(
                f"[red]ContextOS returned an error:[/red] {escape(exc.message)} (HTTP {exc.status_code})"
            )
        raise typer.Exit(EXIT_ERROR) from None
    except ContextOSError as exc:
        err().print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from None


def items_of(payload: Any, *keys: str) -> list[Any]:
    """Items from a ``Page`` (``items``), another list-valued key, or a bare list."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", *keys):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def total_of(payload: Any, shown: int) -> int:
    return payload["total"] if isinstance(payload, dict) and isinstance(payload.get("total"), int) else shown


def pick(item: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(item, dict):
        return default
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def fmt_time(value: Any) -> str:
    if not value:
        return "—"
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def text(value: Any, default: str = "—") -> str:
    """Escaped display text (server data may contain Rich markup characters)."""
    return escape(str(value)) if value not in (None, "") else default


_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
_DECISION_STYLE = {
    "ALLOW": "green",
    "AUDIT": "cyan",
    "RESTRICT": "yellow",
    "REQUIRE_APPROVAL": "magenta",
    "DENY": "bold red",
}
_STATUS_STYLE = {
    "open": "red",
    "investigating": "yellow",
    "contained": "cyan",
    "resolved": "green",
    "false_positive": "dim",
    "active": "green",
    "ended": "dim",
    "quarantined": "red",
}


def severity(value: Any) -> str:
    key = str(value or "").lower()
    return f"[{_SEVERITY_STYLE.get(key, 'white')}]{escape(key or '—')}[/]"


def decision(value: Any) -> str:
    key = str(value or "").upper()
    return f"[{_DECISION_STYLE.get(key, 'white')}]{escape(key or '—')}[/]"


def status(value: Any) -> str:
    key = str(value or "").lower()
    return f"[{_STATUS_STYLE.get(key, 'white')}]{escape(key or '—')}[/]"


def print_json(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))


__all__ = [
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "EXIT_OK",
    "EXIT_USAGE",
    "cli_errors",
    "client_factory",
    "decision",
    "err",
    "fmt_time",
    "get_client",
    "get_config",
    "items_of",
    "out",
    "pick",
    "print_json",
    "severity",
    "status",
    "text",
    "total_of",
]
