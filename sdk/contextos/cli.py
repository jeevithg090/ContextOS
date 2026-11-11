"""``contextos`` command-line interface.

Setup:        init, status, doctor, flush
Data:         agents, events, policies, incidents, replay (``read`` scope); simulate (``read`` to list,
              ``ingest`` to run a scenario)
Detection:    scan (``read`` scope; nothing is stored)
Integrations: hook (Claude Code), mcp-gateway (MCP proxy) — implemented by integration packages

Exit codes: 0 success, 1 error (unreachable server, rejected key, failed check), 2 usage error,
3 ``scan`` detected something.
"""

from __future__ import annotations

import typer

from contextos._cli import data, delegates, scan, setup
from contextos._version import __version__

app = typer.Typer(
    name="contextos",
    help="ContextOS: security, trust and provenance for AI agents. Configure, diagnose and inspect from the terminal.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"contextos {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version and exit."),
) -> None:
    """ContextOS CLI."""


app.command("init")(setup.init)
app.command("status")(setup.status)
app.command("doctor")(setup.doctor)
app.command("flush")(setup.flush)
app.command("agents")(data.agents)
app.command("events")(data.events)
app.command("policies")(data.policies)
app.command("incidents")(data.incidents)
app.command("replay")(data.replay)
app.command("simulate")(data.simulate)
app.command("scan")(scan.scan)
app.command("hook")(delegates.hook)
app.command(
    "mcp-gateway",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
    add_help_option=False,
)(delegates.mcp_gateway)


def main() -> None:  # pragma: no cover - console entry point alternative
    app(prog_name="contextos")


__all__ = ["app", "main"]
