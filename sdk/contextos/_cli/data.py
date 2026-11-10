"""Read-only commands: agents, events, policies, incidents, replay, simulate (need the ``read`` scope)."""

from __future__ import annotations

import time
from typing import Any

import typer
from rich.table import Table

from contextos._cli.common import (
    EXIT_ERROR,
    cli_errors,
    decision,
    fmt_time,
    get_client,
    get_config,
    items_of,
    out,
    pick,
    print_json,
    severity,
    status,
    text,
    total_of,
)

JSON_OPT = typer.Option(False, "--json", help="Print the raw JSON response.")
LIMIT_OPT = typer.Option(50, "--limit", "-n", min=1, max=500, help="Maximum rows to show.")


def _footer(shown: int, total: int, noun: str) -> None:
    if total > shown:
        out().print(f"[dim]Showing {shown} of {total} {noun}. Use --limit to see more.[/dim]")


def agents(limit: int = LIMIT_OPT, as_json: bool = JSON_OPT) -> None:
    """List agents known to ContextOS."""
    cfg = get_config()
    with cli_errors(cfg.url):
        payload = get_client(cfg).list_agents(limit=limit)
    if as_json:
        return print_json(payload)
    rows = items_of(payload)
    if not rows:
        out().print("No agents yet. Agents register automatically when they send their first event.")
        return
    table = Table(title="Agents", title_justify="left")
    for col in ("Name", "Framework", "Environment", "Status", "Risk", "Last seen", "ID"):
        table.add_column(col, no_wrap=col in ("ID", "Last seen"))
    for a in rows:
        table.add_row(text(pick(a, "name")), text(pick(a, "framework")), text(pick(a, "environment")),
                      status(pick(a, "status")), text(pick(a, "risk_score")), fmt_time(pick(a, "last_seen_at")),
                      text(pick(a, "id")))
    out().print(table)
    _footer(len(rows), total_of(payload, len(rows)), "agents")


def events(
    session: str | None = typer.Option(None, "--session", "-s", help="Only events of this session id."),
    event_type: str | None = typer.Option(None, "--type", "-t", help="Only this event type, e.g. tool.requested."),
    limit: int = LIMIT_OPT,
    as_json: bool = JSON_OPT,
) -> None:
    """List recently ingested events (newest first)."""
    cfg = get_config()
    with cli_errors(cfg.url):
        payload = get_client(cfg).list_events(session_id=session, event_type=event_type, limit=limit)
    if as_json:
        return print_json(payload)
    rows = items_of(payload)
    if not rows:
        out().print("No events match." if session or event_type else "No events recorded yet.")
        return
    table = Table(title="Events" + (f" — session {session}" if session else ""), title_justify="left")
    for col in ("Received", "Type", "Session", "Integration", "Processing", "ID"):
        table.add_column(col, no_wrap=col in ("Received", "ID"))
    for e in rows:
        table.add_row(fmt_time(pick(e, "received_at", "occurred_at", "timestamp")), text(pick(e, "event_type")),
                      text(pick(e, "session_id")), text(pick(e, "integration")),
                      text(pick(e, "processing_status", default="processed")), text(pick(e, "id")))
    out().print(table)
    _footer(len(rows), total_of(payload, len(rows)), "events")


def policies(as_json: bool = JSON_OPT) -> None:
    """List security policies and what they do."""
    cfg = get_config()
    with cli_errors(cfg.url):
        payload = get_client(cfg).list_policies()
    if as_json:
        return print_json(payload)
    rows = items_of(payload)
    if not rows:
        out().print("No policies defined. Every tool call gets the organisation's default decision.")
        return
    table = Table(title="Policies", title_justify="left")
    for col in ("Name", "Outcome", "Mode", "Enabled", "Priority", "Severity", "ID"):
        table.add_column(col, no_wrap=col == "ID")
    for p in rows:
        mode = str(pick(p, "mode", default="enforce"))
        mode_text = "enforce" if mode == "enforce" else "[dim]monitor (recorded only)[/dim]"
        table.add_row(text(pick(p, "name")), decision(pick(p, "outcome")), mode_text,
                      "yes" if pick(p, "enabled", default=True) else "[dim]no[/dim]", text(pick(p, "priority")),
                      severity(pick(p, "severity")), text(pick(p, "id")))
    out().print(table)


def incidents(
    state: str | None = typer.Option(None, "--status", help="open, investigating, contained, resolved, false_positive."),
    limit: int = LIMIT_OPT,
    as_json: bool = JSON_OPT,
) -> None:
    """List incidents."""
    cfg = get_config()
    with cli_errors(cfg.url):
        payload = get_client(cfg).list_incidents(status=state, limit=limit)
    if as_json:
        return print_json(payload)
    rows = items_of(payload)
    if not rows:
        out().print("No incidents" + (f" with status {state}." if state else "."))
        return
    table = Table(title="Incidents", title_justify="left")
    for col in ("#", "Title", "Severity", "Status", "Opened", "ID"):
        table.add_column(col, no_wrap=col in ("#", "Opened", "ID"))
    for i in rows:
        table.add_row(text(pick(i, "number")), text(pick(i, "title")), severity(pick(i, "severity")),
                      status(pick(i, "status")), fmt_time(pick(i, "opened_at", "created_at")), text(pick(i, "id")))
    out().print(table)
    _footer(len(rows), total_of(payload, len(rows)), "incidents")


def _timeline_line(entry: dict[str, Any]) -> str:
    when = fmt_time(pick(entry, "timestamp", "at", "occurred_at", "received_at"))
    kind = pick(entry, "kind", "type", "event_type", default="event")
    title = pick(entry, "title", "summary", "description", "label", default="")
    badges = []
    if pick(entry, "decision"):
        badges.append(decision(pick(entry, "decision")))
    if pick(entry, "enforcement"):
        badges.append(f"[dim]{text(pick(entry, 'enforcement'))}[/dim]")
    if pick(entry, "severity"):
        badges.append(severity(pick(entry, "severity")))
    if pick(entry, "trust_level"):
        badges.append(f"trust {text(pick(entry, 'trust_level'))}")
    return f"[dim]{when}[/dim]  [bold]{text(kind)}[/bold]  {text(title, '')}  {' '.join(badges)}".rstrip()


def replay(session_id: str = typer.Argument(..., help="Session id (as shown in the UI or `contextos events`)."),
           as_json: bool = JSON_OPT) -> None:
    """Print a session's recorded timeline in order (what happened, not why)."""
    cfg = get_config()
    with cli_errors(cfg.url):
        payload = get_client(cfg).session_timeline(session_id)
    if as_json:
        return print_json(payload)
    entries = items_of(payload, "timeline", "events", "entries")
    console = out()
    console.print(f"[bold]Session {text(session_id)}[/bold] — {len(entries)} recorded step(s)")
    if not entries:
        console.print("Nothing was recorded for this session.")
        return
    for entry in entries:
        console.print(_timeline_line(entry if isinstance(entry, dict) else {"title": entry}))
        explanation = pick(entry, "explanation", "reason") if isinstance(entry, dict) else None
        if explanation:
            console.print(f"    [dim]{text(explanation)}[/dim]")
    console.print("[dim]Steps are listed in recorded order. Steps that appear together were observed together; "
                  "that is not proof one caused another.[/dim]")


def _print_scenarios(payload: Any) -> None:
    rows = items_of(payload, "scenarios")
    if not rows:
        out().print("No simulation scenarios are available on this server.")
        return
    table = Table(title="Simulation scenarios", title_justify="left")
    for col in ("ID", "Name", "Category", "What it tests"):
        table.add_column(col, no_wrap=col == "ID")
    for s in rows:
        table.add_row(text(pick(s, "id", "scenario_id")), text(pick(s, "name", "title")),
                      text(pick(s, "category", "kind")), text(pick(s, "description", "summary")))
    out().print(table)


def simulate(
    scenario_id: str | None = typer.Argument(None, help="Scenario to run (see --list)."),
    list_only: bool = typer.Option(False, "--list", "-l", help="List available scenarios."),
    wait_s: float = typer.Option(120.0, "--timeout", help="Seconds to wait for the run to finish."),
    as_json: bool = JSON_OPT,
) -> None:
    """Run a Simulation Lab scenario through the real pipeline (results are flagged as simulation)."""
    cfg = get_config()
    client = get_client(cfg)
    if list_only or not scenario_id:
        with cli_errors(cfg.url):
            payload = client.list_scenarios()
        return print_json(payload) if as_json else _print_scenarios(payload)
    with cli_errors(cfg.url):
        run = client.run_simulation(scenario_id)
        deadline = time.monotonic() + wait_s
        while str(pick(run, "status", default="")).lower() == "running" and time.monotonic() < deadline:
            time.sleep(1.0)
            run = client.get_simulation_run(str(pick(run, "id")))
    if as_json:
        return print_json(run)
    _print_run(run)
    state = str(pick(run, "status", default="")).lower()
    if state == "running":
        out().print(f"[yellow]Still running after {wait_s:.0f}s.[/yellow] Check later with the run id above.")
        raise typer.Exit(EXIT_ERROR)
    if state == "failed" or pick(run, "passed") is False:
        raise typer.Exit(EXIT_ERROR)


def _print_run(run: Any) -> None:
    console = out()
    passed = pick(run, "passed")
    verdict = "[green]PASSED[/green]" if passed else "[red]FAILED[/red]" if passed is False else "[yellow]no verdict[/yellow]"
    console.print(f"[bold]Simulation {text(pick(run, 'scenario_name', 'scenario_id'))}[/bold] "
                  f"({text(pick(run, 'id'))}) — {text(pick(run, 'status'))} — {verdict}")
    if pick(run, "summary"):
        console.print(text(pick(run, "summary")))
    if pick(run, "error"):
        console.print(f"[red]Error:[/red] {text(pick(run, 'error'))}")
    results = pick(run, "results", default=[]) or []
    if results:
        table = Table(title="Checks", title_justify="left")
        for col in ("Check", "Expected", "Observed", "Result"):
            table.add_column(col)
        for r in results:
            ok = pick(r, "passed")
            table.add_row(text(pick(r, "name", "check", "step")), text(pick(r, "expected")), text(pick(r, "actual", "observed")),
                          "[green]pass[/green]" if ok else "[red]fail[/red]" if ok is False else "—")
        console.print(table)
    if pick(run, "session_id"):
        console.print(f"[dim]Inspect it with: contextos replay {text(pick(run, 'session_id'))}[/dim]")
