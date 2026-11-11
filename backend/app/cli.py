"""``contextos-server`` — operate a ContextOS server.

    contextos-server init-db
    contextos-server create-org --name "Acme AI" --email owner@acme.test --name-of-owner "Ada Owner"
    contextos-server create-api-key --org-slug acme-ai --name "Claude Code laptop" --scopes ingest,decide
    contextos-server seed-demo --org-slug acme-ai
    contextos-server purge [--org-slug acme-ai] [--dry-run]
    contextos-server serve --host 127.0.0.1 --port 8000

The database comes from ``CONTEXTOS_DATABASE_URL`` (or ``--database-url``). Output never contains
secrets, except a newly created API key, printed exactly once.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import INSECURE_DEV_SECRET, get_settings
from app.core.errors import AppError
from app.core.logging import configure_logging
from app.database.migrations import (
    SchemaNotReadyError,
    display_url,
    ensure_schema_ready,
    upgrade_to_head,
)
from app.database.session import make_engine, session_factory, set_engine

app = typer.Typer(
    name="contextos-server",
    help="Operate a ContextOS server: database, organisations, API keys, demo data and the API process.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(highlight=False, soft_wrap=True)
err_console = Console(stderr=True, highlight=False, soft_wrap=True)

_state: dict[str, str | None] = {"database_url": None}


# ----------------------------------------------------------------------------- helpers


@app.callback()
def _root(
    database_url: str | None = typer.Option(
        None, "--database-url", help="Database URL to use instead of CONTEXTOS_DATABASE_URL.", show_default=False
    ),
) -> None:
    _state["database_url"] = database_url


def _database_url() -> str:
    return _state["database_url"] or get_settings().database_url


def _display_url(url: str) -> str:
    return display_url(url)


def _fail(message: str) -> typer.Exit:
    err_console.print(f"[bold red]Error:[/] {message}", markup=True)
    return typer.Exit(code=1)


def _bind_engine() -> Engine:
    engine = make_engine(_database_url())
    set_engine(engine)
    return engine


@contextmanager
def _session(*, require_schema: bool = True) -> Iterator[Session]:
    engine = _bind_engine()
    if require_schema:
        try:
            ensure_schema_ready(engine, allow_unversioned=get_settings().env != "production")
        except SchemaNotReadyError as exc:
            raise _fail(str(exc)) from exc
    db = session_factory()()
    try:
        yield db
        db.commit()
    except AppError as exc:
        db.rollback()
        raise _fail(exc.message) from exc
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def _org_by_slug(db: Session, slug: str) -> Any:
    from app.models import Organization

    org = db.scalar(select(Organization).where(Organization.slug == slug))
    if org is None:
        raise _fail(f"No organisation with slug '{slug}'.")
    return org


# ----------------------------------------------------------------------------- commands


@app.command("init-db")
def init_db() -> None:
    """Create or upgrade the database schema by applying the Alembic migrations."""
    url = _database_url()
    engine = make_engine(url)  # creates the parent directory of a SQLite file
    try:
        # Alembic's own logging setup (alembic.ini) would replace the CLI's; its progress lines go through ours.
        result = upgrade_to_head(engine, url, configure_logging=False)
    except SchemaNotReadyError as exc:
        raise _fail(str(exc)) from exc
    finally:
        engine.dispose()
    head = ", ".join(result.heads)
    if result.action == "unchanged":
        console.print(f"[green]✓[/] Database {_display_url(url)} is already at the latest migration ({head}).")
    elif result.action == "adopted":
        console.print(f"[green]✓[/] Database {_display_url(url)} matched the current schema and was stamped at "
                      f"{head} (it had been created without migrations).")
    else:
        before = ", ".join(result.before) or "an empty database"
        console.print(f"[green]✓[/] Database {_display_url(url)} upgraded from {before} to {head}.")


@app.command("create-org")
def create_org(
    name: str = typer.Option(..., "--name", help="Organisation name."),
    email: str = typer.Option(..., "--email", help="Owner's email (their login)."),
    owner_name: str = typer.Option(..., "--name-of-owner", help="Owner's display name."),
    password: str | None = typer.Option(
        None, "--password", help="Owner password (min 10 characters). Prompted, hidden, when omitted.", show_default=False
    ),
) -> None:
    """Create an organisation with an owner account and seed its security defaults."""
    from app.models import SecurityPolicy, TrustRule
    from app.services.bootstrap import create_organization

    if password is None:
        password = typer.prompt("Owner password", hide_input=True, confirmation_prompt=True)
    with _session() as db:
        org, user = create_organization(db, name=name, owner_email=email, owner_name=owner_name, password=password)
        policies = db.scalar(select(func.count()).select_from(SecurityPolicy).where(SecurityPolicy.organization_id == org.id))
        rules = db.scalar(select(func.count()).select_from(TrustRule).where(TrustRule.organization_id == org.id))
        org_id, slug, org_name, owner = org.id, org.slug, org.name, user.email

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("Organisation", org_name)
    table.add_row("Slug", slug)
    table.add_row("ID", org_id)
    table.add_row("Owner", owner)
    table.add_row("Seeded", f"{policies} built-in policies, {rules} trust rules")
    console.print(Panel(table, title="[green]Organisation created[/]", expand=False))


@app.command("create-api-key")
def create_api_key(
    org_slug: str = typer.Option(..., "--org-slug", help="Organisation slug."),
    name: str = typer.Option(..., "--name", help="Key name, e.g. the machine or integration using it."),
    scopes: str = typer.Option("ingest,decide", "--scopes", help="Comma-separated subset of: ingest, decide, read."),
    agent: str | None = typer.Option(
        None, "--agent", help="Bind the key to one agent (id or name): it can then only report that agent.", show_default=False
    ),
    expires_in_days: int | None = typer.Option(None, "--expires-in-days", min=1, max=3650, show_default=False),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the raw key (for scripts)."),
) -> None:
    """Create an integration API key. The raw key is printed once and never stored."""
    from app.models import Agent
    from app.services.auth_service import SYSTEM_ACTOR
    from app.services.auth_service import create_api_key as create_key

    scope_list = [s.strip().lower() for s in scopes.split(",") if s.strip()]
    with _session() as db:
        org = _org_by_slug(db, org_slug)
        agent_id: str | None = None
        if agent:
            row = db.scalar(
                select(Agent).where(Agent.organization_id == org.id, (Agent.id == agent) | (Agent.name == agent))
            )
            if row is None:
                raise _fail(
                    f"No agent '{agent}' in {org_slug}. Register it first (POST /api/v1/agents or the Agents page), "
                    "or create the key without --agent."
                )
            agent_id = row.id
        key, raw, bound = create_key(
            db, org.id, SYSTEM_ACTOR, name=name.strip(), scopes=scope_list, agent_id=agent_id,
            expires_in_days=expires_in_days,
        )
        summary = {
            "id": key.id, "scopes": ", ".join(key.scopes), "agent": bound.name if bound else "any agent",
            "expires": key.expires_at.isoformat() if key.expires_at else "never",
        }

    if quiet:
        typer.echo(raw)
        return
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("Key ID", summary["id"])
    table.add_row("Scopes", summary["scopes"])
    table.add_row("Agent", summary["agent"])
    table.add_row("Expires", summary["expires"])
    console.print(Panel(table, title="[green]API key created[/]", expand=False))
    console.print("\n" + raw + "\n", markup=False)
    console.print(
        "[yellow]This is the only time the key is shown.[/] Store it in a secret manager; ContextOS keeps only its hash."
    )


def _scenario_id(scenario: Any) -> str:
    if isinstance(scenario, str):
        return scenario
    if isinstance(scenario, dict):
        return str(scenario.get("id") or scenario.get("key"))
    return str(getattr(scenario, "id", None) or scenario.key)


def _is_demo(scenario: Any) -> bool:
    flag = scenario.get("demo") if isinstance(scenario, dict) else getattr(scenario, "demo", False)
    return flag is True


def _demo_scenarios(scenarios: list[Any]) -> list[Any]:
    """Scenarios flagged ``demo=True``; every scenario when none is flagged."""
    flagged = [s for s in scenarios if _is_demo(s)]
    return flagged or scenarios


def _outcome(run: Any) -> str | None:
    status = run.get("status") if isinstance(run, dict) else getattr(run, "status", None)
    passed = run.get("passed") if isinstance(run, dict) else getattr(run, "passed", None)
    if status and passed is not None:
        return f"{status}, expectations {'met' if passed else 'NOT met'}"
    return str(status) if status else None


@app.command("seed-demo")
def seed_demo(org_slug: str = typer.Option(..., "--org-slug", help="Organisation slug.")) -> None:
    """Populate an organisation with demo data by running the Simulation Lab's demo scenarios (every
    scenario when none is flagged as a demo) through the real pipeline. All resulting rows are flagged
    as simulations."""
    try:
        simulations = importlib.import_module("app.services.simulations")
    except ModuleNotFoundError as exc:
        if exc.name != "app.services.simulations":
            raise
        raise _fail("The Simulation Lab service (app.services.simulations) is not available in this build.") from exc
    list_scenarios = getattr(simulations, "list_scenarios", None)
    run_scenario = getattr(simulations, "run_scenario", None)
    if list_scenarios is None or run_scenario is None:
        raise _fail("app.services.simulations does not provide list_scenarios() and run_scenario().")

    with _session() as db:
        org_id = _org_by_slug(db, org_slug).id
    scenarios = _demo_scenarios(list(list_scenarios()))
    if not scenarios:
        raise _fail("The Simulation Lab has no scenarios to run.")
    failures = 0
    for scenario in scenarios:
        scenario_id = _scenario_id(scenario)
        try:
            with _session() as db:
                outcome = _outcome(run_scenario(db, org_id, scenario_id))
        except typer.Exit:
            failures += 1
            continue
        except Exception as exc:  # report and continue with the remaining scenarios
            failures += 1
            err_console.print(f"[red]✗[/] {escape(scenario_id)}: {type(exc).__name__}: {escape(str(exc))}")
            continue
        console.print(f"[green]✓[/] {scenario_id}" + (f" — {outcome}" if outcome else ""))
    if failures:
        raise _fail(f"{failures} of {len(scenarios)} scenario(s) failed.")
    console.print(f"Demo data generated from {len(scenarios)} scenario(s). Every row it created is flagged as a "
                  "simulation.")


@app.command()
def purge(
    org_slug: str | None = typer.Option(
        None, "--org-slug", help="Only this organisation (default: every organisation).", show_default=False
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Count what would be deleted; delete nothing."),
    as_json: bool = typer.Option(False, "--json", help="Print the per-table counts as JSON (for scripts)."),
) -> None:
    """Delete recorded event data older than each organisation's retention period (Settings → Privacy).

    Audit entries are never deleted (they form a hash chain), and evidence of open incidents is kept
    until the incident is closed. Schedule this daily, e.g. from cron or a Kubernetes CronJob."""
    import json

    from app.core.timeutil import isoformat
    from app.models import Organization
    from app.services.retention import TABLES, purge_expired

    with _session() as db:
        if org_slug:
            orgs = [_org_by_slug(db, org_slug)]
        else:
            orgs = list(db.scalars(select(Organization).order_by(Organization.created_at, Organization.id)))
        results = [(org.slug, purge_expired(db, org.id, dry_run=dry_run)) for org in orgs]
        if dry_run:
            db.rollback()

    if as_json:
        typer.echo(json.dumps([{"org_slug": slug, **r.as_dict()} for slug, r in results], indent=2))
        return
    if not results:
        console.print("No organisations.")
        return
    console.print("[bold]Dry run[/] — nothing was deleted." if dry_run else "[bold]Retention purge[/]")
    for slug, r in results:
        table = Table(show_header=False, box=None, padding=(0, 2))
        for name in TABLES:
            table.add_row(name.replace("_", " "), str(r.counts[name]))
        console.print(f"\n{escape(slug)}: keeps {r.retention_days} days (older than {isoformat(r.cutoff)}); "
                      f"{r.protected_incidents} open incident(s) keep their evidence")
        console.print(table)
    verb = "would be deleted" if dry_run else "deleted"
    console.print(f"{sum(r.total for _, r in results)} row(s) {verb}. Audit entries are never deleted.")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind."),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
    reload: bool = typer.Option(False, "--reload", help="Reload on code changes (development only)."),
) -> None:
    """Run the API (and the built frontend, when present) with uvicorn."""
    import uvicorn

    settings = get_settings()
    if settings.secret_key == INSECURE_DEV_SECRET:
        err_console.print("[yellow]Warning:[/] using the insecure development secret. Set CONTEXTOS_SECRET_KEY.")
    if _state["database_url"]:
        os.environ["CONTEXTOS_DATABASE_URL"] = _state["database_url"]
        get_settings.cache_clear()
    console.print(f"ContextOS API on http://{host}:{port}  (database: {_display_url(_database_url())})")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload, log_level=settings.log_level.lower())


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    app()


if __name__ == "__main__":
    main()
