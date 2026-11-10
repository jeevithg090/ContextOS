"""``contextos-server`` — operate a ContextOS server.

    contextos-server init-db
    contextos-server create-org --name "Acme AI" --email owner@acme.test --name-of-owner "Ada Owner"
    contextos-server create-api-key --org-slug acme-ai --name "Claude Code laptop" --scopes ingest,decide
    contextos-server seed-demo --org-slug acme-ai
    contextos-server serve --host 127.0.0.1 --port 8000

The database comes from ``CONTEXTOS_DATABASE_URL`` (or ``--database-url``). Output never contains
secrets, except a newly created API key, printed exactly once.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import Engine, func, inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.config import INSECURE_DEV_SECRET, get_settings
from app.core.errors import AppError
from app.core.logging import configure_logging
from app.database.session import make_engine, session_factory, set_engine

app = typer.Typer(
    name="contextos-server",
    help="Operate a ContextOS server: database, organisations, API keys, demo data and the API process.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(highlight=False, soft_wrap=True)
err_console = Console(stderr=True, highlight=False, soft_wrap=True)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
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
    return make_url(url).render_as_string(hide_password=True)


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
    if require_schema and not inspect(engine).has_table("organizations"):
        raise _fail(f"Database {_display_url(_database_url())} is not initialised. Run `contextos-server init-db` first.")
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


@contextmanager
def _database_env(url: str) -> Iterator[None]:
    """Make ``get_settings()`` (read by alembic/env.py and the app) see ``url`` for the duration."""
    previous = os.environ.get("CONTEXTOS_DATABASE_URL")
    os.environ["CONTEXTOS_DATABASE_URL"] = url
    get_settings.cache_clear()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("CONTEXTOS_DATABASE_URL", None)
        else:
            os.environ["CONTEXTOS_DATABASE_URL"] = previous
        get_settings.cache_clear()


def _migration_files() -> list[Path]:
    versions = _BACKEND_ROOT / "alembic" / "versions"
    if not (_BACKEND_ROOT / "alembic.ini").is_file() or not versions.is_dir():
        return []
    return sorted(p for p in versions.glob("*.py") if p.name != "__init__.py")


def _org_by_slug(db: Session, slug: str) -> Any:
    from app.models import Organization

    org = db.scalar(select(Organization).where(Organization.slug == slug))
    if org is None:
        raise _fail(f"No organisation with slug '{slug}'.")
    return org


# ----------------------------------------------------------------------------- commands


@app.command("init-db")
def init_db() -> None:
    """Create or upgrade the database schema (Alembic migrations when present)."""
    url = _database_url()
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        if path and path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    migrations = _migration_files()
    if migrations:
        from alembic.config import Config

        from alembic import command

        config = Config(str(_BACKEND_ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
        with _database_env(url):
            command.upgrade(config, "head")
        console.print(f"[green]✓[/] Database {_display_url(url)} upgraded to the latest migration ({len(migrations)} available).")
        return

    import app.models  # noqa: F401  (registers every table)
    from app.database.base import Base

    err_console.print("[yellow]Warning:[/] no Alembic migrations found; creating tables directly from the models.")
    engine = _bind_engine()
    Base.metadata.create_all(engine)
    console.print(f"[green]✓[/] Database {_display_url(url)} initialised ({len(Base.metadata.tables)} tables).")


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


def _scenario_key(scenario: Any) -> str:
    if isinstance(scenario, str):
        return scenario
    if isinstance(scenario, dict):
        return str(scenario.get("key") or scenario.get("id"))
    return str(getattr(scenario, "key", None) or scenario.id)


@app.command("seed-demo")
def seed_demo(org_slug: str = typer.Option(..., "--org-slug", help="Organisation slug.")) -> None:
    """Populate an organisation with demo data by running every Simulation Lab scenario through the real
    pipeline. All resulting rows are flagged as simulations."""
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
    failures = 0
    for scenario in list_scenarios():
        key = _scenario_key(scenario)
        try:
            with _session() as db:
                run = run_scenario(db, org_id, key)
                outcome = getattr(run, "status", None) or (run.get("status") if isinstance(run, dict) else None)
        except typer.Exit:
            failures += 1
            continue
        except Exception as exc:  # report and continue with the remaining scenarios
            failures += 1
            err_console.print(f"[red]✗[/] {key}: {type(exc).__name__}: {exc}", markup=True)
            continue
        console.print(f"[green]✓[/] {key}" + (f" — {outcome}" if outcome else ""))
    if failures:
        raise _fail(f"{failures} scenario(s) failed.")
    console.print("Demo data generated. Every row it created is flagged as a simulation.")


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
