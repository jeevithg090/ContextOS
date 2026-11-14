"""Alembic integration: apply the migrations and check that a database is at the latest revision.

The schema is owned by the Alembic revisions in ``backend/alembic/versions``. Production never creates
tables from the models (``Base.metadata.create_all`` is for tests only); ``contextos-server init-db``
runs the migrations, and the API refuses to start until the database is at the latest revision
(:func:`ensure_schema_ready`, called from the application lifespan).

States reported by :func:`schema_status`:

- ``current`` — the database records the latest revision(s).
- ``uninitialised`` — no ContextOS tables at all (a fresh database).
- ``outdated`` — the recorded revision is older than this build's latest one, or unknown to this build
  (migrated by a newer version).
- ``incomplete`` — some ContextOS tables are missing although others exist.
- ``unversioned`` — every table exists but no revision is recorded: the schema was created with
  ``create_all`` (test fixtures, or a development database from before migrations existed).
  ``init-db`` adopts such a database (stamps it) only when it matches the models exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import Engine, inspect, text
from sqlalchemy.engine import make_url

from app.database.base import Base

BACKEND_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
SCRIPT_LOCATION = BACKEND_ROOT / "alembic"
MIGRATE_COMMAND = "contextos-server init-db"
VERSION_TABLE = "alembic_version"

SchemaState = Literal["current", "uninitialised", "outdated", "incomplete", "unversioned"]


class SchemaNotReadyError(RuntimeError):
    """The database schema is missing or not at the latest migration. The message names the fix."""

    def __init__(self, message: str, status: SchemaStatus | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class SchemaStatus:
    state: SchemaState
    current: tuple[str, ...]
    heads: tuple[str, ...]
    missing_tables: tuple[str, ...] = field(default_factory=tuple)
    unknown_revisions: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.state == "current"


def display_url(url: str) -> str:
    return make_url(url).render_as_string(hide_password=True)


def migration_files() -> list[Path]:
    versions = SCRIPT_LOCATION / "versions"
    if not ALEMBIC_INI.is_file() or not versions.is_dir():
        return []
    return sorted(p for p in versions.glob("*.py") if p.name != "__init__.py")


def alembic_config(database_url: str | None = None, *, configure_logging: bool = True) -> Config:
    """An Alembic config for this backend. ``database_url`` overrides ``CONTEXTOS_DATABASE_URL``."""
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(SCRIPT_LOCATION))
    config.attributes["configure_logging"] = configure_logging
    if database_url:
        config.attributes["database_url"] = database_url
    return config


@lru_cache(maxsize=1)
def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(alembic_config())


def head_revisions() -> tuple[str, ...]:
    return tuple(sorted(_script().get_heads()))


def _known(revision: str) -> bool:
    try:
        return _script().get_revision(revision) is not None
    except CommandError:  # an id this build's revision graph does not contain
        return False


def _recorded_revisions(engine: Engine) -> tuple[str, ...]:
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT version_num FROM {VERSION_TABLE}")).scalars()  # noqa: S608 (constant)
        return tuple(sorted(str(r) for r in rows))


def schema_status(engine: Engine) -> SchemaStatus:
    heads = head_revisions()
    expected = set(Base.metadata.tables)
    present = set(inspect(engine).get_table_names())
    current = _recorded_revisions(engine) if VERSION_TABLE in present else ()
    missing = tuple(sorted(expected - present))
    if current:
        unknown = tuple(r for r in current if not _known(r))
        if unknown or set(current) != set(heads):
            return SchemaStatus("outdated", current, heads, missing, unknown)
        if missing:
            return SchemaStatus("incomplete", current, heads, missing)
        return SchemaStatus("current", current, heads)
    if not expected & present:
        return SchemaStatus("uninitialised", current, heads, missing)
    if missing:
        return SchemaStatus("incomplete", current, heads, missing)
    return SchemaStatus("unversioned", current, heads)


def describe(status: SchemaStatus, url: str) -> str:
    """A one-paragraph explanation of what is wrong and the command that fixes it."""
    where = f"The database {display_url(url)}"
    run = f"Run `{MIGRATE_COMMAND}` (or `make migrate`) with the same CONTEXTOS_DATABASE_URL"
    heads = ", ".join(status.heads) or "none"
    if status.state == "uninitialised":
        return f"{where} has no ContextOS schema. {run} to create it, then start the server again."
    if status.state == "outdated":
        if status.unknown_revisions:
            return (
                f"{where} is at revision {', '.join(status.unknown_revisions)}, which this build of ContextOS "
                f"does not know (latest here: {heads}). It was probably migrated by a newer version; run that "
                "version, or restore a backup taken before the upgrade."
            )
        current = ", ".join(status.current)
        return (
            f"{where} is at revision {current} but this build needs {heads}. {run} to apply the pending "
            "migrations, then start the server again."
        )
    if status.state == "incomplete":
        missing = ", ".join(status.missing_tables[:8]) + (" …" if len(status.missing_tables) > 8 else "")
        if status.current:
            return (
                f"{where} records revision {', '.join(status.current)} but is missing ContextOS tables ({missing}); "
                "it was changed outside the migrations. Restore those tables from a backup, or back the data up "
                f"and recreate the database with `{MIGRATE_COMMAND}`."
            )
        return (
            f"{where} is missing ContextOS tables ({missing}) and has no migration history. Back it up and "
            f"recreate it with `{MIGRATE_COMMAND}` on an empty database."
        )
    if status.state == "unversioned":
        return (
            f"{where} was created without migrations (no alembic_version table). {run}: it adopts the "
            "schema when it matches this version exactly, or explains what differs."
        )
    return f"{where} is at the latest revision ({heads})."


def ensure_schema_ready(engine: Engine, *, allow_unversioned: bool = False) -> SchemaStatus:
    """Raise :class:`SchemaNotReadyError` unless the schema is at the latest revision.

    ``allow_unversioned`` accepts a complete schema created by ``create_all`` (tests and local
    development); production passes ``False``.
    """
    status = schema_status(engine)
    if status.ok or (allow_unversioned and status.state == "unversioned"):
        return status
    raise SchemaNotReadyError(describe(status, engine.url.render_as_string(hide_password=False)), status)


def schema_differences(engine: Engine) -> list[str]:
    """Differences between the live schema and the models, as Alembic autogenerate sees them."""
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        return [repr(diff) for diff in compare_metadata(context, Base.metadata)]


@dataclass(frozen=True)
class UpgradeResult:
    action: Literal["upgraded", "adopted", "unchanged"]
    before: tuple[str, ...]
    heads: tuple[str, ...]


def upgrade_to_head(engine: Engine, database_url: str, *, configure_logging: bool = True) -> UpgradeResult:
    """Apply every pending migration. An unversioned schema that matches the models exactly is stamped
    (adopted) instead; one that differs raises :class:`SchemaNotReadyError` listing the differences."""
    from alembic import command

    if not migration_files():
        raise SchemaNotReadyError(
            f"No Alembic migrations found under {SCRIPT_LOCATION / 'versions'}; this "
            "installation is incomplete (the alembic/ directory must ship with the server)."
        )
    status = schema_status(engine)
    config = alembic_config(database_url, configure_logging=configure_logging)
    if status.state == "unversioned":
        diffs = schema_differences(engine)
        if diffs:
            shown = "; ".join(diffs[:5]) + (f"; and {len(diffs) - 5} more" if len(diffs) > 5 else "")
            raise SchemaNotReadyError(
                f"The database {display_url(database_url)} was created without migrations and differs from this "
                f"version's schema ({shown}). Back it up and recreate it with `{MIGRATE_COMMAND}` on an empty "
                "database, or migrate it by hand and then run `alembic stamp head`.",
                status,
            )
        command.stamp(config, "head")
        return UpgradeResult("adopted", status.current, head_revisions())
    if status.state == "incomplete" or (status.state == "outdated" and status.unknown_revisions):
        raise SchemaNotReadyError(describe(status, database_url), status)
    if status.ok:
        return UpgradeResult("unchanged", status.current, status.heads)
    command.upgrade(config, "head")
    after = schema_status(engine)
    if not after.ok:
        raise SchemaNotReadyError(describe(after, database_url), after)
    return UpgradeResult("upgraded", status.current, after.heads)
