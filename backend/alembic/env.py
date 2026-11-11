"""Alembic environment.

Database URL, in priority order:

1. a connection passed programmatically via ``config.attributes["connection"]``;
2. a URL passed programmatically via ``config.attributes["database_url"]`` (``contextos-server init-db``,
   see ``app.database.migrations``);
3. ``alembic -x url=<database-url> ...``;
4. ``CONTEXTOS_DATABASE_URL`` (the application settings; ``sqlalchemy.url`` in alembic.ini is not used).

Autogenerate renders the app's column types portably (``UTCDateTime`` becomes
``sa.DateTime(timezone=True)``), so migrations never import application code. SQLite runs in batch
mode (it cannot ``ALTER`` most things in place).
"""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from sqlalchemy.engine import Connection

import app.models  # noqa: F401  (registers all tables)
from alembic import context
from app.core.config import get_settings
from app.database.base import Base, UTCDateTime
from app.database.session import make_engine

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logging", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return (config.attributes.get("database_url") or context.get_x_argument(as_dictionary=True).get("url")
            or get_settings().database_url)


def _render_item(type_: str, obj: Any, autogen_context: Any) -> str | bool:
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False  # default rendering


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
        render_item=_render_item,
    )


def run_migrations_offline() -> None:
    url = _url()
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True, render_as_batch=url.startswith("sqlite"),
        render_item=_render_item, dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = make_engine(_url())
    try:
        with engine.connect() as conn:
            sqlite = conn.dialect.name == "sqlite"
            if sqlite:
                # Batch mode rebuilds tables (create copy, drop original). With foreign keys ON, dropping a
                # parent table would fire ON DELETE CASCADE into its children, so keep them off while
                # migrating. The pragma only takes effect outside a transaction, hence the commit.
                conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
                conn.commit()
            try:
                _configure(conn)
                with context.begin_transaction():
                    context.run_migrations()
            finally:
                if sqlite:
                    conn.exec_driver_sql("PRAGMA foreign_keys=ON")
                    conn.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
