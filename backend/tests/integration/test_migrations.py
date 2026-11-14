"""Alembic migrations: fresh upgrade matches the models, round-trips, and the startup schema guard."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, inspect, text

import app.models  # noqa: F401  (registers every table)
from alembic import command
from app.core.config import get_settings
from app.database.base import Base
from app.database.migrations import (
    MIGRATE_COMMAND,
    SCRIPT_LOCATION,
    SchemaNotReadyError,
    alembic_config,
    ensure_schema_ready,
    head_revisions,
    migration_files,
    schema_differences,
    schema_status,
    upgrade_to_head,
)
from app.database.session import make_engine, set_engine


@pytest.fixture()
def fresh(tmp_path: Path) -> tuple[Engine, str]:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    engine = make_engine(url)
    yield engine, url
    engine.dispose()


def _upgrade(engine: Engine, url: str):
    return upgrade_to_head(engine, url, configure_logging=False)


def test_revisions_form_a_single_portable_chain():
    files = migration_files()
    assert files and len(head_revisions()) == 1
    for path in files:
        source = path.read_text()
        # Revisions must not import application code (models change; migrations are history).
        assert "from app" not in source and "import app" not in source, path.name
        assert "UTCDateTime(" not in source and "astext_type=Text()" not in source, path.name
        assert "def downgrade() -> None:" in source and "pass\n" not in source.split("def downgrade")[1], (
            path.name
        )


def test_upgrade_head_on_a_fresh_database_matches_the_models(fresh):
    engine, url = fresh
    assert schema_status(engine).state == "uninitialised"
    result = _upgrade(engine, url)
    assert result.action == "upgraded" and result.before == () and result.heads == head_revisions()
    status = schema_status(engine)
    assert status.ok and status.current == head_revisions() and status.missing_tables == ()
    assert schema_differences(engine) == []  # what `alembic check` verifies
    insp = inspect(engine)
    assert set(Base.metadata.tables) <= set(insp.get_table_names())
    # Foreign keys keep their ondelete behaviour and conventional names.
    fks = {fk["name"]: fk for fk in insp.get_foreign_keys("context_items")}
    assert fks["fk_context_items_session_id_agent_sessions"]["options"].get("ondelete") == "CASCADE"
    assert fks["fk_context_items_organization_id_organizations"]["options"].get("ondelete") == "CASCADE"
    parent = {fk["name"]: fk for fk in insp.get_foreign_keys("agent_sessions")}
    assert (
        parent["fk_agent_sessions_parent_session_id_agent_sessions"]["options"].get("ondelete") == "SET NULL"
    )
    tasks = {fk["name"]: fk for fk in insp.get_foreign_keys("tasks")}
    assert tasks["fk_tasks_column_id_board_columns"]["options"].get("ondelete") == "RESTRICT"
    # Unique constraints and indexes, including the per-tenant idempotency key.
    uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints("ingested_events")}
    assert ("organization_id", "client_event_id") in uniques
    indexes = {i["name"]: i for i in insp.get_indexes("ingested_events")}
    assert indexes["ix_events_org_received"]["column_names"] == ["organization_id", "received_at"]
    assert {i["name"] for i in insp.get_indexes("users") if i["unique"]} == {"ix_users_email"}
    # Running it again is a no-op.
    assert _upgrade(engine, url).action == "unchanged"


def test_downgrade_to_base_and_upgrade_again(fresh):
    engine, url = fresh
    _upgrade(engine, url)
    config = alembic_config(url, configure_logging=False)
    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    assert schema_status(engine).state == "uninitialised"
    command.upgrade(config, "head")
    assert schema_status(engine).ok and schema_differences(engine) == []
    command.downgrade(config, "-1")
    command.upgrade(config, "head")
    assert schema_status(engine).ok


def test_migrated_schema_accepts_the_application_data_path(fresh):
    """The migrated schema (not create_all) works end to end: FKs, JSON and timezone-aware datetimes."""
    engine, url = fresh
    _upgrade(engine, url)
    set_engine(engine)
    from app.database.session import session_factory
    from app.services.bootstrap import create_organization
    from app.services.retention import purge_expired

    with session_factory()() as db:
        org, _ = create_organization(
            db,
            name="Migrated Co",
            owner_email="owner@migrated.test",
            owner_name="Owner",
            password="migrated-password-123",
        )
        db.commit()
        assert org.created_at.tzinfo is not None and org.settings["retention_days"] == 90
        assert purge_expired(db, org.id).total == 0
        db.commit()


def test_unversioned_create_all_schema_is_adopted_when_identical(tmp_path):
    url = f"sqlite:///{tmp_path / 'legacy.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    assert schema_status(engine).state == "unversioned"
    with pytest.raises(SchemaNotReadyError, match=MIGRATE_COMMAND):
        ensure_schema_ready(engine)
    assert ensure_schema_ready(engine, allow_unversioned=True).state == "unversioned"
    result = _upgrade(engine, url)
    assert result.action == "adopted" and schema_status(engine).ok
    engine.dispose()


def test_divergent_unversioned_schema_is_refused(tmp_path):
    url = f"sqlite:///{tmp_path / 'drifted.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_events_org_received"))
        conn.execute(text("ALTER TABLE agents ADD COLUMN legacy_flag INTEGER"))
    with pytest.raises(SchemaNotReadyError, match="differs from this version's schema") as err:
        _upgrade(engine, url)
    assert "ix_events_org_received" in str(err.value)
    assert schema_status(engine).state == "unversioned"  # nothing was stamped
    engine.dispose()


def test_outdated_unknown_and_incomplete_states(fresh):
    engine, url = fresh
    _upgrade(engine, url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = 'f00dfeed1234'"))
    status = schema_status(engine)
    assert status.state == "outdated" and status.unknown_revisions == ("f00dfeed1234",)
    with pytest.raises(SchemaNotReadyError, match="does not know"):
        ensure_schema_ready(engine, allow_unversioned=True)
    with pytest.raises(SchemaNotReadyError, match="newer version"):
        _upgrade(engine, url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": head_revisions()[0]})
        conn.execute(text("DROP TABLE verification_runs"))
    status = schema_status(engine)
    assert status.state == "incomplete" and status.missing_tables == ("verification_runs",)
    with pytest.raises(SchemaNotReadyError, match="missing ContextOS tables"):
        ensure_schema_ready(engine, allow_unversioned=True)
    with pytest.raises(SchemaNotReadyError, match="changed outside the migrations"):
        _upgrade(engine, url)  # init-db cannot repair it and says so instead of looping


def test_missing_migrations_directory_is_a_packaging_error(fresh, monkeypatch):
    engine, url = fresh
    monkeypatch.setattr("app.database.migrations.migration_files", lambda: [])
    with pytest.raises(SchemaNotReadyError, match="installation is incomplete"):
        _upgrade(engine, url)
    assert SCRIPT_LOCATION.is_dir()


# ----------------------------------------------------------------------------- application startup


def _start(engine: Engine) -> None:
    from app.main import create_app

    set_engine(engine)
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/ready").json()["database"] == "ok"


def test_app_refuses_to_start_on_an_empty_database(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    with pytest.raises(SchemaNotReadyError) as err:
        _start(engine)
    assert "no ContextOS schema" in str(err.value) and MIGRATE_COMMAND in str(err.value)
    engine.dispose()


def test_app_refuses_a_database_behind_the_latest_migration(fresh, monkeypatch):
    engine, url = fresh
    _upgrade(engine, url)
    current = head_revisions()
    # This build pretends to ship one more revision than the database has applied.
    monkeypatch.setattr("app.database.migrations.head_revisions", lambda: ("0002_next",))
    with pytest.raises(SchemaNotReadyError) as err:
        _start(engine)
    message = str(err.value)
    assert (
        f"at revision {current[0]} but this build needs 0002_next" in message and MIGRATE_COMMAND in message
    )


def test_production_refuses_a_schema_created_without_migrations(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 'create_all.db'}")
    Base.metadata.create_all(engine)
    _start(engine)  # accepted outside production (test fixtures build schemas this way)
    settings = get_settings()
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "cookie_secure", True)
    with pytest.raises(SchemaNotReadyError, match="created without migrations"):
        _start(engine)
    engine.dispose()


def test_app_starts_on_a_migrated_database_in_production(fresh, monkeypatch):
    engine, url = fresh
    _upgrade(engine, url)
    settings = get_settings()
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "cookie_secure", True)
    _start(engine)
