"""Incident numbers (INC-<n>) come from the atomic per-organisation counter ``incident_seq``.

Regression: numbers were ``max(number) + 1`` read before the insert, so two transactions creating an
incident at the same time (an analyst and the ingestion pipeline's escalation) stored the same INC-n.
Migration ``0002_incident_seq`` adds the counter and backfills it from existing incidents.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select, text

from alembic import command
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.database.migrations import alembic_config, head_revisions, schema_differences, schema_status
from app.database.session import make_engine, session_factory, set_engine
from app.models import Incident, Organization
from app.services.incidents import create_incident


def _create(client, org, title: str) -> dict:
    response = client.post(
        "/api/v1/incidents",
        headers=org.user_headers,
        json={"title": title, "summary": "", "severity": "high"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_numbers_come_from_the_org_counter_not_the_highest_row(client, org, other_org, db):
    assert [_create(client, org, t)["number"] for t in ("first", "second")] == [1, 2]
    assert _create(client, other_org, "theirs")["number"] == 1  # every organisation counts on its own

    # A concurrent transaction that read max(number) = 2 before this one committed would have reused
    # INC-3; the counter hands out the next value regardless of which rows this session can see.
    db.rollback()
    db.execute(text("UPDATE organizations SET incident_seq = 7 WHERE id = :id"), {"id": org.org_id})
    db.commit()
    assert _create(client, org, "after a concurrent create")["number"] == 8


def test_migration_backfills_the_counter_from_existing_incidents(tmp_path: Path):
    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    engine = make_engine(url)
    config = alembic_config(url, configure_logging=False)
    try:
        command.upgrade(config, "0001_initial")
        now = utcnow().isoformat()
        with engine.begin() as conn:
            for org_id, numbers in (("org_A", (1, 2, 5)), ("org_B", ()), ("org_C", (3,))):
                conn.execute(
                    text(
                        "INSERT INTO organizations (id, name, slug, settings, audit_seq, event_seq, task_seq, "
                        "created_at, updated_at) VALUES (:id, :id, :id, '{}', 0, 0, 0, :now, :now)"
                    ),
                    {"id": org_id, "now": now},
                )
                for n in numbers:
                    conn.execute(
                        text(
                            "INSERT INTO incidents (id, organization_id, number, title, summary, severity, status, "
                            "opened_at, created_by, tags, is_simulation, created_at, updated_at) VALUES "
                            "(:id, :org, :n, 't', '', 'high', 'open', :now, 'system', '[]', 0, :now, :now)"
                        ),
                        {"id": new_id("incident"), "org": org_id, "n": n, "now": now},
                    )
        command.upgrade(config, "head")
        assert schema_status(engine).current == head_revisions() and schema_differences(engine) == []
        with engine.connect() as conn:
            seqs = dict(conn.execute(text("SELECT id, incident_seq FROM organizations")).all())
        assert seqs == {"org_A": 5, "org_B": 0, "org_C": 3}

        set_engine(engine)
        with session_factory()() as db:
            incident = create_incident(db, "org_A", title="next", summary="", severity="low")
            db.commit()
            assert incident.number == 6
            assert db.scalar(select(Organization.incident_seq).where(Organization.id == "org_A")) == 6
            assert db.scalar(select(Incident.number).where(Incident.id == incident.id)) == 6

        command.downgrade(config, "0001_initial")
        with engine.connect() as conn:
            columns = {row[1] for row in conn.execute(text("PRAGMA table_info(organizations)"))}
        assert "incident_seq" not in columns
    finally:
        engine.dispose()
