"""``contextos-server`` operations: init-db through migrations, retention purge and demo seeding."""

from __future__ import annotations

import json
import sys
import types
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from app import cli
from app.core.ids import new_id
from app.core.timeutil import utcnow
from app.database.base import Base
from app.database.migrations import head_revisions
from app.models import Agent, AgentSession, AuditEvent, IngestedEvent, Organization, SimulationRun

PASSWORD = "cli-owner-password"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'ops.db'}"


def _invoke(runner: CliRunner, url: str, *args: str):
    return runner.invoke(cli.app, ["--database-url", url, *args])


def _session(url: str) -> Session:
    return Session(create_engine(url))


@pytest.fixture()
def org_slug(runner, db_url) -> str:
    assert _invoke(runner, db_url, "init-db").exit_code == 0
    result = _invoke(runner, db_url, "create-org", "--name", "Acme AI", "--email", "owner@acme.test",
                     "--name-of-owner", "Ada Owner", "--password", PASSWORD)
    assert result.exit_code == 0, result.output
    return "acme-ai"


# ----------------------------------------------------------------------------- init-db


def test_init_db_applies_migrations_and_is_idempotent(runner, db_url):
    first = _invoke(runner, db_url, "init-db")
    assert first.exit_code == 0, first.output
    head = head_revisions()[0]
    assert f"upgraded from an empty database to {head}" in first.output
    with _session(db_url) as db:
        assert db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == head
    second = _invoke(runner, db_url, "init-db")
    assert second.exit_code == 0 and "already at the latest migration" in second.output


def test_init_db_adopts_an_identical_schema_and_refuses_a_divergent_one(runner, tmp_path):
    same = f"sqlite:///{tmp_path / 'same.db'}"
    Base.metadata.create_all(create_engine(same))
    adopted = _invoke(runner, same, "init-db")
    assert adopted.exit_code == 0 and "stamped" in adopted.output

    drifted = f"sqlite:///{tmp_path / 'drifted.db'}"
    engine = create_engine(drifted)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE tools ADD COLUMN legacy INTEGER"))
    refused = _invoke(runner, drifted, "init-db")
    assert refused.exit_code == 1 and "differs from this version's schema" in refused.output


def test_commands_name_the_fix_for_an_unmigrated_database(runner, db_url):
    result = _invoke(runner, db_url, "purge", "--dry-run")
    assert result.exit_code == 1 and "contextos-server init-db" in result.output


# ----------------------------------------------------------------------------- purge


def _backdated_data(url: str, slug: str) -> dict[str, str]:
    now = utcnow()
    with _session(url) as db:
        org = db.scalars(select(Organization).where(Organization.slug == slug)).one()
        agent = Agent(id=new_id("agent"), organization_id=org.id, name="worker")
        db.add(agent)
        db.flush()
        old = AgentSession(id=new_id("agent_session"), organization_id=org.id, agent_id=agent.id,
                           external_session_id="old", status="ended", started_at=now - timedelta(days=201),
                           ended_at=now - timedelta(days=200), last_event_at=now - timedelta(days=200))
        db.add(old)
        db.flush()
        ids = {"org": org.id, "session": old.id}
        for key, days, session_id in (("old_event", 200, old.id), ("new_event", 1, None)):
            row = IngestedEvent(id=new_id("ingested_event"), organization_id=org.id, client_event_id=new_id("x"),
                                event_type="prompt.submitted", sequence=1, session_id=session_id, occurred_at=now,
                                received_at=now - timedelta(days=days), payload_redacted={}, payload_hash="0" * 64)
            db.add(row)
            ids[key] = row.id
        db.commit()
    return ids


def _count(url: str, model, org_id: str) -> int:
    with _session(url) as db:
        return int(db.scalar(select(func.count()).select_from(model).where(model.organization_id == org_id)) or 0)


def test_purge_dry_run_then_purge_one_organisation(runner, db_url, org_slug):
    ids = _backdated_data(db_url, org_slug)

    dry = _invoke(runner, db_url, "purge", "--dry-run")
    assert dry.exit_code == 0, dry.output
    assert "Dry run" in dry.output and "would be deleted" in dry.output and org_slug in dry.output
    assert _count(db_url, IngestedEvent, ids["org"]) == 2 and _count(db_url, AgentSession, ids["org"]) == 1

    real = _invoke(runner, db_url, "purge", "--org-slug", org_slug, "--json")
    assert real.exit_code == 0, real.output
    [report] = json.loads(real.output)
    assert report["org_slug"] == org_slug and report["dry_run"] is False and report["retention_days"] == 90
    assert report["counts"]["ingested_events"] == 1 and report["counts"]["agent_sessions"] == 1
    with _session(db_url) as db:
        events = set(db.scalars(select(IngestedEvent.id).where(IngestedEvent.organization_id == ids["org"])))
        assert events == {ids["new_event"]}
        assert db.scalar(select(AgentSession.id).where(AgentSession.id == ids["session"])) is None
        audit = db.scalars(select(AuditEvent).where(AuditEvent.organization_id == ids["org"],
                                                    AuditEvent.action == "retention.purged")).one()
        assert audit.details["counts"]["ingested_events"] == 1

    again = _invoke(runner, db_url, "purge")
    assert again.exit_code == 0 and "0 row(s) deleted" in again.output


def test_purge_unknown_organisation(runner, db_url, org_slug):
    result = _invoke(runner, db_url, "purge", "--org-slug", "nope")
    assert result.exit_code == 1 and "No organisation with slug 'nope'" in result.output


# ----------------------------------------------------------------------------- seed-demo


def _fake_simulations(scenarios: list, outcomes: dict[str, object]) -> tuple[types.ModuleType, list]:
    calls: list = []
    module = types.ModuleType("app.services.simulations")

    def run_scenario(db, org_id, scenario_id, *, triggered_by_user_id=None, agent_id=None, suite_run_id=None):
        calls.append({"org_id": org_id, "scenario_id": scenario_id, "triggered_by_user_id": triggered_by_user_id})
        outcome = outcomes.get(scenario_id)
        if isinstance(outcome, Exception):
            raise outcome
        run = SimulationRun(id=new_id("simulation_run"), organization_id=org_id, scenario_id=scenario_id,
                            scenario_name=scenario_id, status="completed", passed=bool(outcome))
        db.add(run)
        db.flush()
        return run

    module.list_scenarios = lambda: scenarios  # type: ignore[attr-defined]
    module.run_scenario = run_scenario  # type: ignore[attr-defined]
    return module, calls


def test_seed_demo_runs_only_demo_scenarios_with_the_simulation_contract(runner, db_url, org_slug, monkeypatch):
    scenarios = [types.SimpleNamespace(id="prompt_injection", name="Injection", demo=True),
                 types.SimpleNamespace(id="regression_only", name="Regression", demo=False),
                 types.SimpleNamespace(id="credential_exfiltration", name="Exfiltration", demo=True)]
    module, calls = _fake_simulations(scenarios, {"prompt_injection": True, "credential_exfiltration": False})
    monkeypatch.setitem(sys.modules, "app.services.simulations", module)
    result = _invoke(runner, db_url, "seed-demo", "--org-slug", org_slug)
    assert result.exit_code == 0, result.output
    assert [c["scenario_id"] for c in calls] == ["prompt_injection", "credential_exfiltration"]
    assert all(c["triggered_by_user_id"] is None for c in calls)
    assert "prompt_injection — completed, expectations met" in result.output
    assert "credential_exfiltration — completed, expectations NOT met" in result.output
    assert "2 scenario(s)" in result.output
    with _session(db_url) as db:  # each scenario's rows were committed
        assert {r.scenario_id for r in db.scalars(select(SimulationRun))} == {"prompt_injection",
                                                                             "credential_exfiltration"}


def test_seed_demo_runs_everything_when_nothing_is_flagged_and_reports_failures(runner, db_url, org_slug,
                                                                                 monkeypatch):
    scenarios = [types.SimpleNamespace(id="a"), {"id": "b"}, types.SimpleNamespace(id="c", demo=False)]
    module, calls = _fake_simulations(scenarios, {"a": True, "b": RuntimeError("pipeline [unavailable]"), "c": True})
    monkeypatch.setitem(sys.modules, "app.services.simulations", module)
    result = _invoke(runner, db_url, "seed-demo", "--org-slug", org_slug)
    assert [c["scenario_id"] for c in calls] == ["a", "b", "c"]
    assert result.exit_code == 1 and "pipeline [unavailable]" in result.output and "1 of 3 scenario(s) failed" in result.output
    with _session(db_url) as db:  # the failed scenario rolled back; the others were kept
        assert {r.scenario_id for r in db.scalars(select(SimulationRun))} == {"a", "c"}


def test_seed_demo_with_the_real_simulation_lab(runner, db_url, org_slug):
    simulations = pytest.importorskip("app.services.simulations")
    if not hasattr(simulations, "run_scenario") or not hasattr(simulations, "list_scenarios"):
        pytest.skip("app.services.simulations does not provide the scenario API yet")
    result = _invoke(runner, db_url, "seed-demo", "--org-slug", org_slug)
    assert result.exit_code == 0, result.output
    with _session(db_url) as db:
        runs = list(db.scalars(select(SimulationRun)))
        assert runs and all(r.status in ("completed", "failed") for r in runs)
        assert db.scalar(select(func.count()).select_from(IngestedEvent).where(
            IngestedEvent.is_simulation.is_(False))) == 0  # demo data is flagged as simulation


def test_create_org_bootstrap_seeds_the_default_boards(runner, db_url, org_slug):
    from app.models import Board

    with _session(db_url) as db:
        org = db.scalars(select(Organization).where(Organization.slug == org_slug)).one()
        assert {b.name for b in db.scalars(select(Board).where(Board.organization_id == org.id))} == {
            "Engineering", "Security Remediation"}
        seeded = db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org.id,
                                                     AuditEvent.action == "organization.defaults_seeded")).one()
        assert seeded.details["default_board"] is True and seeded.details["boards_created"] == 2
