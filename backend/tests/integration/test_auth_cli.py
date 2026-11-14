"""``contextos-server`` CLI against a temporary SQLite database."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from app import cli, models
from app.core.ids import new_id
from app.core.security import hash_token, verify_password

PASSWORD = "cli-owner-password"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'nested' / 'cli.db'}"


def _session(url: str) -> Session:
    return Session(create_engine(url))


def _invoke(runner: CliRunner, url: str, *args: str, input: str | None = None):
    return runner.invoke(cli.app, ["--database-url", url, *args], input=input)


@pytest.fixture()
def initialised(runner, db_url) -> str:
    result = _invoke(runner, db_url, "init-db")
    assert result.exit_code == 0, result.output
    return db_url


@pytest.fixture()
def org_slug(runner, initialised) -> str:
    result = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "Acme AI",
        "--email",
        "owner@acme.test",
        "--name-of-owner",
        "Ada Owner",
        "--password",
        PASSWORD,
    )
    assert result.exit_code == 0, result.output
    return "acme-ai"


def test_init_db_creates_directory_and_schema(runner, db_url, tmp_path):
    result = _invoke(runner, db_url, "init-db")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "nested" / "cli.db").exists()
    tables = set(inspect(create_engine(db_url)).get_table_names())
    assert {"organizations", "users", "memberships", "api_keys", "audit_events"} <= tables
    # Re-running is safe.
    assert _invoke(runner, db_url, "init-db").exit_code == 0


def test_commands_refuse_uninitialised_database(runner, db_url):
    result = _invoke(
        runner,
        db_url,
        "create-org",
        "--name",
        "X",
        "--email",
        "x@y.test",
        "--name-of-owner",
        "X",
        "--password",
        PASSWORD,
    )
    assert result.exit_code == 1
    assert "init-db" in result.output


def test_create_org_seeds_defaults_and_never_prints_password(runner, initialised):
    result = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "Acme AI",
        "--email",
        "Owner@Acme.test",
        "--name-of-owner",
        "Ada Owner",
        "--password",
        PASSWORD,
    )
    assert result.exit_code == 0, result.output
    assert "acme-ai" in result.output
    assert PASSWORD not in result.output
    with _session(initialised) as db:
        org = db.scalar(select(models.Organization).where(models.Organization.slug == "acme-ai"))
        user = db.scalar(select(models.User).where(models.User.email == "owner@acme.test"))
        membership = db.scalar(select(models.Membership).where(models.Membership.user_id == user.id))
        assert membership.organization_id == org.id and membership.role == "owner"
        assert verify_password(PASSWORD, user.password_hash)
        assert (
            db.scalars(
                select(models.SecurityPolicy).where(models.SecurityPolicy.organization_id == org.id)
            ).first()
            is not None
        )
        actions = set(
            db.scalars(select(models.AuditEvent.action).where(models.AuditEvent.organization_id == org.id))
        )
        assert "organization.created" in actions


def test_create_org_prompts_for_hidden_password(runner, initialised):
    result = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "Prompted",
        "--email",
        "p@acme.test",
        "--name-of-owner",
        "P",
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output
    assert PASSWORD not in result.output
    with _session(initialised) as db:
        user = db.scalar(select(models.User).where(models.User.email == "p@acme.test"))
        assert verify_password(PASSWORD, user.password_hash)


def test_create_org_rejects_short_password(runner, initialised):
    result = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "X",
        "--email",
        "x@y.test",
        "--name-of-owner",
        "X",
        "--password",
        "short",
    )
    assert result.exit_code == 1
    assert "at least 10" in result.output


def test_create_org_with_existing_email_requires_their_password(runner, org_slug, initialised):
    wrong = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "Second",
        "--email",
        "owner@acme.test",
        "--name-of-owner",
        "A",
        "--password",
        "not-their-password",
    )
    assert wrong.exit_code == 1
    assert "already exists" in wrong.output
    right = _invoke(
        runner,
        initialised,
        "create-org",
        "--name",
        "Second",
        "--email",
        "owner@acme.test",
        "--name-of-owner",
        "A",
        "--password",
        PASSWORD,
    )
    assert right.exit_code == 0, right.output
    with _session(initialised) as db:
        user = db.scalar(select(models.User).where(models.User.email == "owner@acme.test"))
        assert (
            len(db.scalars(select(models.Membership).where(models.Membership.user_id == user.id)).all()) == 2
        )


def test_create_api_key_prints_key_once_and_stores_hash(runner, org_slug, initialised):
    result = _invoke(
        runner,
        initialised,
        "create-api-key",
        "--org-slug",
        org_slug,
        "--name",
        "laptop",
        "--scopes",
        "ingest, decide,read",
    )
    assert result.exit_code == 0, result.output
    raw = next(word for word in result.output.split() if word.startswith("ctxk_"))
    assert result.output.count(raw) == 1
    with _session(initialised) as db:
        key = db.scalar(select(models.ApiKey).where(models.ApiKey.key_hash == hash_token(raw)))
        assert key is not None and sorted(key.scopes) == ["decide", "ingest", "read"]
        assert key.created_by_user_id is None
        audit = db.scalar(select(models.AuditEvent).where(models.AuditEvent.action == "api_key.created"))
        assert audit.actor_type == "system" and raw not in str(audit.details)


def test_create_api_key_quiet_and_agent_binding(runner, org_slug, initialised):
    with _session(initialised) as db:
        org = db.scalar(select(models.Organization).where(models.Organization.slug == org_slug))
        agent = models.Agent(id=new_id("agent"), organization_id=org.id, name="claude-code-laptop")
        db.add(agent)
        db.commit()
        agent_id = agent.id
    result = _invoke(
        runner,
        initialised,
        "create-api-key",
        "--org-slug",
        org_slug,
        "--name",
        "bound",
        "--agent",
        "claude-code-laptop",
        "-q",
    )
    assert result.exit_code == 0, result.output
    raw = result.output.strip()
    assert raw.startswith("ctxk_") and "\n" not in raw
    with _session(initialised) as db:
        assert (
            db.scalar(select(models.ApiKey).where(models.ApiKey.key_hash == hash_token(raw))).agent_id
            == agent_id
        )


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--org-slug", "acme-ai", "--name", "k", "--scopes", "admin"], "Unknown scope"),
        (["--org-slug", "nope", "--name", "k"], "No organisation"),
        (["--org-slug", "acme-ai", "--name", "k", "--agent", "ghost"], "No agent"),
    ],
)
def test_create_api_key_errors(runner, org_slug, initialised, args, message):
    result = _invoke(runner, initialised, "create-api-key", *args)
    assert result.exit_code == 1
    assert message in result.output
    assert "ctxk_" not in result.output


def test_seed_demo_reports_missing_simulation_service(runner, org_slug, initialised, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.services.simulations", None)
    result = _invoke(runner, initialised, "seed-demo", "--org-slug", org_slug)
    assert result.exit_code == 1
    assert "Simulation Lab service" in result.output


def test_seed_demo_runs_every_scenario(runner, org_slug, initialised, monkeypatch):
    calls: list[tuple[str, str]] = []
    fake = types.ModuleType("app.services.simulations")
    fake.list_scenarios = lambda: [
        {"key": "prompt_injection"},
        types.SimpleNamespace(key="credential_exfiltration"),
    ]  # type: ignore[attr-defined]

    def run_scenario(db, org_id, key):
        calls.append((org_id, key))
        if key == "credential_exfiltration":
            raise RuntimeError("pipeline unavailable")
        return types.SimpleNamespace(status="completed")

    fake.run_scenario = run_scenario  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.services.simulations", fake)
    result = _invoke(runner, initialised, "seed-demo", "--org-slug", org_slug)
    assert [k for _, k in calls] == ["prompt_injection", "credential_exfiltration"]
    assert "prompt_injection — completed" in result.output
    assert "pipeline unavailable" in result.output
    assert result.exit_code == 1  # one scenario failed; reported, not hidden


def test_serve_invokes_uvicorn(runner, monkeypatch, db_url):
    captured: dict = {}
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda target, **kw: captured.update(target=target, **kw))
    monkeypatch.delenv("CONTEXTOS_DATABASE_URL", raising=False)
    result = runner.invoke(cli.app, ["serve", "--host", "127.0.0.1", "--port", "18765"])
    assert result.exit_code == 0, result.output
    assert (
        captured["target"] == "app.main:app" and captured["port"] == 18765 and captured["host"] == "127.0.0.1"
    )
