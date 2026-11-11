"""Shared fixtures.

Every test gets a fresh SQLite database file and a FastAPI TestClient bound to it.
``make_org`` creates an isolated tenant with an owner user session and an ingest/decide API key.

PostgreSQL: set ``CONTEXTOS_TEST_DATABASE_URL`` (e.g. ``postgresql+psycopg://user:pw@127.0.0.1:18432/contextos_test``)
to run the same tests against a dedicated test database instead. Its tables are dropped and recreated
once per run and every table is truncated before each test, so the database name must contain "test".
Tests that build their own SQLite databases (CLI, migrations) keep doing so.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

os.environ.setdefault("CONTEXTOS_ENV", "test")
os.environ.setdefault("CONTEXTOS_SECRET_KEY", "test-secret-key-for-contextos-unit-tests-0123456789")
os.environ.setdefault("CONTEXTOS_SERVE_FRONTEND", "false")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

import app.models as models  # noqa: F401  (registers tables)
from app.core.ids import new_id
from app.core.security import generate_api_key, generate_session_token, hash_password
from app.core.timeutil import utcnow
from app.database.base import Base
from app.database.session import make_engine, session_factory, set_engine
from app.domain.enums import Role

TEST_DATABASE_URL = os.environ.get("CONTEXTOS_TEST_DATABASE_URL", "").strip() or None


def _external_test_engine(url: str) -> Engine:
    parsed = make_url(url)
    if "test" not in (parsed.database or "").lower():
        raise pytest.UsageError(
            "CONTEXTOS_TEST_DATABASE_URL must name a dedicated test database (its name must contain 'test'): "
            "every ContextOS table in it is dropped, recreated and truncated."
        )
    if parsed.get_backend_name() == "postgresql":
        # Fail a test that waits on a lock (e.g. a fixture session holding a row lock a request needs)
        # instead of hanging the whole run.
        return create_engine(url, pool_pre_ping=True,
                             connect_args={"options": "-c lock_timeout=30s -c statement_timeout=300s"})
    return make_engine(url)


def _reset_tables(eng: Engine) -> None:
    with eng.begin() as conn:
        if conn.dialect.name == "postgresql":
            # Sessions a previous test leaked ("idle in transaction") would block TRUNCATE.
            conn.exec_driver_sql(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() "
                "AND pid <> pg_backend_pid() AND state IN ('idle in transaction', 'idle in transaction (aborted)')"
            )
            names = ", ".join(conn.dialect.identifier_preparer.quote(t.name) for t in Base.metadata.sorted_tables)
            conn.exec_driver_sql(f"TRUNCATE {names} RESTART IDENTITY CASCADE")
        else:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())


@pytest.fixture(scope="session")
def _external_engine() -> Iterator[Engine | None]:
    if TEST_DATABASE_URL is None:
        yield None
        return
    eng = _external_test_engine(TEST_DATABASE_URL)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def engine(tmp_path: Path, _external_engine: Engine | None):
    if _external_engine is not None:
        _reset_tables(_external_engine)
        set_engine(_external_engine)
        yield _external_engine
        return
    eng = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(eng)
    set_engine(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine) -> Iterator[Session]:
    session = session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def app(engine):
    from app.main import create_app

    return create_app()


@pytest.fixture()
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@dataclass
class OrgCtx:
    org_id: str
    user_id: str
    email: str
    password: str
    session_token: str
    api_key: str
    api_key_id: str
    role: str
    extra: dict = field(default_factory=dict)

    @property
    def user_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.session_token}", "X-Requested-With": "contextos"}

    @property
    def api_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}


def _make_org(db: Session, *, name: str, role: str = Role.OWNER, scopes: list[str] | None = None) -> OrgCtx:
    from datetime import timedelta

    org = models.Organization(id=new_id("organization"), name=name, slug=name.lower().replace(" ", "-") + "-" + new_id("x")[-6:].lower(), settings={})
    db.add(org)
    db.flush()
    email = f"{org.slug}@example.test"
    password = "correct-horse-battery-staple"
    user = models.User(id=new_id("user"), email=email, name=f"{name} Owner", password_hash=hash_password(password))
    db.add(user)
    db.flush()
    db.add(models.Membership(id=new_id("membership"), organization_id=org.id, user_id=user.id, role=role))
    token, token_hash = generate_session_token()
    db.add(models.AuthSession(id=new_id("auth_session"), user_id=user.id, token_hash=token_hash, expires_at=utcnow() + timedelta(hours=1)))
    raw_key, prefix, key_hash = generate_api_key()
    key = models.ApiKey(id=new_id("api_key"), organization_id=org.id, name="test key", prefix=prefix, key_hash=key_hash, scopes=scopes or ["ingest", "decide", "read"])
    db.add(key)
    db.commit()
    return OrgCtx(org.id, user.id, email, password, token, raw_key, key.id, role)


@pytest.fixture()
def make_org(db):
    def _factory(name: str = "Acme", **kwargs) -> OrgCtx:
        return _make_org(db, name=name, **kwargs)

    return _factory


@pytest.fixture()
def org(make_org) -> OrgCtx:
    return make_org("Acme")


@pytest.fixture()
def other_org(make_org) -> OrgCtx:
    return make_org("Globex")


@pytest.fixture()
def seeded_org(org, db) -> OrgCtx:
    """``org`` with the built-in policy pack and default trust rules installed."""
    from app.services.seed import seed_security_defaults

    seed_security_defaults(db, org.org_id)
    db.commit()
    return org
