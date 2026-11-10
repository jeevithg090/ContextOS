"""Shared fixtures.

Every test gets a fresh SQLite database file and a FastAPI TestClient bound to it.
``make_org`` creates an isolated tenant with an owner user session and an ingest/decide API key.
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
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import generate_api_key, generate_session_token, hash_password
from app.core.timeutil import utcnow
from app.database.base import Base
from app.database.session import make_engine, session_factory, set_engine
from app.domain.enums import Role

import app.models as models  # noqa: F401  (registers tables)


@pytest.fixture()
def engine(tmp_path: Path):
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
