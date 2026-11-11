"""Helpers shared by the Engineering Workspace integration tests."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import generate_session_token, hash_password
from app.core.timeutil import utcnow
from app.models import AuthSession, Membership, User

API = "/api/v1/workspace"


def add_member(db: Session, org_id: str, role: str, name: str = "Member") -> tuple[str, dict[str, str]]:
    """Add a user with ``role`` to an existing organisation. Returns ``(user_id, session headers)``."""
    user = User(id=new_id("user"), email=f"{new_id('x').lower()}@example.test", name=name,
                password_hash=hash_password("correct-horse-battery-staple"))
    db.add(user)
    db.flush()
    db.add(Membership(id=new_id("membership"), organization_id=org_id, user_id=user.id, role=role))
    token, token_hash = generate_session_token()
    db.add(AuthSession(id=new_id("auth_session"), user_id=user.id, token_hash=token_hash,
                       expires_at=utcnow() + timedelta(hours=1)))
    db.commit()
    return user.id, {"Authorization": f"Bearer {token}", "X-Requested-With": "contextos"}


def ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json() if response.content else None


def boards(client: TestClient, headers: dict[str, str]) -> list[dict[str, Any]]:
    return ok(client.get(f"{API}/boards", headers=headers))["items"]


def board_by_name(client: TestClient, headers: dict[str, str], name: str) -> dict[str, Any]:
    board_id = next(b["id"] for b in boards(client, headers) if b["name"] == name)
    return ok(client.get(f"{API}/boards/{board_id}", headers=headers))


def column(board: dict[str, Any], name: str) -> dict[str, Any]:
    return next(c for c in board["columns"] if c["name"] == name)


def create_task(client: TestClient, headers: dict[str, str], title: str = "Fix the thing", **fields: Any) -> dict:
    return ok(client.post(f"{API}/tasks", json={"title": title, **fields}, headers=headers), 201)


def move(client: TestClient, headers: dict[str, str], task_id: str, column_id: str, **kw: Any) -> Any:
    return client.post(f"{API}/tasks/{task_id}/move", json={"column_id": column_id, **kw}, headers=headers)


def get_task(client: TestClient, headers: dict[str, str], task_id: str) -> dict[str, Any]:
    return ok(client.get(f"{API}/tasks/{task_id}", headers=headers))


def verify(client: TestClient, headers: dict[str, str], task_id: str, status: str = "passed", **kw: Any) -> dict:
    body = {"kind": "test_run", "status": status, "summary": f"pytest {status}", **kw}
    return ok(client.post(f"{API}/tasks/{task_id}/verifications", json=body, headers=headers), 201)


def activity_kinds(task: dict[str, Any]) -> list[str]:
    return [a["kind"] for a in task["activity"]]
