"""Lazy expiry when an integration polls an approval never overwrites a decision made meanwhile.

Regression: ``get_approval_status`` (``GET /decide/approvals/{id}`` and duplicate ``/decide`` answers)
expired an overdue approval with an unconditional ORM write. A request that had read the row while it
was still ``pending`` turned a reviewer's committed ``approved``/``rejected`` into ``expired``.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from app.core.timeutil import utcnow
from app.events.bus import bus
from app.models import Approval
from app.services.approvals import get_approval_status
from tests.integration.ingestion_support import decide, tool_requested

WEBHOOK = {"url": "https://hooks.webhook.site/9f1c", "method": "POST", "body": "build=green"}


@pytest.fixture()
def published(monkeypatch) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    monkeypatch.setattr(bus, "publish", lambda org_id, message: messages.append(message))
    return messages


def _paused(client, org) -> str:
    response = decide(client, org.api_headers, tool_requested("WebFetch", WEBHOOK))
    assert response["decision"] == "REQUIRE_APPROVAL" and response["approval_status"] == "pending"
    return response["approval_id"]


def _make_overdue(db, approval_id: str) -> Approval:
    db.rollback()
    approval = db.scalar(select(Approval).where(Approval.id == approval_id))
    approval.expires_at = utcnow() - timedelta(seconds=5)
    db.commit()
    return approval


def test_poll_after_a_concurrent_decision_keeps_the_decision(client, seeded_org, db, published):
    approval_id = _paused(client, seeded_org)
    approval = _make_overdue(db, approval_id)
    assert approval.status == "pending"  # this session now holds a stale "pending" copy

    # A reviewer's decision lands after this request read the row (simulated without refreshing it).
    db.execute(
        update(Approval)
        .where(Approval.id == approval_id)
        .values(status="approved", decided_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    assert approval.status == "pending"

    published.clear()
    result = get_approval_status(db, seeded_org.org_id, approval_id)
    db.commit()
    assert result.status == "approved"
    db.expire_all()
    assert db.scalar(select(Approval.status).where(Approval.id == approval_id)) == "approved"
    assert not any(m["type"] == "approval.decided" for m in published)


def test_poll_of_an_overdue_pending_approval_expires_it_once(client, seeded_org, db, published):
    approval_id = _paused(client, seeded_org)
    _make_overdue(db, approval_id)
    published.clear()

    first = client.get(f"/api/v1/decide/approvals/{approval_id}", headers=seeded_org.api_headers)
    second = client.get(f"/api/v1/decide/approvals/{approval_id}", headers=seeded_org.api_headers)
    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == second.json()["status"] == "expired"
    expiries = [m for m in published if m["type"] == "approval.decided" and m["status"] == "expired"]
    assert len(expiries) == 1  # the second poll found it already closed and announced nothing
