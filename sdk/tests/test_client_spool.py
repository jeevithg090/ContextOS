"""Offline spool: unreachable server → JSONL spool (0600, secrets masked, capped) → flushed on next send."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from contextos.errors import Unreachable
from contextos.models import SourceRef, ToolRef
from contextos.spool import Spool, spool_path_for

from .sdk_fakes import FakeServer

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))


def test_unreachable_server_spools_events_with_private_permissions_and_masked_secrets(tmp_path: Path) -> None:
    server = FakeServer()
    server.down = True
    client = server.client(tmp_path)
    event = client.new_event(
        "context.ingested",
        "ses_1",
        source=SourceRef(type="file", identifier=".env"),
        content=f"GITHUB_TOKEN={SECRET}\nother text",
    )
    outcome = client.send_event(event)
    assert outcome.spooled == [event.event_id] and outcome.results == []
    path = client.spool.path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    raw = path.read_text()
    assert SECRET not in raw and "[REDACTED:github_token]" in raw
    stored = json.loads(raw.splitlines()[0])
    assert stored["event_id"] == event.event_id
    assert stored["metadata"]["client_redacted_before_spool"] == ["github_token"]


def test_spool_is_flushed_on_the_next_successful_send(tmp_path: Path) -> None:
    server = FakeServer()
    client = server.client(tmp_path)
    server.down = True
    first = [client.new_event("prompt.submitted", "ses_1", content=f"p{i}") for i in range(3)]
    client.send_events(first)
    assert client.spool.stats().events == 3
    server.down = False
    later = client.new_event("prompt.submitted", "ses_1", content="back online")
    client.send_event(later)
    sent_ids = [e["event_id"] for e in server.events()]
    assert sent_ids[0] == later.event_id
    assert set(sent_ids[1:]) == {e.event_id for e in first}  # re-sent with the same idempotency keys
    assert client.spool.stats().events == 0


def test_decisions_are_never_spooled(tmp_path: Path) -> None:
    server = FakeServer()
    server.down = True
    client = server.client(tmp_path)
    with pytest.raises(Unreachable):
        client.decide(
            client.new_event("tool.requested", "ses_1", tool=ToolRef(name="shell"), arguments={"c": "ls"})
        )
    assert client.spool.stats().events == 0


def test_spool_disabled_raises(tmp_path: Path) -> None:
    server = FakeServer()
    server.down = True
    client = server.client(tmp_path, spool=False)
    with pytest.raises(Unreachable):
        client.send_event(client.new_event("session.started", "ses_1"))


def test_spool_is_size_capped(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    spool = Spool(tmp_path / "s" / "a.jsonl", max_bytes=2048)
    events = [
        {"event_id": f"evt_{i}", "event_type": "prompt.submitted", "content": "x" * 300} for i in range(20)
    ]
    stored = spool.append(events)
    assert 0 < stored < 20
    assert spool.path.stat().st_size <= 2048
    assert "full" in caplog.text


def test_partial_flush_keeps_undelivered_events(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "s" / "a.jsonl")
    spool.append([{"event_id": f"evt_{i}", "event_type": "session.started"} for i in range(5)])
    calls: list[int] = []

    def send(batch: list[dict]) -> list[str]:
        calls.append(len(batch))
        if len(calls) == 2:
            raise Unreachable("down again")
        return [e["event_id"] for e in batch]

    assert spool.flush(send, batch_size=2) == 2
    remaining = [json.loads(line)["event_id"] for line in spool.path.read_text().splitlines()]
    assert remaining == ["evt_2", "evt_3", "evt_4"]
    assert list(spool.path.parent.glob("*.flushing")) == []


def test_spool_file_names_are_sanitised(tmp_path: Path) -> None:
    path = spool_path_for("../../etc/passwd agent")
    assert path.parent.name == "spool" and "/" not in path.name and path.name.endswith(".jsonl")
