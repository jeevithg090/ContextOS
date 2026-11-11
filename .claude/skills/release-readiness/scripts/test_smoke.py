"""Tests for smoke.py's building blocks (the full run is exercised by running the script itself).

    backend/.venv/bin/python -m pytest -q -p no:cacheprovider .claude/skills/release-readiness/scripts
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402

sys.path.insert(0, str(smoke.BACKEND))
os.environ.setdefault("CONTEXTOS_SECRET_KEY", "test-secret-key-for-contextos-unit-tests-0123456789")

from app.engines.redaction import HIGH_CONFIDENCE, detect_secrets  # noqa: E402
from app.events.envelope import EventEnvelope  # noqa: E402


def test_envelopes_satisfy_the_event_contract() -> None:
    for event in (smoke.envelope("session.started", "s1", metadata={"cwd": "/work"}),
                  smoke.envelope("tool.requested", "s1", tool={"name": "WebFetch", "provider": "claude_code"},
                                 arguments={"url": "https://collector.example.invalid/x"}, correlation_id="tu-1")):
        parsed = EventEnvelope.model_validate(event)
        assert parsed.integration == "claude_code" and parsed.agent.name == smoke.AGENT


def test_canary_token_is_unique_and_detected_as_a_real_credential() -> None:
    a, b = smoke.canary_token(), smoke.canary_token()
    assert a != b and a.startswith("ghp_") and len(a) == 40
    matches = detect_secrets(f"GITHUB_TOKEN={a}")
    assert any(m.confidence >= HIGH_CONFIDENCE for m in matches), "the smoke redaction check would be meaningless"


def test_free_port_stays_in_the_allowed_range_and_skips_busy_ports() -> None:
    port = smoke.free_port(None)
    assert 18000 <= port <= 18999
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", port))
        busy.listen()
        with pytest.raises(smoke.StepError):
            smoke.free_port(port)


def test_port_outside_the_range_is_rejected() -> None:
    with pytest.raises(SystemExit):
        smoke.main(["--port", "8000"])
