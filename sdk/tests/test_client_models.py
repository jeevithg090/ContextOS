"""Envelope mirror: serialisation, validation, and parity with the server contract."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from contextos.models import (
    AgentRef,
    DecisionResponse,
    EventEnvelope,
    EventResult,
    EventType,
    ToolRef,
    new_correlation_id,
    new_event_id,
    new_session_id,
)

AGENT = AgentRef(name="billing-bot", framework="python_sdk")


def test_ids_are_prefixed_uuid4_and_valid_for_the_server_pattern() -> None:
    import re

    pattern = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
    for maker, prefix in ((new_event_id, "evt_"), (new_session_id, "ses_"), (new_correlation_id, "cor_")):
        value = maker()
        assert value.startswith(prefix) and len(value) == len(prefix) + 32
        assert pattern.match(value)
    assert new_event_id() != new_event_id()


def test_wire_format_omits_none_and_keeps_schema_version() -> None:
    env = EventEnvelope(
        event_type=EventType.TOOL_REQUESTED,
        agent=AGENT,
        session_id="ses_1",
        tool=ToolRef(name="send_email", category_hint="email"),
        arguments={"to": "a@b.co"},
    )
    wire = env.to_wire()
    assert wire["schema_version"] == "1.0"
    assert wire["event_type"] == "tool.requested"
    assert wire["tool"] == {"name": "send_email", "provider": "unknown", "category_hint": "email"}
    assert "destination" not in wire and "content" not in wire
    datetime.fromisoformat(wire["timestamp"])  # ISO-8601
    json.dumps(wire)  # JSON-safe


def test_client_supplied_trust_or_decision_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        EventEnvelope(event_type="session.started", agent=AGENT, session_id="ses_1", trust_level="TRUSTED")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ToolRef(name="x", decision="ALLOW")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("event_type", "fields"),
    [
        ("context.ingested", {"content": "x"}),  # missing source
        ("prompt.submitted", {}),
        ("tool.requested", {}),
        ("agent.delegated", {}),
        ("agent.message", {}),
        ("mcp.server_connected", {}),
    ],
)
def test_shape_rules_match_the_server(event_type: str, fields: dict) -> None:
    with pytest.raises(ValidationError):
        EventEnvelope(event_type=event_type, agent=AGENT, session_id="ses_1", **fields)


def test_session_id_pattern_and_content_limit() -> None:
    with pytest.raises(ValidationError):
        EventEnvelope(event_type="session.started", agent=AGENT, session_id="bad id with spaces")
    with pytest.raises(ValidationError):
        EventEnvelope(event_type="prompt.submitted", agent=AGENT, session_id="s", content="x" * 200_001)


def test_response_models_ignore_unknown_server_fields() -> None:
    d = DecisionResponse.model_validate(
        {
            "decision": "DENY",
            "enforcement": "enforced",
            "reason": "r",
            "policy_decision_id": "pd",
            "tool_invocation_id": "ti",
            "new_field": 1,
        }
    )
    assert d.decision == "DENY" and d.restrictions == {}
    r = EventResult.model_validate({"event_id": "e", "status": "duplicate", "future": True})
    assert r.status == "duplicate"
