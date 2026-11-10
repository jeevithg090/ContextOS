"""Contract parity: the SDK's envelope mirror must match backend/app/events/envelope.py exactly.

Skipped when the server package is not importable (e.g. the SDK installed on its own).
"""

from __future__ import annotations

import pytest

from contextos.models import AgentRef, EventEnvelope, SourceRef, ToolRef

AGENT = AgentRef(name="billing-bot", framework="python_sdk")


server = pytest.importorskip("app.events.envelope")

PAIRS = ["AgentRef", "SourceRef", "ToolRef", "DestinationRef", "DelegationRef", "MessageRef", "EventEnvelope",
         "EventBatch", "EventResult", "DecisionResponse"]


@pytest.mark.parametrize("name", PAIRS)
def test_field_names_match_the_server(name: str) -> None:
    import contextos.models as sdk

    assert set(getattr(sdk, name).model_fields) == set(getattr(server, name).model_fields)
    assert getattr(sdk, name).model_config.get("extra") == getattr(server, name).model_config.get("extra")


def test_sdk_wire_events_validate_against_the_server_model() -> None:
    envs = [
        EventEnvelope(event_type="context.ingested", agent=AGENT, session_id="ses_1",
                      source=SourceRef(type="web", identifier="https://example.com"), content="hello"),
        EventEnvelope(event_type="tool.completed", agent=AGENT, session_id="ses_1", correlation_id="cor_1",
                      tool=ToolRef(name="t"), result={"ok": True}, metadata={"duration_ms": 1.5}),
    ]
    for env in envs:
        parsed = server.EventEnvelope.model_validate(env.to_wire())
        assert parsed.event_id == env.event_id


def test_enum_values_match_the_server() -> None:
    from app.domain import enums as server_enums

    import contextos.models as sdk

    for name in ("EventType", "SourceType", "ToolCategory", "Decision", "ApprovalStatus"):
        assert {e.value for e in getattr(sdk, name)} == {e.value for e in getattr(server_enums, name)}
