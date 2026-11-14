"""Codex hook payload → event envelope mapping (pure), per hook event, with captured payload shapes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contextos.integrations.codex import mapping, observe
from contextos.integrations.codex.mapping import parse_payload
from contextos.integrations.codex.results import extract_result
from contextos.models import EventEnvelope

from . import codex_payloads as P

AGENT = mapping.agent_ref("codex@payments-service", "development")
FORBIDDEN = {"trust_level", "trust", "risk", "risk_score", "severity", "decision", "enforcement"}


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))


def h(payload: dict, event: str | None = None) -> mapping.HookInput:
    return parse_payload(P.as_bytes(payload), event if event is not None else payload["hook_event_name"])


def wire(envelope: EventEnvelope) -> dict:
    data = envelope.to_wire()
    assert not FORBIDDEN & set(data), "the envelope must carry facts only"
    EventEnvelope.model_validate(data)  # round-trips through the strict model
    return data


def test_session_start_and_end() -> None:
    [started] = observe.observation_events(h(P.SESSION_START), AGENT, max_result_chars=1000)
    data = wire(started)
    assert data["event_type"] == "session.started" and data["session_id"] == P.SESSION
    assert data["integration"] == "openai_codex" and data["collected_via"] == "openai_codex:SessionStart"
    assert data["agent"] == {
        "name": "codex@payments-service",
        "framework": "openai_codex",
        "environment": "development",
    }
    assert data["metadata"]["source"] == "startup" and data["metadata"]["model"] == P.MODEL
    assert "transcript_path" not in json.dumps(data)  # never read or forwarded
    [ended] = observe.observation_events(h(P.SESSION_END), AGENT, max_result_chars=1000)
    assert wire(ended)["event_type"] == "session.ended" and ended.metadata["reason"] == "other"


def test_user_prompt_is_a_prompt_with_a_stable_id() -> None:
    [event] = observe.observation_events(h(P.USER_PROMPT), AGENT, max_result_chars=1000)
    data = wire(event)
    assert data["event_type"] == "prompt.submitted" and data["content"] == P.USER_PROMPT["prompt"]
    assert data["metadata"]["turn_id"] == P.TURN
    [again] = observe.observation_events(h(P.USER_PROMPT), AGENT, max_result_chars=1000)
    assert again.event_id == event.event_id  # a retried hook deduplicates on the server


def test_a_sub_agent_task_is_a_message_between_agents_not_a_persons_prompt() -> None:
    [event] = observe.observation_events(h(P.SUBAGENT_PROMPT), AGENT, max_result_chars=1000)
    data = wire(event)
    assert data["event_type"] == "agent.message"
    assert data["message"]["from_agent"] == AGENT.name and data["message"]["content"] == "say hi"
    assert (
        data["metadata"]["subagent_id"] == P.SUBAGENT and data["metadata"]["codex_turn"] == "subagent_input"
    )
    [root] = observe.observation_events(h(P.USER_PROMPT), AGENT, max_result_chars=1000)
    assert root.event_id != event.event_id


def test_tool_request_carries_the_full_input_and_the_tool_use_id() -> None:
    envelope = mapping.tool_request(h(P.PRE_BASH), AGENT)
    data = wire(envelope)
    assert data["event_type"] == "tool.requested"
    assert data["tool"] == {
        "name": "Bash",
        "provider": "openai_codex",
    }  # no category hint: the server classifies
    assert data["arguments"] == {"command": "cat README.md"}
    assert data["correlation_id"] == "call_0" and data["collected_via"] == "openai_codex:PreToolUse:Bash"
    long_patch = P.with_input(
        P.PRE_PATCH, {"command": "*** Begin Patch\n" + "+x\n" * 50_000 + "*** End Patch\n"}
    )
    assert mapping.tool_request(h(long_patch), AGENT).arguments == long_patch["tool_input"]  # never truncated


def test_mcp_tools_name_their_server() -> None:
    data = wire(mapping.tool_request(h(P.PRE_MCP), AGENT))
    assert data["tool"]["name"] == "add" and data["tool"]["provider"] == "mcp:toolbox"
    assert data["tool"]["server"] == "toolbox" and data["metadata"]["codex_tool_name"] == "mcp__toolbox__add"
    assert mapping.split_tool_name("mcp__broken") == ("mcp__broken", "openai_codex", None)


def test_non_object_tool_input_is_wrapped() -> None:
    data = wire(mapping.tool_request(h(P.with_input(P.PRE_BASH, "not json")), AGENT))
    assert data["arguments"] == {"input": "not json"}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (P.POST_BASH, P.POST_BASH["tool_response"]),
        (P.POST_PATCH, P.POST_PATCH["tool_response"]),
        (P.POST_MCP, "5.0"),
    ],
)
def test_tool_results_are_the_text_the_model_reads(payload: dict, expected: str) -> None:
    [event] = observe.observation_events(h(payload), AGENT, max_result_chars=60_000)
    data = wire(event)
    assert data["event_type"] == "tool.completed" and data["result"] == expected
    assert data["correlation_id"] == payload["tool_use_id"]
    assert event.event_id == mapping.tool_result(h(payload), AGENT, max_result_chars=60_000).event_id


def test_a_sub_agent_result_read_through_wait_agent_is_tool_output() -> None:
    [event] = observe.observation_events(h(P.POST_WAIT), AGENT, max_result_chars=60_000)
    data = wire(event)
    assert data["tool"] == {"name": "multi_agent_v1wait_agent", "provider": "openai_codex"}
    assert "hi from the sub-agent" in data["result"]


def test_result_shapes_and_limits() -> None:
    items = [
        {"type": "input_text", "text": "first"},
        {"type": "input_image", "image_url": "data:image/png;base64," + "A" * 400},
    ]
    assert extract_result("view_image", items, 1000) == "first\n[input_image content omitted]"
    structured = extract_result("mcp__db__query", {"content": [], "structuredContent": {"rows": 3}}, 1000)
    assert structured == {"content": [], "structuredContent": {"rows": 3}}
    blob = extract_result("custom", {"image": "B" * 1000}, 1000)
    assert blob == {"image": "[binary content omitted: 1000 characters]"}
    cut = extract_result("Bash", "x" * 5000, 1000)
    assert isinstance(cut, str) and len(cut) < 1200 and "TRUNCATED" in cut


def test_spawn_agent_delegates_and_sub_agent_stop_closes_the_child_session() -> None:
    pre = h(P.PRE_SPAWN)
    delegated = wire(mapping.delegation(pre, AGENT))
    assert delegated["event_type"] == "agent.delegated"
    child_session = delegated["delegation"]["child_session_id"]
    assert delegated["delegation"]["child_agent"]["name"] == "codex@payments-service/explorer"
    assert delegated["delegation"]["task"] == "say hi" and child_session == f"{P.SESSION}.agent.call_5"
    from contextos.integrations.codex.enforce import remember_delegation

    remember_delegation(pre, AGENT)

    post = observe.observation_events(h(P.POST_SPAWN), AGENT, max_result_chars=1000)
    assert [e.event_type for e in post] == ["tool.completed"]
    assert h(P.POST_SPAWN).launched_agent_id == P.SUBAGENT
    [message] = observe.observation_events(h(P.SUBAGENT_PROMPT), AGENT, max_result_chars=1000)
    assert message.message is not None and message.message.to_agent == "codex@payments-service/explorer"

    [ended] = observe.observation_events(h(P.SUBAGENT_STOP), AGENT, max_result_chars=1000)
    data = wire(ended)
    assert data["event_type"] == "session.ended" and data["session_id"] == child_session
    assert (
        data["parent_session_id"] == P.SESSION and data["agent"]["name"] == "codex@payments-service/explorer"
    )
    assert observe.observation_events(h(P.SUBAGENT_STOP), AGENT, max_result_chars=1000) == []  # closed once


def test_calls_inside_a_sub_agent_stay_in_the_session_with_its_id() -> None:
    data = wire(mapping.tool_request(h(P.SUBAGENT_BASH), AGENT))
    assert data["session_id"] == P.SESSION
    assert data["metadata"]["subagent_id"] == P.SUBAGENT and data["metadata"]["subagent_type"] == "explorer"


def test_an_unknown_sub_agent_stop_reports_nothing() -> None:
    assert observe.observation_events(h(P.SUBAGENT_STOP), AGENT, max_result_chars=1000) == []


def test_unusable_session_ids_get_a_stable_stand_in() -> None:
    odd = {**P.PRE_BASH, "session_id": "has spaces / slashes"}
    first, second = h(odd).session_id, h(odd).session_id
    assert first == second and first.startswith("cx_")
    assert h({**P.PRE_BASH, "tool_use_id": None}).correlation_id.startswith("cx_")


@pytest.mark.parametrize("raw", [b"", b"   ", b"{truncated", b"[1, 2]"])
def test_unusable_input_is_a_payload_error_that_never_echoes_it(raw: bytes) -> None:
    with pytest.raises(mapping.PayloadError) as info:
        parse_payload(raw, "PreToolUse")
    assert "truncated" not in str(info.value)


def test_the_event_name_falls_back_to_the_payload() -> None:
    assert parse_payload(P.as_bytes(P.PRE_BASH), "").event == "PreToolUse"
    with pytest.raises(mapping.PayloadError, match="event name"):
        parse_payload(b"{}", "")
