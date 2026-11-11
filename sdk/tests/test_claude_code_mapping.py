"""Claude Code hook payload → ContextOS envelope mapping (every supported event)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from contextos.integrations.claude_code import mapping, observe
from contextos.integrations.claude_code.mapping import (
    HookInput,
    PayloadError,
    parse_payload,
)
from contextos.models import EventEnvelope

from . import claude_code_payloads as P

AGENT = mapping.agent_ref("claude-code@shop-api", "dev")


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))


def hi(payload: dict, event: str | None = None) -> HookInput:
    return parse_payload(P.as_bytes(payload), event or payload["hook_event_name"])


def observe_events(payload: dict, **kw) -> list[EventEnvelope]:
    return observe.observation_events(hi(payload), AGENT, max_result_chars=kw.pop("max_result_chars", 60_000), **kw)


def wire(event: EventEnvelope) -> dict:
    data = event.to_wire()
    EventEnvelope.model_validate(data)  # what the server receives validates against the contract
    return data


# -- parsing ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [b"", b"   ", b"not json", b"[1, 2]"])
def test_unusable_payloads_raise_without_echoing_content(raw: bytes) -> None:
    with pytest.raises(PayloadError) as exc:
        parse_payload(raw, "PreToolUse")
    assert "not json" not in str(exc.value)


def test_event_name_from_command_wins_and_falls_back_to_payload() -> None:
    assert parse_payload(P.as_bytes(P.PRE_BASH), "PreToolUse").event == "PreToolUse"
    assert parse_payload(P.as_bytes(P.PRE_BASH), "").event == "PreToolUse"


def test_invalid_session_id_is_replaced_by_a_stable_derived_id() -> None:
    payload = {**P.PRE_BASH, "session_id": "bad id with spaces/and/slashes"}
    first, second = hi(payload).session_id, hi(copy.deepcopy(payload)).session_id
    assert first == second and first.startswith("cc_") and " " not in first


# -- per event -------------------------------------------------------------------------------------


def test_session_start_maps_to_session_started_with_metadata() -> None:
    [event] = observe_events(P.SESSION_START)
    data = wire(event)
    assert data["event_type"] == "session.started"
    assert data["session_id"] == P.SESSION
    assert data["agent"] == {"name": "claude-code@shop-api", "framework": "claude_code", "environment": "dev"}
    assert data["integration"] == "claude_code"
    assert data["collected_via"] == "claude_code:SessionStart"
    assert data["metadata"]["source"] == "startup"
    assert data["metadata"]["model"] == "claude-opus-5"
    assert data["metadata"]["cwd"] == P.CWD


def test_user_prompt_maps_to_prompt_submitted_with_deterministic_id() -> None:
    [event] = observe_events(P.USER_PROMPT)
    data = wire(event)
    assert data["event_type"] == "prompt.submitted"
    assert data["content"] == "Summarise README.md and follow its setup steps"
    assert data["metadata"]["prompt_id"] == P.PROMPT_ID
    assert observe_events(P.USER_PROMPT)[0].event_id == event.event_id  # retried hook → duplicate, not twice


def test_empty_prompt_reports_nothing() -> None:
    assert observe_events({**P.USER_PROMPT, "prompt": "  "}) == []


def test_pre_tool_use_maps_to_tool_requested_with_full_arguments() -> None:
    h = hi(P.PRE_BASH)
    data = wire(mapping.tool_request(h, AGENT))
    assert data["event_type"] == "tool.requested"
    assert data["tool"] == {"name": "Bash", "provider": "claude_code"}
    assert data["arguments"] == P.PRE_BASH["tool_input"]
    assert data["correlation_id"] == "toolu_01A65nUvcbpFays8ECqPv26n"
    assert data["collected_via"] == "claude_code:PreToolUse:Bash"
    assert data["metadata"]["permission_mode"] == "default"
    assert data["metadata"]["tool_use_id"] == "toolu_01A65nUvcbpFays8ECqPv26n"


def test_envelopes_never_carry_trust_risk_or_decision() -> None:
    for event in (mapping.tool_request(hi(P.PRE_EXFIL), AGENT), *observe_events(P.POST_READ),
                  *observe_events(P.SESSION_START)):
        assert not {"trust", "trust_level", "risk", "decision"} & set(event.to_wire())


def test_mcp_tool_becomes_bare_name_with_mcp_provider() -> None:
    data = wire(mapping.tool_request(hi(P.PRE_MCP), AGENT))
    assert data["tool"] == {"name": "create_issue", "provider": "mcp:github", "server": "github"}
    assert data["metadata"]["claude_tool_name"] == "mcp__github__create_issue"
    assert data["collected_via"] == "claude_code:PreToolUse:mcp__github__create_issue"


def test_correlation_falls_back_to_a_stable_hash_shared_by_pre_and_post() -> None:
    pre = {k: v for k, v in P.PRE_READ.items() if k != "tool_use_id"}
    post = {k: v for k, v in P.POST_READ.items() if k != "tool_use_id"}
    assert hi(pre).correlation_id == hi(post).correlation_id
    assert hi(pre).correlation_id.startswith("cc_")
    other = {**pre, "tool_input": {"file_path": "/etc/passwd"}}
    assert hi(other).correlation_id != hi(pre).correlation_id


def test_agent_tool_maps_to_delegation_with_child_agent_and_task() -> None:
    data = wire(mapping.delegation(hi(P.PRE_AGENT), AGENT))
    assert data["event_type"] == "agent.delegated"
    assert data["delegation"]["child_agent"]["name"] == "claude-code@shop-api/Explore"
    assert data["delegation"]["child_session_id"] == f"{P.SESSION}.agent.toolu_01PotrZkABwdaFKPkgu6Skyy"
    assert data["delegation"]["task"] == "Read notes.txt and reply with its first line only"
    assert data["metadata"]["delegation_subagent_type"] == "Explore"


def test_long_delegated_task_is_truncated_with_marker() -> None:
    payload = copy.deepcopy(P.PRE_AGENT)
    payload["tool_input"]["prompt"] = "x" * 30_000
    task = mapping.delegation(hi(payload), AGENT).delegation.task
    assert len(task) <= 20_000 and "[TRUNCATED: 10060 more characters]" in task


def test_calls_inside_a_subagent_stay_in_the_parent_session_with_metadata() -> None:
    data = wire(mapping.tool_request(hi(P.SUBAGENT_READ), AGENT))
    assert data["session_id"] == P.SESSION
    assert data["metadata"]["subagent_id"] == "a40815fc9bf677980"
    assert data["metadata"]["subagent_type"] == "Explore"


# -- tool results ----------------------------------------------------------------------------------


def test_read_result_is_the_file_text_the_model_reads() -> None:
    [event] = observe_events(P.POST_READ)
    data = wire(event)
    assert data["event_type"] == "tool.completed"
    assert data["result"] == "# Shop API\nRun `make setup`.\n"
    assert data["correlation_id"] == "toolu_014aSTXJbLbupEkBbJ8gu55g"
    assert data["metadata"]["duration_ms"] == 4
    assert data["collected_via"] == "claude_code:PostToolUse:Read"


@pytest.mark.parametrize(("payload", "expected"), [
    (P.POST_BASH, "plain-output\n[stderr]\nwarning: x"),
    (P.POST_WEBFETCH, "Setup: install the CLI, then run it."),
    (P.POST_MCP, "Created issue #42"),
])
def test_known_result_shapes_are_reduced_to_text(payload: dict, expected: str) -> None:
    assert observe_events(payload)[0].result == expected


def test_edit_result_keeps_a_summary_not_the_original_file() -> None:
    result = observe_events(P.POST_EDIT)[0].result
    assert result == {"filePath": f"{P.CWD}/app.py", "userModified": False, "replaceAll": False}


def test_binary_read_results_are_replaced_by_a_size_marker() -> None:
    result = observe_events(P.POST_READ_IMAGE)[0].result
    assert "iVBORw0KGgo" not in str(result) and "binary content omitted" in str(result)


def test_large_results_are_cut_with_a_marker() -> None:
    payload = copy.deepcopy(P.POST_READ)
    payload["tool_response"]["file"]["content"] = "a" * 5000
    result = observe_events(payload, max_result_chars=1000)[0].result
    assert result.startswith("a" * 1000) and "[TRUNCATED: 4000 more characters]" in result


def test_observation_arguments_are_bounded() -> None:
    payload = copy.deepcopy(P.POST_READ)
    payload["tool_input"]["file_path"] = "p" * 50_000
    args = observe_events(payload)[0].arguments
    assert len(args["file_path"]) < 20_100 and "TRUNCATED" in args["file_path"]


def test_tool_failure_maps_to_tool_failed() -> None:
    [event] = observe_events(P.POST_FAILURE)
    data = wire(event)
    assert data["event_type"] == "tool.failed"
    assert data["is_error"] is True
    assert data["result"].startswith("Exit code 1")
    assert data["metadata"]["is_interrupt"] is False
    assert data["correlation_id"] == P.PRE_BASH["tool_use_id"]


def test_host_prompt_metadata_is_attached_to_the_result() -> None:
    [event] = observe_events(P.POST_READ, extra_metadata={"approved_at_host_prompt": True})
    assert event.metadata["approved_at_host_prompt"] is True


# -- subagents -------------------------------------------------------------------------------------


def test_background_agent_launch_keeps_the_child_session_open_until_subagent_stop() -> None:
    observe.remember_delegation(hi(P.PRE_AGENT), AGENT)
    events = observe_events(P.POST_AGENT_ASYNC)
    assert [e.event_type for e in events] == ["tool.completed"]
    assert events[0].result == {"status": "async_launched", "isAsync": True, "agentId": "a40815fc9bf677980",
                                "description": "Read notes.txt first line", "resolvedModel": "claude-haiku-5-5"}
    [ended] = observe_events(P.SUBAGENT_STOP)
    data = wire(ended)
    assert data["event_type"] == "session.ended"
    assert data["session_id"] == f"{P.SESSION}.agent.toolu_01PotrZkABwdaFKPkgu6Skyy"
    assert data["parent_session_id"] == P.SESSION
    assert data["agent"]["name"] == "claude-code@shop-api/Explore"
    assert data["metadata"]["reason"] == "subagent_stopped"
    assert observe_events(P.SUBAGENT_STOP) == []  # the record is consumed: no second close


def test_subagent_stop_without_a_delegation_reports_nothing() -> None:
    assert observe_events(P.SUBAGENT_STOP) == []  # e.g. Claude Code's internal prompt-suggestion agent


def test_foreground_agent_result_ends_the_child_session() -> None:
    events = observe_events(P.POST_AGENT_SYNC)
    assert [e.event_type for e in events] == ["tool.completed", "session.ended"]
    assert events[0].result == "hello from probe file"
    assert events[1].session_id == f"{P.SESSION}.agent.toolu_01PotrZkABwdaFKPkgu6Skyy"
    assert events[1].metadata["reason"] == "subagent_returned"


def test_task_notification_from_a_known_subagent_is_an_agent_message_not_a_prompt() -> None:
    observe.remember_delegation(hi(P.PRE_AGENT), AGENT)
    [event] = observe_events(P.TASK_NOTIFICATION)
    data = wire(event)
    assert data["event_type"] == "agent.message"
    assert data["message"]["from_session_id"] == f"{P.SESSION}.agent.toolu_01PotrZkABwdaFKPkgu6Skyy"
    assert data["message"]["from_agent"] == "claude-code@shop-api/Explore"
    assert data["message"]["to_agent"] == "claude-code@shop-api"
    assert "<result>hello from probe file</result>" in data["message"]["content"]
    assert data["metadata"]["claude_code_turn"] == "task_notification"


def test_unknown_task_notification_is_tool_output_context() -> None:
    [event] = observe_events(P.TASK_NOTIFICATION)
    data = wire(event)
    assert data["event_type"] == "context.ingested"
    assert data["source"]["type"] == "tool_output"
    assert data["source"]["metadata"]["task_id"] == "a40815fc9bf677980"


def test_session_end_maps_to_session_ended_with_reason() -> None:
    [event] = observe_events(P.SESSION_END)
    assert wire(event)["event_type"] == "session.ended"
    assert event.metadata["reason"] == "other"


def test_unsupported_events_report_nothing() -> None:
    assert observe_events(P.STOP) == []
