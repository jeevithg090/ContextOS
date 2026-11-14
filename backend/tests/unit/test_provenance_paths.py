"""Risky-path analysis: untrusted origin -> session(s) -> risky tool invocation."""

from __future__ import annotations

import pytest

from app.domain.enums import SEVERITY_RANK
from app.engines.provenance import (
    OBSERVED_RELATIONSHIP_NOTE,
    ProvenanceGraph,
    RiskyPath,
    build_graph,
    find_risky_paths,
)


def t(minute: int) -> str:
    return f"2026-03-01T10:{minute:02d}:00Z"


class G:
    """Tiny builder for provenance graphs in tests."""

    def __init__(self) -> None:
        self.nodes: list[dict] = []
        self.edges: list[dict] = []

    def node(self, node_id: str, node_type: str, label: str | None = None, **attrs) -> str:
        self.nodes.append({"id": node_id, "type": node_type, "label": label or node_id, **attrs})
        return node_id

    def edge(self, src: str, dst: str, relation: str, **attrs) -> str:
        edge_id = attrs.pop("id", f"e{len(self.edges) + 1}")
        self.edges.append(
            {
                "id": edge_id,
                "src": src,
                "dst": dst,
                "relation": relation,
                "confidence": attrs.pop("confidence", "observed"),
                **attrs,
            }
        )
        return edge_id

    def build(self) -> ProvenanceGraph:
        return build_graph(self.nodes, self.edges)


INJECTION = {
    "max_severity": "high",
    "rule_ids": ["PI-001-ignore-previous"],
    "categories": ["prompt_injection"],
}


def readme_scenario(
    *,
    dest_class: str = "UNKNOWN",
    fetch: dict | None = None,
    detection: dict | None = INJECTION,
    source_trust: str = "UNKNOWN",
    timestamps: bool = True,
    with_read: bool = True,
) -> G:
    """README (untrusted) -> session -> Read .env -> WebFetch to an unclassified host."""
    g = G()
    g.node("src:readme", "source", "README.md", trust_level=source_trust)
    g.node(
        "ctx:readme",
        "context_item",
        "README.md (fetched)",
        trust_level=source_trust,
        detection_summary=detection or {},
    )
    g.node("ses:1", "session", "coding session")
    g.edge("src:readme", "ctx:readme", "source_produced_item")
    g.edge("ctx:readme", "ses:1", "item_entered_session", **({"observed_at": t(0)} if timestamps else {}))
    if with_read:
        g.node(
            "inv:read",
            "tool_invocation",
            "Read .env",
            tool_name="Read",
            decision="ALLOW",
            enforcement="enforced",
            status="completed",
            **({"requested_at": t(1)} if timestamps else {}),
        )
        g.node("res:env", "resource", ".env", sensitive=True)
        g.edge("ses:1", "inv:read", "session_invoked_tool")
        g.edge("inv:read", "res:env", "invocation_accessed_resource")
    attrs = {"tool_name": "WebFetch", "decision": "ALLOW", "enforcement": "enforced", "status": "completed"}
    attrs.update(fetch or {})
    if timestamps:
        attrs.setdefault("requested_at", t(2))
    g.node("inv:fetch", "tool_invocation", "WebFetch", **attrs)
    g.node("dst:host", "destination", "collector.example", classification=dest_class)
    g.edge("ses:1", "inv:fetch", "session_invoked_tool")
    g.edge("inv:fetch", "dst:host", "invocation_sent_to")
    return g


def only(paths: list[RiskyPath]) -> RiskyPath:
    assert len(paths) == 1, [p.title for p in paths]
    return paths[0]


# ---------------------------------------------------------------- the canonical exfiltration path


def test_readme_to_env_read_to_webfetch_unknown_host_is_one_critical_path():
    path = only(find_risky_paths(readme_scenario().build()))
    assert path.node_ids == [
        "src:readme",
        "ctx:readme",
        "ses:1",
        "inv:read",
        "res:env",
        "inv:fetch",
        "dst:host",
    ]
    assert len(path.edge_ids) == 6
    assert path.severity == "critical"
    assert path.category == "exfiltration"
    assert path.outcome == "not_prevented"
    assert path.origin_id == "src:readme" and path.sink_id == "inv:fetch"
    assert path.session_ids == ["ses:1"] and path.cross_session is False and path.order_verified is True
    assert "README.md" in path.title and "collector.example" in path.title and "WebFetch" in path.title
    assert '".env"' in path.explanation and "UNKNOWN" in path.explanation
    assert "prompt-injection" in path.explanation
    assert path.explanation.endswith(OBSERVED_RELATIONSHIP_NOTE)
    assert any("PI-001-ignore-previous" in r for r in path.reasons)
    assert path.to_dict()["node_ids"] == path.node_ids


def test_enforced_deny_is_reported_as_prevented_and_ranks_below_allowed():
    allowed = only(find_risky_paths(readme_scenario().build()))
    denied_paths = find_risky_paths(readme_scenario(fetch={"decision": "DENY", "status": "denied"}).build())
    combined = next(p for p in denied_paths if p.sink_id == "inv:fetch")
    assert combined.outcome == "prevented"
    assert "prevented" in combined.explanation and "enforced execution boundary" in combined.explanation
    assert combined.score < allowed.score
    assert SEVERITY_RANK[combined.severity] < SEVERITY_RANK[allowed.severity]
    # The Read of .env itself was NOT prevented, so it remains visible as its own path.
    read = next(p for p in denied_paths if p.sink_id == "inv:read")
    assert read.outcome == "not_prevented" and read.category == "credential_access"
    assert len(denied_paths) == 2


def test_prevented_sibling_does_not_count_as_sensitive_access():
    g = readme_scenario()
    g.nodes[3].update(decision="DENY", status="denied")  # the Read of .env was blocked at the hook
    paths = find_risky_paths(g.build())
    fetch = next(p for p in paths if p.sink_id == "inv:fetch")
    assert "inv:read" not in fetch.node_ids and fetch.category == "destination_risk"
    read = next(p for p in paths if p.sink_id == "inv:read")
    assert read.outcome == "prevented"


def test_advisory_deny_is_not_claimed_as_prevented():
    graph = readme_scenario(fetch={"decision": "DENY", "enforcement": "advisory", "status": "denied"}).build()
    path = next(p for p in find_risky_paths(graph) if p.sink_id == "inv:fetch")
    assert path.outcome == "advisory_only"
    assert "cannot confirm" in path.explanation and "was prevented" not in path.explanation


def test_observed_deny_is_not_prevented():
    graph = readme_scenario(
        fetch={"decision": "DENY", "enforcement": "observed", "status": "completed"}
    ).build()
    path = only(find_risky_paths(graph))
    assert path.outcome == "not_prevented"
    assert "nothing was prevented" in path.explanation


@pytest.mark.parametrize("worse", ["SUSPICIOUS", "BLOCKED"])
def test_suspicious_or_blocked_destination_raises_severity(worse):
    base = only(find_risky_paths(readme_scenario(detection=None, with_read=False).build()))
    worse_path = only(
        find_risky_paths(readme_scenario(detection=None, with_read=False, dest_class=worse).build())
    )
    assert worse_path.score > base.score
    assert SEVERITY_RANK[worse_path.severity] > SEVERITY_RANK[base.severity]
    assert worse_path.category == "destination_risk"


@pytest.mark.parametrize("safe", ["TRUSTED", "APPROVED"])
def test_trusted_or_approved_destination_is_not_an_outbound_risk(safe):
    paths = find_risky_paths(readme_scenario(dest_class=safe).build())
    assert [p.sink_id for p in paths] == ["inv:read"]  # only the sensitive read remains


def test_injection_detection_on_origin_raises_severity():
    plain = only(find_risky_paths(readme_scenario(detection=None).build()))
    injected = only(find_risky_paths(readme_scenario().build()))
    assert injected.score >= plain.score + 4
    assert SEVERITY_RANK[injected.severity] > SEVERITY_RANK[plain.severity]
    assert not any("injection" in r for r in plain.reasons)


def test_matched_secret_fingerprint_raises_severity_and_is_called_inferred():
    base = only(find_risky_paths(readme_scenario(detection=None).build()))
    matched = only(
        find_risky_paths(
            readme_scenario(
                detection=None,
                fetch={"matched_session_fingerprints": [{"type": "aws", "fingerprint": "f" * 16}]},
            ).build()
        )
    )
    assert matched.score >= base.score + 3
    assert "inferred match" in matched.explanation
    assert any("fingerprint" in r and "inferred" in r for r in matched.reasons)


# ---------------------------------------------------------------- no-path cases


def test_trusted_origin_without_detections_produces_no_paths():
    g = readme_scenario(source_trust="TRUSTED", detection=None)
    assert find_risky_paths(g.build()) == []


def test_low_severity_detection_on_trusted_source_is_not_an_origin():
    g = readme_scenario(source_trust="TRUSTED", detection={"max_severity": "low", "rule_ids": ["X-1"]})
    assert find_risky_paths(g.build()) == []


def test_flagged_content_from_trusted_source_is_still_an_origin():
    g = readme_scenario(source_trust="TRUSTED")
    path = only(find_risky_paths(g.build()))
    assert path.origin_id == "ctx:readme"
    assert path.title.startswith('Flagged context item "README.md (fetched)"')


def test_untrusted_content_in_unrelated_session_is_not_linked():
    g = readme_scenario(with_read=False)
    g.node("ses:other", "session", "other session")
    g.node("inv:other", "tool_invocation", "Bash", tool_name="Bash", sensitive=True)
    g.edge("ses:other", "inv:other", "session_invoked_tool")
    paths = find_risky_paths(g.build())
    assert all("ses:other" not in p.node_ids for p in paths)


def test_benign_invocation_is_not_a_sink():
    g = G()
    g.node("ctx:web", "context_item", "web page", trust_level="EXTERNAL")
    g.node("ses:1", "session")
    g.node("inv:grep", "tool_invocation", "Grep", tool_name="Grep", decision="ALLOW")
    g.node("res:src", "resource", "src/app.py", sensitive=False)
    g.edge("ctx:web", "ses:1", "item_entered_session")
    g.edge("ses:1", "inv:grep", "session_invoked_tool")
    g.edge("inv:grep", "res:src", "invocation_accessed_resource")
    assert find_risky_paths(g.build()) == []


def test_tool_call_made_before_untrusted_content_arrived_is_not_linked():
    g = readme_scenario(with_read=False, fetch={"requested_at": t(0)})
    g.edges[1]["observed_at"] = t(5)  # README entered the session after the WebFetch call
    assert find_risky_paths(g.build()) == []


def test_missing_timestamps_are_disclosed():
    path = only(find_risky_paths(readme_scenario(timestamps=False).build()))
    assert path.order_verified is False
    assert " is linked to " in path.title
    assert "order of these events is not confirmed" in path.explanation


def test_dangling_edges_in_a_hand_built_graph_are_ignored():
    graph = readme_scenario(with_read=False).build()
    graph.edges.append({"id": "bad", "src": "ses:1", "dst": "inv:ghost", "relation": "session_invoked_tool"})
    path = only(find_risky_paths(graph))
    assert "inv:ghost" not in path.node_ids


# ---------------------------------------------------------------- multi-agent (delegation) paths


def delegation_scenario(*, delegated_at: str = t(1)) -> G:
    g = G()
    g.node(
        "ctx:issue", "context_item", "GitHub issue #42", trust_level="EXTERNAL", detection_summary=INJECTION
    )
    g.node("ses:planner", "session", "planner")
    g.node("ses:worker", "session", "worker")
    g.node("inv:post", "tool_invocation", "http_request", tool_name="http_request", requested_at=t(3))
    g.node("dst:paste", "destination", "paste.example", classification="SUSPICIOUS")
    g.edge("ctx:issue", "ses:planner", "item_entered_session", observed_at=t(0))
    g.edge("ses:planner", "ses:worker", "session_delegated_to", observed_at=delegated_at)
    g.edge("ses:worker", "inv:post", "session_invoked_tool")
    g.edge("inv:post", "dst:paste", "invocation_sent_to")
    return g


def test_delegation_chain_is_a_cross_agent_path():
    path = only(find_risky_paths(delegation_scenario().build()))
    assert path.cross_session is True
    assert path.session_ids == ["ses:planner", "ses:worker"]
    assert path.category == "cross_agent_contamination"
    assert path.title.endswith("in a delegated session")
    assert '"worker"' in path.explanation and "downstream" in path.explanation
    assert path.node_ids == ["ctx:issue", "ses:planner", "ses:worker", "inv:post", "dst:paste"]


def test_delegation_before_the_content_arrived_is_not_followed():
    g = delegation_scenario(delegated_at="2026-03-01T09:59:00Z")
    assert find_risky_paths(g.build()) == []


def test_agent_message_carries_content_to_another_session():
    g = G()
    g.node("src:mail", "source", "inbox", trust_level="SUSPICIOUS")
    g.node("ctx:mail", "context_item", "email", trust_level="SUSPICIOUS")
    g.node("ses:a", "session", "triage agent")
    g.node("ctx:msg", "context_item", "message to ops agent", trust_level="APPROVED")
    g.node("ses:b", "session", "ops agent")
    g.node(
        "inv:bash",
        "tool_invocation",
        "Bash",
        tool_name="Bash",
        decision="REQUIRE_APPROVAL",
        enforcement="enforced",
        status="pending_approval",
    )
    g.edge("src:mail", "ctx:mail", "source_produced_item")
    g.edge("ctx:mail", "ses:a", "item_entered_session")
    g.edge("ses:a", "ctx:msg", "agent_messaged")
    g.edge("ctx:msg", "ses:b", "item_entered_session")
    g.edge("ses:b", "inv:bash", "session_invoked_tool")
    path = only(find_risky_paths(g.build()))
    assert path.node_ids[:5] == ["src:mail", "ctx:mail", "ses:a", "ctx:msg", "ses:b"]
    assert path.outcome == "awaiting_approval" and path.cross_session is True
    assert "held for approval" in path.title
    assert "held until someone decides" in path.explanation


def chain(length: int) -> G:
    g = G()
    g.node("ctx:origin", "context_item", "scraped page", trust_level="UNKNOWN")
    previous = g.node("ses:0", "session")
    g.edge("ctx:origin", "ses:0", "item_entered_session")
    for i in range(1, length):
        current = g.node(f"ses:{i}", "session")
        g.edge(previous, current, "session_delegated_to")
        previous = current
    g.node("inv:end", "tool_invocation", "Read", tool_name="Read", sensitive=True)
    g.edge(previous, "inv:end", "session_invoked_tool")
    return g


def test_depth_limit_bounds_the_walk():
    g = chain(6).build()  # origin -> 6 sessions -> invocation = 7 edges
    assert len(only(find_risky_paths(g)).session_ids) == 6
    assert len(only(find_risky_paths(g, max_depth=7)).edge_ids) == 7
    assert find_risky_paths(g, max_depth=6) == []
    with pytest.raises(ValueError):
        find_risky_paths(g, max_depth=0)


def test_delegation_cycles_terminate():
    g = chain(3)
    g.edge("ses:2", "ses:0", "session_delegated_to")
    g.edge("ses:1", "ses:0", "session_delegated_to")
    path = only(find_risky_paths(g.build()))
    assert path.session_ids == ["ses:0", "ses:1", "ses:2"]


# ---------------------------------------------------------------- dedupe, caps, misc


def test_origins_sharing_a_route_are_merged_into_one_path():
    g = readme_scenario(with_read=False, detection=None)
    for i in range(3):
        g.node(f"ctx:page{i}", "context_item", f"page {i}", trust_level="EXTERNAL")
        g.edge(f"ctx:page{i}", "ses:1", "item_entered_session", observed_at=t(0))
    path = only(find_risky_paths(g.build()))
    assert path.origin_id == "src:readme"
    assert path.related_origin_ids == ["ctx:page0", "ctx:page1", "ctx:page2"]


def test_results_are_capped_and_sorted_by_severity():
    g = G()
    g.node("ctx:bad", "context_item", "bad", trust_level="BLOCKED", detection_summary=INJECTION)
    g.node("ses:1", "session")
    g.edge("ctx:bad", "ses:1", "item_entered_session")
    for i in range(40):
        g.node(f"inv:{i}", "tool_invocation", f"call {i}", tool_name="http_request")
        g.node(
            f"dst:{i}", "destination", f"host{i}.example", classification="BLOCKED" if i % 2 else "EXTERNAL"
        )
        g.edge("ses:1", f"inv:{i}", "session_invoked_tool")
        g.edge(f"inv:{i}", f"dst:{i}", "invocation_sent_to")
    graph = g.build()
    paths = find_risky_paths(graph)
    assert len(paths) == 25
    ranks = [(SEVERITY_RANK[p.severity], p.score) for p in paths]
    assert ranks == sorted(ranks, reverse=True)
    assert len(find_risky_paths(graph, max_results=3)) == 3
    assert len({p.sink_id for p in paths}) == 25


def test_inferred_edges_are_reported():
    g = readme_scenario(with_read=False)
    g.edges[-2]["confidence"] = "inferred"  # session -> WebFetch inferred by ContextOS
    path = only(find_risky_paths(g.build()))
    assert path.inferred_edge_ids == [g.edges[-2]["id"]]
    assert "inferred by ContextOS" in path.explanation


def test_inline_resources_and_nested_data_attributes_are_read():
    g = G()
    g.node("ctx:x", "context_item", "tool output", data={"trust_level": "SUSPICIOUS"})
    g.node("ses:1", "session")
    g.node(
        "inv:cat",
        "tool_invocation",
        "Bash",
        data={"tool_name": "Bash"},
        resources=[{"kind": "file", "id": "~/.aws/credentials", "sensitive": True}],
    )
    g.edge("ctx:x", "ses:1", "item_entered_session")
    g.edge("ses:1", "inv:cat", "session_invoked_tool")
    path = only(find_risky_paths(g.build()))
    assert '"~/.aws/credentials"' in path.explanation
    assert path.title.startswith('Suspicious context item "tool output"')


def test_every_path_disclaims_causation():
    graphs = [readme_scenario().build(), delegation_scenario().build(), chain(2).build()]
    for graph in graphs:
        for path in find_risky_paths(graph):
            assert OBSERVED_RELATIONSHIP_NOTE in path.explanation
            assert "caused" not in path.explanation.replace(OBSERVED_RELATIONSHIP_NOTE, "")
            assert "caused" not in path.title


def test_many_benign_calls_do_not_hide_a_risky_one():
    g = readme_scenario(with_read=False, detection=None)
    for i in range(300):
        g.node(f"inv:ls{i}", "tool_invocation", f"Glob {i}", tool_name="Glob", requested_at=t(1))
        g.edges.insert(
            2, {"id": f"ls{i}", "src": "ses:1", "dst": f"inv:ls{i}", "relation": "session_invoked_tool"}
        )
    path = only(find_risky_paths(g.build()))
    assert path.sink_id == "inv:fetch"


def test_sensitive_read_after_the_outbound_call_is_not_folded_in():
    g = readme_scenario(detection=None)
    g.nodes[3]["requested_at"] = t(5)  # Read .env happened after the WebFetch at t(2)
    paths = {p.sink_id: p for p in find_risky_paths(g.build())}
    assert set(paths) == {"inv:fetch", "inv:read"}
    assert "inv:read" not in paths["inv:fetch"].node_ids
    assert paths["inv:fetch"].category == "destination_risk"


def test_stopped_calls_are_described_as_attempts_not_actions():
    graph = readme_scenario(fetch={"decision": "DENY", "status": "denied"}).build()
    path = next(p for p in find_risky_paths(graph) if p.sink_id == "inv:fetch")
    assert "attempting to send data to" in path.title
    assert "tried to send data to" in path.explanation and "sent data to" not in path.explanation
    allowed = only(find_risky_paths(readme_scenario().build()))
    assert "WebFetch sent data to" in allowed.explanation and "attempting" not in allowed.title


def test_item_arrival_time_is_used_when_the_entry_edge_has_no_timestamp():
    g = readme_scenario(with_read=False, fetch={"requested_at": t(2)})
    del g.edges[1]["observed_at"]
    g.nodes[1]["received_at"] = t(5)  # the README arrived after the WebFetch call
    g.nodes[2]["started_at"] = t(0)  # the session's start time must not stand in for the arrival
    assert find_risky_paths(g.build()) == []
