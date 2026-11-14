"""Context receipts (canonicalisation, signing, tamper detection) and provenance graph assembly."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core.security import keyed_hmac
from app.engines.provenance import (
    OBSERVED_RELATIONSHIP_NOTE,
    build_graph,
    canonical_json,
    receipt_fields,
    sign_receipt,
    verify_receipt,
)

RECEIPT_KEYS = [
    "receipt_version",
    "context_item_id",
    "organization_id",
    "source",
    "agent_id",
    "session_id",
    "event_id",
    "collected_via",
    "collected_at",
    "received_at",
    "content_hash",
    "content_length",
    "content_type",
    "sensitivity",
    "contains_secrets",
    "secret_fingerprint_count",
    "detection",
    "tool_invocation_id",
]


def _item(**overrides):
    item = {
        "id": "ctx_01",
        "organization_id": "org_01",
        "source": {
            "type": "repository",
            "identifier": "github.com/acme/app/README.md",
            "trust_level": "TRUSTED",
        },
        "trust_level": "UNKNOWN",
        "agent_id": "agt_01",
        "session_id": "ses_01",
        "event_id": "evt_01",
        "collected_via": "claude_code:PostToolUse:Read",
        "collected_at": datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC),
        "received_at": datetime(2026, 3, 1, 10, 0, 1, 250000, tzinfo=UTC),
        "content_hash": "A" * 64,
        "content_length": 1834,
        "content_type": "text/markdown",
        "sensitivity": "internal",
        "contains_secrets": True,
        "secret_fingerprints": [{"type": "aws_access_key", "fingerprint": "deadbeefcafe0001"}],
        "detection_summary": {
            "score": 0.81234,
            "max_severity": "HIGH",
            "rule_ids": ["PI-002", "PI-001", "PI-002"],
            "hit_count": 3,
        },
        "tool_invocation_id": "inv_01",
        "redacted_preview": "Ignore previous instructions [REDACTED:aws_access_key:deadbeef]",
    }
    item.update(overrides)
    return item


# ---------------------------------------------------------------- receipt canonicalisation


def test_receipt_fields_are_the_attested_subset_in_stable_order():
    fields = receipt_fields(_item())
    assert list(fields) == RECEIPT_KEYS
    assert fields["receipt_version"] == "1"
    assert fields["source"] == {
        "type": "repository",
        "identifier": "github.com/acme/app/README.md",
        "trust_level_at_ingest": "UNKNOWN",
    }
    assert fields["detection"] == {"score": 0.812, "max_severity": "high", "rule_ids": ["PI-001", "PI-002"]}
    assert fields["content_hash"] == "a" * 64
    assert fields["secret_fingerprint_count"] == 1
    json.dumps(fields)  # JSON-serialisable


def test_receipt_never_contains_content_or_raw_fingerprints():
    text = canonical_json(receipt_fields(_item()))
    assert "deadbeefcafe0001" not in text
    assert "Ignore previous" not in text and "redacted_preview" not in text


@pytest.mark.parametrize(
    "collected_at",
    [
        datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC),
        datetime(2026, 3, 1, 10, 0, 0),  # naive values from SQLite are UTC
        datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        "2026-03-01T10:00:00Z",
        "2026-03-01T10:00:00.000000+00:00",
        "2026-03-01T05:00:00-05:00",
    ],
)
def test_timestamps_canonicalise_to_one_utc_form(collected_at):
    fields = receipt_fields(_item(collected_at=collected_at))
    assert fields["collected_at"] == "2026-03-01T10:00:00.000000Z"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", fields["received_at"])


def test_canonical_json_is_independent_of_key_order():
    item = _item()
    shuffled = dict(reversed(list(item.items())))
    shuffled["detection_summary"] = dict(reversed(list(item["detection_summary"].items())))
    assert canonical_json(receipt_fields(item)) == canonical_json(receipt_fields(shuffled))
    assert sign_receipt(receipt_fields(item)) == sign_receipt(receipt_fields(shuffled))
    text = canonical_json(receipt_fields(item))
    assert ", " not in text and ": " not in text
    assert text.index('"agent_id"') < text.index('"collected_at"') < text.index('"source"')


def test_receipt_fields_is_idempotent_for_exported_receipts():
    fields = receipt_fields(_item())
    again = receipt_fields(json.loads(json.dumps(fields)))
    assert again == fields
    assert verify_receipt(again, sign_receipt(fields))


def test_trust_at_ingest_ignores_the_sources_current_classification():
    # The source was later reclassified TRUSTED; the receipt must keep the classification at ingest.
    fields = receipt_fields(_item(source={"type": "web", "identifier": "x", "trust_level": "TRUSTED"}))
    assert fields["source"]["trust_level_at_ingest"] == "UNKNOWN"
    fallback = receipt_fields(
        _item(trust_level=None, source={"type": "web", "trust_level_at_ingest": "external"})
    )
    assert fallback["source"]["trust_level_at_ingest"] == "EXTERNAL"


def test_missing_optional_values_have_deterministic_defaults():
    fields = receipt_fields(
        {
            "id": "ctx_x",
            "organization_id": "org_x",
            "source_type": "WEB",
            "source_identifier": "https://example.org",
        }
    )
    assert fields["source"] == {
        "type": "web",
        "identifier": "https://example.org",
        "trust_level_at_ingest": "UNKNOWN",
    }
    assert fields["detection"] == {"score": 0.0, "max_severity": None, "rule_ids": []}
    assert fields["collected_at"] is None and fields["content_length"] == 0
    assert fields["contains_secrets"] is False and fields["secret_fingerprint_count"] == 0


def test_receipt_accepts_row_like_objects():
    as_dict = _item()
    as_object = SimpleNamespace(**as_dict)
    assert receipt_fields(as_object) == receipt_fields(as_dict)


def test_invalid_timestamp_is_rejected():
    with pytest.raises(ValueError, match="collected_at"):
        receipt_fields(_item(collected_at="yesterday-ish"))


# ---------------------------------------------------------------- signing and tamper detection


def test_sign_and_verify_round_trip():
    fields = receipt_fields(_item())
    signature = sign_receipt(fields)
    assert re.fullmatch(r"[0-9a-f]{64}", signature)
    assert verify_receipt(fields, signature)
    assert verify_receipt(fields, signature.upper())
    assert signature == keyed_hmac(canonical_json(fields).encode(), purpose="context-receipt-v1")
    assert signature != keyed_hmac(canonical_json(fields).encode(), purpose="audit-chain-v1")


@pytest.mark.parametrize(
    "tamper",
    [
        lambda f: f.update(content_hash="b" * 64),
        lambda f: f.update(content_length=f["content_length"] + 1),
        lambda f: f["source"].update(trust_level_at_ingest="TRUSTED"),
        lambda f: f["detection"].update(rule_ids=[]),
        lambda f: f.update(contains_secrets=False),
        lambda f: f.update(received_at="2026-03-01T10:00:02.000000Z"),
        lambda f: f.update(extra_field="injected"),
        lambda f: f.pop("tool_invocation_id"),
    ],
)
def test_any_tampering_breaks_verification(tamper):
    fields = receipt_fields(_item())
    signature = sign_receipt(fields)
    tampered = json.loads(json.dumps(fields))
    tamper(tampered)
    assert verify_receipt(tampered, signature) is False


@pytest.mark.parametrize("bad", [None, "", "abc", "z" * 64, "0" * 63, "0" * 65, 12345, "é" * 64])
def test_malformed_signatures_are_rejected_without_raising(bad):
    assert verify_receipt(receipt_fields(_item()), bad) is False


def test_unserialisable_fields_fail_verification_without_raising():
    assert verify_receipt({"value": float("nan")}, "0" * 64) is False
    assert verify_receipt({"value": object()}, "0" * 64) is False


def test_receipt_signed_under_another_server_secret_does_not_verify(monkeypatch):
    import app.core.security as security

    fields = receipt_fields(_item())
    signature = sign_receipt(fields)
    monkeypatch.setattr(
        security, "get_settings", lambda: SimpleNamespace(secret_key="a-rotated-secret-" + "x" * 32)
    )
    assert verify_receipt(fields, signature) is False


# ---------------------------------------------------------------- graph assembly


def test_build_graph_dedupes_nodes_and_fills_missing_attributes():
    nodes = [
        {"id": "ses_1", "type": "SESSION", "label": "first"},
        {"id": "ses_1", "type": "session", "label": "second", "agent_id": "agt_1"},
        {"id": "", "type": "session"},
        {"type": "session"},
        {"id": "ctx_1", "type": "context_item"},
    ]
    graph = build_graph(nodes, [])
    assert list(graph.nodes) == ["ses_1", "ctx_1"]
    assert graph.nodes["ses_1"]["label"] == "first"  # first occurrence wins on conflict
    assert graph.nodes["ses_1"]["agent_id"] == "agt_1"  # missing attribute filled from duplicate
    assert graph.nodes["ses_1"]["type"] == "session"
    assert graph.nodes["ctx_1"]["label"] == "ctx_1"
    assert graph.metadata["duplicate_node_count"] == 1
    assert graph.metadata["invalid_node_count"] == 2


def test_build_graph_drops_and_counts_edges_with_missing_endpoints():
    nodes = [{"id": "a", "type": "source"}, {"id": "b", "type": "context_item"}]
    edges = [
        {"id": "e1", "src": "a", "dst": "b", "relation": "source_produced_item", "confidence": "observed"},
        {"id": "e2", "src": "b", "dst": "ghost", "relation": "item_entered_session"},
        {"id": "e3", "src": None, "dst": "b", "relation": "x"},
        {"id": "e4", "dst": "b"},
    ]
    graph = build_graph(nodes, edges)
    assert [e["id"] for e in graph.edges] == ["e1"]
    assert graph.metadata["dropped_edge_count"] == 3
    assert graph.metadata["dropped_edge_ids"] == ["e2"]
    assert graph.metadata["edge_count"] == 1 and graph.metadata["node_count"] == 2


def test_build_graph_keeps_relation_and_confidence_and_dedupes_edges():
    nodes = [{"id": "s", "type": "session"}, {"id": "i", "type": "tool_invocation"}]
    edges = [
        {
            "id": "e1",
            "src": "s",
            "dst": "i",
            "relation": "session_invoked_tool",
            "confidence": "Inferred",
            "observed_at": "2026-03-01T10:00:00Z",
        },
        {"id": "e1", "src": "s", "dst": "i", "relation": "session_invoked_tool"},
        {"src": "s", "dst": "i"},
    ]
    graph = build_graph(nodes, edges)
    assert len(graph.edges) == 2
    first, second = graph.edges
    assert first["relation"] == "session_invoked_tool" and first["confidence"] == "inferred"
    assert first["observed_at"] == "2026-03-01T10:00:00Z"
    assert second == {
        "src": "s",
        "dst": "i",
        "relation": "unspecified",
        "confidence": "observed",
        "id": "s->i:unspecified",
    }
    assert graph.metadata["duplicate_edge_count"] == 1 and graph.metadata["inferred_edge_count"] == 1


def test_build_graph_does_not_mutate_inputs_and_serialises_with_note():
    nodes = [{"id": "a", "type": "Source"}]
    edges = [{"id": "e", "src": "a", "dst": "a", "relation": "self"}]
    snapshot = json.dumps([nodes, edges])
    out = build_graph(nodes, edges).to_dict()
    assert json.dumps([nodes, edges]) == snapshot
    assert set(out) == {"nodes", "edges", "metadata"}
    assert out["metadata"]["note"] == OBSERVED_RELATIONSHIP_NOTE
    assert "not proof" in OBSERVED_RELATIONSHIP_NOTE
