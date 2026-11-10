"""Risk engine: lethal-trifecta session risk."""

from __future__ import annotations

import itertools
import json

import pytest

from app.engines.risk import SessionSignals, compute_session_risk
from app.engines.risk.engine import risk_level_for

CAVEAT = "not proof of an attack"

SECRET_ITEM = {"id": "ctx_secret", "trust_level": "TRUSTED", "source_type": "file", "contains_secrets": True}
UNTRUSTED_ITEM = {"id": "ctx_web", "trust_level": "EXTERNAL", "source_type": "web"}
INJECTED_ITEM = {"id": "ctx_inj", "trust_level": "UNKNOWN", "source_type": "web",
                 "detection_categories": ["prompt_injection"], "detection_max_severity": "high"}
OUTBOUND_CALL = {"id": "inv_out", "tool_name": "WebFetch", "category": "http", "status": "completed",
                 "outbound": True, "destination_classification": "EXTERNAL"}
SENSITIVE_CALL = {"id": "inv_env", "tool_name": "Read", "category": "file_read", "status": "completed",
                  "outbound": False, "sensitive_resources": ["/srv/app/.env"]}


def _signals(**kw) -> SessionSignals:
    return SessionSignals(**kw)


def _factor(risk, key):
    return next((f for f in risk.factors if f.key == key), None)


def test_empty_session_is_low_with_caveat():
    risk = compute_session_risk(SessionSignals())
    assert (risk.score, risk.level, risk.trifecta) == (0, "low", False)
    assert risk.factors == [] and CAVEAT in risk.summary
    assert set(risk.trifecta_evidence) == {"sensitive_access", "untrusted_exposure", "outbound_channel"}


def test_trifecta_with_evidence():
    risk = compute_session_risk(_signals(context_items=[SECRET_ITEM, UNTRUSTED_ITEM], tool_invocations=[OUTBOUND_CALL]))
    assert risk.trifecta and risk.level in {"high", "critical"} and risk.score >= 50
    ev = risk.trifecta_evidence
    assert ev["sensitive_access"][0]["id"] == "ctx_secret"
    assert ev["untrusted_exposure"][0]["id"] == "ctx_web"
    assert ev["outbound_channel"][0]["id"] == "inv_out"
    trifecta = _factor(risk, "trifecta")
    assert trifecta is not None and trifecta.weight > 0 and trifecta.evidence
    assert "All three" in risk.summary and CAVEAT in risk.summary
    for items in ev.values():
        for item in items:
            assert set(item) == {"type", "id", "detail"} and all(isinstance(v, str) for v in item.values())


@pytest.mark.parametrize("missing", ["sensitive", "untrusted", "outbound"])
def test_trifecta_off_when_any_condition_missing(missing):
    kw = {"context_items": [], "tool_invocations": []}
    if missing != "sensitive":
        kw["tool_invocations"].append(SENSITIVE_CALL)
    if missing != "untrusted":
        kw["context_items"].append(UNTRUSTED_ITEM)
    if missing != "outbound":
        kw["tool_invocations"].append(OUTBOUND_CALL)
    risk = compute_session_risk(_signals(**kw))
    assert not risk.trifecta and _factor(risk, "trifecta") is None
    assert "not observed" in risk.summary and CAVEAT in risk.summary


def test_declared_capability_counts_as_outbound_channel_without_usage_points():
    risk = compute_session_risk(_signals(context_items=[SECRET_ITEM, UNTRUSTED_ITEM],
                                         declared_tools=[{"name": "Bash"}, {"name": "Read"}]))
    assert risk.outbound_channel and risk.trifecta
    assert _factor(risk, "outbound_channel") is None  # declared, not used
    assert "declared capability" in risk.summary
    assert risk.trifecta_evidence["outbound_channel"][0]["type"] == "tool"
    local_only = compute_session_risk(_signals(declared_tools=[{"name": "Read"}, {"name": "Edit"}]))
    assert not local_only.outbound_channel


def test_denied_calls_do_not_create_conditions_but_raise_score():
    denied = dict(OUTBOUND_CALL, status="denied", decision="DENY")
    denied_read = dict(SENSITIVE_CALL, id="inv_env2", status="denied", decision="DENY")
    risk = compute_session_risk(_signals(tool_invocations=[denied, denied_read]))
    assert not risk.sensitive_access and not risk.outbound_channel
    factor = _factor(risk, "denied_actions")
    assert factor.weight == 10 and len(factor.evidence) == 2


def test_untrusted_items_with_injection_raise_score_by_severity():
    low = compute_session_risk(_signals(context_items=[dict(INJECTED_ITEM, detection_max_severity="low")]))
    high = compute_session_risk(_signals(context_items=[INJECTED_ITEM]))
    assert _factor(high, "injection_observed").weight > _factor(low, "injection_observed").weight
    assert high.score > low.score
    assert "prompt_injection" in high.trifecta_evidence["untrusted_exposure"][0]["detail"]


def test_trifecta_with_high_injection_is_critical():
    risk = compute_session_risk(_signals(context_items=[SECRET_ITEM, INJECTED_ITEM], tool_invocations=[OUTBOUND_CALL]))
    assert risk.level == "critical"


def test_suspicious_source_strengthens_exposure():
    base = compute_session_risk(_signals(context_items=[UNTRUSTED_ITEM]))
    sus = compute_session_risk(_signals(context_items=[dict(UNTRUSTED_ITEM, trust_level="SUSPICIOUS")]))
    assert _factor(sus, "untrusted_exposure").weight > _factor(base, "untrusted_exposure").weight


def test_credential_flow_outranks_plain_credential_detection():
    plain = dict(OUTBOUND_CALL, sensitive_data_detected=True)
    flow = dict(plain, matched_session_fingerprints=["fp_1"])
    a = compute_session_risk(_signals(tool_invocations=[plain]))
    b = compute_session_risk(_signals(tool_invocations=[flow]))
    assert _factor(a, "credential_in_outbound") is not None
    assert _factor(b, "credential_flow").weight > _factor(a, "credential_in_outbound").weight
    assert "fingerprint" in _factor(b, "credential_flow").explanation


def test_destination_factors():
    bad = compute_session_risk(_signals(tool_invocations=[dict(OUTBOUND_CALL, destination_classification="BLOCKED")]))
    unknown = compute_session_risk(_signals(tool_invocations=[dict(OUTBOUND_CALL,
                                                                   destination_classification="UNKNOWN")]))
    assert _factor(bad, "suspicious_destinations").weight == 15
    assert _factor(unknown, "unverified_destinations").weight == 5
    assert _factor(unknown, "suspicious_destinations") is None


def test_open_findings_exclude_trifecta_feedback_and_resolved():
    findings = [
        {"id": "f1", "category": "prompt_injection", "severity": "critical", "status": "open"},
        {"id": "f2", "category": "lethal_trifecta", "severity": "critical", "status": "open"},
        {"id": "f3", "category": "exfiltration", "severity": "high", "status": "resolved"},
        {"id": "f4", "category": "secret_exposure", "severity": "low", "status": "open"},
    ]
    factor = _factor(compute_session_risk(_signals(findings=findings)), "open_findings")
    assert factor.weight == 15 and [e["id"] for e in factor.evidence] == ["f1"]


def test_inherited_child_session_risk():
    risk = compute_session_risk(_signals(inherited_risk={"session_id": "ses_child", "score": 60, "trifecta": True,
                                                         "relation": "child"}))
    factor = _factor(risk, "inherited_risk")
    assert factor.weight == 15 and factor.evidence[0]["id"] == "ses_child"
    assert compute_session_risk(_signals(inherited_risk={"score": 0})).factors == []


def test_score_is_monotonic_in_signals():
    pieces = [
        ("context_items", SECRET_ITEM), ("context_items", UNTRUSTED_ITEM), ("context_items", INJECTED_ITEM),
        ("tool_invocations", OUTBOUND_CALL), ("tool_invocations", SENSITIVE_CALL),
        ("tool_invocations", dict(OUTBOUND_CALL, id="inv_d", status="denied", decision="DENY")),
        ("tool_invocations", dict(OUTBOUND_CALL, id="inv_s", sensitive_data_detected=True,
                                  destination_classification="SUSPICIOUS")),
        ("findings", {"id": "f1", "category": "exfiltration", "severity": "high", "status": "open"}),
        ("declared_tools", {"name": "Bash"}),
    ]
    for order in itertools.islice(itertools.permutations(range(len(pieces))), 0, 400, 7):
        kw: dict = {"context_items": [], "tool_invocations": [], "findings": [], "declared_tools": []}
        previous = 0
        for idx in order:
            field, value = pieces[idx]
            kw[field] = kw[field] + [value]
            score = compute_session_risk(SessionSignals(**kw)).score
            assert score >= previous, (order, idx)
            previous = score


def test_score_is_capped_and_equals_factor_sum():
    many = [dict(OUTBOUND_CALL, id=f"inv_{i}", destination_classification="BLOCKED", sensitive_data_detected=True,
                 matched_session_fingerprints=["x"], status="denied", decision="DENY") for i in range(10)]
    risk = compute_session_risk(_signals(context_items=[SECRET_ITEM, INJECTED_ITEM], tool_invocations=many,
                                         declared_tools=[{"name": "WebFetch"}],
                                         inherited_risk={"score": 100, "trifecta": True}))
    assert risk.score == 100 and sum(f.weight for f in risk.factors) >= 100
    small = compute_session_risk(_signals(context_items=[UNTRUSTED_ITEM]))
    assert small.score == sum(f.weight for f in small.factors)


@pytest.mark.parametrize(("score", "level"), [(0, "low"), (24, "low"), (25, "medium"), (49, "medium"),
                                              (50, "high"), (74, "high"), (75, "critical"), (100, "critical")])
def test_level_thresholds(score, level):
    assert risk_level_for(score) == level


def test_to_dict_is_json_serialisable_and_includes_trifecta():
    risk = compute_session_risk(_signals(context_items=[SECRET_ITEM, UNTRUSTED_ITEM], tool_invocations=[OUTBOUND_CALL]))
    data = json.loads(json.dumps(risk.to_dict()))
    assert data["trifecta"] is True and data["factors"][0]["explanation"]


def test_every_factor_explains_itself():
    risk = compute_session_risk(_signals(
        context_items=[SECRET_ITEM, INJECTED_ITEM],
        tool_invocations=[OUTBOUND_CALL, dict(OUTBOUND_CALL, id="x", status="denied", decision="DENY")],
        findings=[{"id": "f1", "category": "exfiltration", "severity": "critical", "status": "open"}],
    ))
    for factor in risk.factors:
        assert factor.label and factor.explanation and factor.weight > 0 and factor.evidence
