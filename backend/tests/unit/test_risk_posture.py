"""Risk engine: explainable agent posture."""

from __future__ import annotations

import json

import pytest

from app.engines.risk import PostureInputs, compute_agent_posture
from app.engines.risk.posture import grade_for
from app.engines.risk.posture_dims import MAX

AGENT = {"id": "agt_1", "name": "builder", "environment": "development", "framework": "claude_code", "status": "active"}

CRED_POLICY = {"id": "pol_cred", "name": "Block credential exfiltration", "outcome": "DENY", "mode": "enforce",
               "conditions": {"all": [{"field": "session_secret_matches", "op": "not_empty"}]}}
SENSITIVE_POLICY = {"id": "pol_res", "name": "Approve sensitive files", "outcome": "REQUIRE_APPROVAL",
                    "mode": "enforce", "conditions": {"field": "sensitive_resources", "op": "not_empty"}}
SHELL_APPROVAL = {"id": "pol_shell", "name": "Approve outbound shell", "outcome": "REQUIRE_APPROVAL",
                  "mode": "enforce", "conditions": {"all": [{"field": "tool.category", "op": "in",
                                                             "value": ["shell", "http"]}]}}
INJECTION_POLICY = {"id": "pol_inj", "name": "Gate after injection", "outcome": "REQUIRE_APPROVAL", "mode": "enforce",
                    "conditions": {"all": [{"field": "context.injection_detected", "op": "is_true"},
                                           {"field": "session.trifecta", "op": "is_true"}]}}
GOOD_INTEGRATION = {"kind": "claude_code", "supports_enforcement": True, "status": "active"}
OBSERVED = [{"name": "Bash", "category": "shell", "risk_level": "high", "count": 12},
            {"name": "WebFetch", "category": "http", "risk_level": "medium", "count": 3},
            {"name": "Read", "category": "file_read", "risk_level": "low", "count": 40}]


def _inputs(**kw) -> PostureInputs:
    base = {"agent": AGENT}
    base.update(kw)
    return PostureInputs(**base)


def _dim(assessment, key):
    return next(d for d in assessment.dimensions if d.key == key)


def _well_configured(**overrides) -> PostureInputs:
    kw = dict(declared_tools=[{"name": t["name"]} for t in OBSERVED], observed_tools=OBSERVED,
              policies=[CRED_POLICY, SENSITIVE_POLICY, SHELL_APPROVAL, INJECTION_POLICY,
                        {"id": "pol_read", "name": "Audit reads", "outcome": "AUDIT", "mode": "enforce",
                         "conditions": {"field": "tool.category", "op": "eq", "value": "file_read"}}],
              trust_rule_count=4, integration=GOOD_INTEGRATION, approval_policy_count=3, total_sessions=20)
    kw.update(overrides)
    return _inputs(**kw)


def test_dimension_maximums_sum_to_100_and_are_all_present():
    assert sum(MAX.values()) == 100
    assessment = compute_agent_posture(_inputs())
    assert [d.key for d in assessment.dimensions] == list(MAX)
    assert all(d.max_score == MAX[d.key] for d in assessment.dimensions)
    assert assessment.score == sum(d.score for d in assessment.dimensions)


def test_unconnected_agent_scores_poorly_and_says_why():
    assessment = compute_agent_posture(_inputs(declared_tools=[{"name": "Bash"}, {"name": "WebFetch"}]))
    enforcement = _dim(assessment, "enforcement_coverage")
    assert enforcement.score == 0 and "Connect" in enforcement.recommendation
    assert assessment.grade in {"D", "F"}
    assert _dim(assessment, "sensitive_data_controls").score == 0


def test_well_configured_agent_gets_an_a():
    assessment = compute_agent_posture(_well_configured())
    assert assessment.grade == "A", [(d.key, d.score, d.explanation) for d in assessment.dimensions]
    assert _dim(assessment, "policy_coverage").score == MAX["policy_coverage"]
    assert _dim(assessment, "approval_controls").score == MAX["approval_controls"]


@pytest.mark.parametrize(("policy", "points"), [
    (CRED_POLICY, 10), (dict(CRED_POLICY, mode="monitor"), 4), (dict(CRED_POLICY, outcome="AUDIT"), 0), (None, 0),
])
def test_credential_exfiltration_policy_must_be_enforced(policy, points):
    dim = _dim(compute_agent_posture(_inputs(policies=[policy] if policy else [])), "sensitive_data_controls")
    assert dim.score == points
    if points < 10:
        assert "enforce mode" in dim.recommendation


def test_disabled_policies_are_ignored():
    dim = _dim(compute_agent_posture(_inputs(policies=[dict(CRED_POLICY, enabled=False)])), "sensitive_data_controls")
    assert dim.score == 0


def test_policy_coverage_counts_positive_references_only():
    negated = {"id": "p_neg", "name": "Everything but shell", "outcome": "AUDIT", "mode": "enforce",
               "conditions": {"field": "tool.category", "op": "not_in", "value": ["shell"]}}
    by_name = {"id": "p_name", "name": "Web tools", "outcome": "AUDIT", "mode": "enforce",
               "conditions": {"field": "tool.name", "op": "glob", "value": "Web*"}}
    monitor = {"id": "p_mon", "name": "Watch reads", "outcome": "AUDIT", "mode": "monitor",
               "conditions": {"not": {"field": "tool.category", "op": "neq", "value": "file_read"}}}
    dim = _dim(compute_agent_posture(_inputs(observed_tools=OBSERVED, policies=[negated, by_name, monitor])),
               "policy_coverage")
    details = {e["id"]: e["detail"] for e in dim.evidence}
    assert details["shell"].startswith("no enabled policy")
    assert details["http"].startswith("covered by Web tools")
    assert details["file_read"].startswith("monitor-only")
    assert dim.score == round(10 * 1.5 / 3)
    assert "shell" in dim.recommendation


def test_policy_coverage_by_risk_level_and_not_assessed_without_tools():
    risky = {"id": "p_r", "name": "High risk", "outcome": "REQUIRE_APPROVAL", "mode": "enforce",
             "conditions": {"field": "tool.risk_level", "op": "in", "value": ["high", "critical"]}}
    dim = _dim(compute_agent_posture(_inputs(observed_tools=OBSERVED, policies=[risky])), "policy_coverage")
    assert any(e["id"] == "shell" and e["detail"].startswith("covered") for e in dim.evidence)
    empty = compute_agent_posture(_inputs())
    assert _dim(empty, "policy_coverage").explanation.startswith("Not assessed yet")
    assert "Not assessed yet" in empty.summary


def test_approval_controls():
    none_needed = _dim(compute_agent_posture(_inputs(observed_tools=[OBSERVED[2]])), "approval_controls")
    assert none_needed.score == MAX["approval_controls"]
    missing = _dim(compute_agent_posture(_inputs(observed_tools=OBSERVED)), "approval_controls")
    assert missing.score == 0 and "shell" in missing.recommendation
    gated = _dim(compute_agent_posture(_inputs(observed_tools=OBSERVED, policies=[SHELL_APPROVAL])),
                 "approval_controls")
    assert gated.score == MAX["approval_controls"] and gated.recommendation is None
    monitor_only = _dim(compute_agent_posture(_inputs(observed_tools=OBSERVED,
                                                      policies=[dict(SHELL_APPROVAL, mode="monitor")])),
                        "approval_controls")
    assert monitor_only.score == 3  # approval policies exist, but none enforce on shell


def test_permission_exposure_costs_and_undeclared_tools():
    dev = _dim(compute_agent_posture(_inputs(declared_tools=[{"name": "Bash"}], observed_tools=OBSERVED)),
               "permission_exposure")
    prod = _dim(compute_agent_posture(_inputs(agent=dict(AGENT, environment="production"),
                                              declared_tools=[{"name": "Bash"}], observed_tools=OBSERVED)),
                "permission_exposure")
    assert prod.score < dev.score
    assert {e["id"] for e in dev.evidence if e["type"] == "tool"} == {"WebFetch", "Read"}
    assert dev.recommendation
    read_only = _dim(compute_agent_posture(_inputs(observed_tools=[OBSERVED[2]])), "permission_exposure")
    assert read_only.score == MAX["permission_exposure"] and read_only.recommendation is None


def test_source_trust():
    none = _dim(compute_agent_posture(_inputs()), "source_trust")
    assert none.score == 3 and "trust rules" in none.recommendation
    many = _dim(compute_agent_posture(_inputs(trust_rule_count=3, untrusted_source_count=12)), "source_trust")
    assert many.score == 6 and "12" in many.explanation


def test_unresolved_findings_penalty_by_severity():
    findings = [{"id": "f1", "severity": "critical", "category": "exfiltration"},
                {"id": "f2", "severity": "high", "category": "prompt_injection"},
                {"id": "f3", "severity": "low", "category": "anomaly"}]
    dim = _dim(compute_agent_posture(_inputs(open_findings=findings)), "unresolved_findings")
    assert dim.score == 10 - 5 - 3 and dim.evidence[0]["id"] == "f1"
    floor = _dim(compute_agent_posture(_inputs(open_findings=findings * 5)), "unresolved_findings")
    assert floor.score == 0


@pytest.mark.parametrize(("with_trifecta", "total", "score"), [(0, 0, 10), (0, 50, 10), (1, 100, 7), (5, 10, 5),
                                                                (10, 10, 0)])
def test_trifecta_exposure(with_trifecta, total, score):
    dim = _dim(compute_agent_posture(_inputs(sessions_with_trifecta=with_trifecta, total_sessions=total)),
               "trifecta_exposure")
    assert dim.score == score
    if with_trifecta:
        assert "not proof of an attack" in dim.explanation and dim.recommendation


def test_enforcement_wording_is_honest():
    advisory = _dim(compute_agent_posture(_inputs(integration={"kind": "python_sdk", "supports_enforcement": False,
                                                               "status": "active"})), "enforcement_coverage")
    assert advisory.score == 4 and "cannot block" in advisory.explanation
    degraded = _dim(compute_agent_posture(_inputs(integration=dict(GOOD_INTEGRATION, status="error"))),
                    "enforcement_coverage")
    assert degraded.score == 5 and degraded.recommendation


def test_detection_coverage_requires_policies_acting_on_detections():
    none = _dim(compute_agent_posture(_inputs()), "detection_coverage")
    full = _dim(compute_agent_posture(_inputs(policies=[INJECTION_POLICY])), "detection_coverage")
    half = _dim(compute_agent_posture(_inputs(policies=[dict(INJECTION_POLICY, mode="monitor")])),
                "detection_coverage")
    assert (none.score, full.score, half.score) == (0, 10, 5)


@pytest.mark.parametrize("variant", range(6))
def test_every_dimension_explains_itself_and_gaps_have_recommendations(variant):
    configs = [
        _inputs(), _well_configured(), _well_configured(policies=[]), _well_configured(integration={}),
        _inputs(observed_tools=OBSERVED, open_findings=[{"id": "f", "severity": "medium"}], total_sessions=3,
                sessions_with_trifecta=3, untrusted_source_count=2),
        _well_configured(agent=dict(AGENT, environment="production"), trust_rule_count=0),
    ]
    assessment = compute_agent_posture(configs[variant])
    assert 0 <= assessment.score <= 100 and assessment.grade == grade_for(assessment.score)
    assert assessment.summary.startswith(f"Posture {assessment.score}/100")
    for dim in assessment.dimensions:
        assert 0 <= dim.score <= dim.max_score and dim.explanation
        if dim.score < dim.max_score:
            assert dim.recommendation, dim.key
        for ev in dim.evidence:
            assert set(ev) == {"type", "id", "detail"}
    json.dumps(assessment.to_dict())


@pytest.mark.parametrize(("score", "grade"), [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (70, "C"), (60, "D"),
                                              (59, "F"), (0, "F")])
def test_grades(score, grade):
    assert grade_for(score) == grade
