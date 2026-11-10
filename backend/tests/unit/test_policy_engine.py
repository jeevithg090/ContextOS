"""Policy evaluation: precedence, ties, modes, defaults, restrictions, explanations, errors."""

from __future__ import annotations

import itertools

import pytest

from app.engines.policy import EvaluationInput, PolicySpec, evaluate

SHELL = EvaluationInput(
    agent={"id": "agt_1", "name": "builder", "environment": "development", "labels": [], "framework": "claude_code"},
    tool={"name": "Bash", "category": "shell", "provider": "claude_code", "server": None, "risk_level": "high"},
    arguments={"command": "ls -la /srv/app"},
    resources=[{"kind": "command", "id": "ls -la /srv/app", "sensitive": False, "reason": None}],
    integration={"kind": "claude_code", "supports_enforcement": True},
)
IS_SHELL = {"field": "tool.category", "op": "eq", "value": "shell"}


def pol(pid: str, outcome: str, *, name: str | None = None, priority: int = 100, mode: str = "enforce",
        enabled: bool = True, conditions: dict | None = None, restrictions: dict | None = None,
        severity: str = "medium") -> PolicySpec:
    return PolicySpec(
        id=pid, name=name or pid, outcome=outcome, conditions=IS_SHELL if conditions is None else conditions,
        mode=mode, enabled=enabled, priority=priority, restrictions=restrictions or {}, severity=severity,
    )


# ---- precedence and ties ---------------------------------------------------------------------

@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        (["ALLOW", "AUDIT", "RESTRICT", "REQUIRE_APPROVAL", "DENY"], "DENY"),
        (["ALLOW", "AUDIT", "RESTRICT", "REQUIRE_APPROVAL"], "REQUIRE_APPROVAL"),
        (["ALLOW", "AUDIT", "RESTRICT"], "RESTRICT"),
        (["ALLOW", "AUDIT"], "AUDIT"),
        (["ALLOW"], "ALLOW"),
    ],
)
def test_precedence(outcomes, expected):
    # Priorities are deliberately inverted so precedence, not priority, must decide.
    policies = [
        pol(f"p{i}", o, priority=1000 - 100 * i, restrictions={"redact_secrets": True} if o == "RESTRICT" else None)
        for i, o in enumerate(outcomes)
    ]
    result = evaluate(SHELL, policies)
    assert result.decision == expected
    assert result.matched[0].outcome == expected
    assert len(result.matched) == len(outcomes)


def test_tie_on_outcome_goes_to_higher_priority():
    result = evaluate(SHELL, [pol("low", "DENY", name="A low", priority=10), pol("high", "DENY", name="Z high", priority=500)])
    assert result.deciding_policy_id == "high"
    assert [m.policy_id for m in result.matched] == ["high", "low"]


def test_tie_on_priority_goes_to_name():
    result = evaluate(SHELL, [pol("p2", "DENY", name="beta"), pol("p1", "DENY", name="Alpha")])
    assert result.deciding_policy_id == "p1"


def test_evaluation_is_independent_of_policy_order():
    policies = [
        pol("a", "AUDIT", priority=5),
        pol("b", "REQUIRE_APPROVAL", priority=50),
        pol("c", "REQUIRE_APPROVAL", priority=50, name="aaa"),
        pol("m", "DENY", mode="monitor"),
    ]
    results = {
        (r.decision, r.deciding_policy_id, tuple(m.policy_id for m in r.matched), r.explanation)
        for r in (evaluate(SHELL, list(p)) for p in itertools.permutations(policies))
    }
    assert len(results) == 1
    decision, deciding, order, _ = results.pop()
    assert (decision, deciding, order) == ("REQUIRE_APPROVAL", "c", ("c", "b", "a"))


def test_outcome_and_mode_are_normalised():
    result = evaluate(SHELL, [pol("p", "deny", mode="ENFORCE")])
    assert result.decision == "DENY"
    assert result.matched[0].mode == "enforce"


# ---- modes, enabled, default -----------------------------------------------------------------

def test_monitor_mode_is_recorded_but_never_decides():
    result = evaluate(SHELL, [pol("dry", "DENY", mode="monitor"), pol("aud", "AUDIT")])
    assert result.decision == "AUDIT"
    assert [m.policy_id for m in result.matched] == ["aud"]
    assert [m.policy_id for m in result.monitor_matches] == ["dry"]
    assert result.monitor_matches[0].mode == "monitor"
    assert "Monitor mode (recorded only, not enforced)" in result.explanation


def test_monitor_only_match_keeps_the_default_decision():
    result = evaluate(SHELL, [pol("dry", "REQUIRE_APPROVAL", mode="monitor")])
    assert result.decision == "ALLOW"
    assert result.deciding_policy_id is None
    assert result.explanation.startswith("No policy matched; default ALLOW applied")
    assert len(result.monitor_matches) == 1


def test_disabled_policies_are_ignored_in_every_mode():
    result = evaluate(SHELL, [pol("off", "DENY", enabled=False), pol("off-dry", "DENY", enabled=False, mode="monitor")])
    assert result.decision == "ALLOW"
    assert result.matched == [] and result.monitor_matches == []


def test_default_decision_when_nothing_matches():
    nomatch = pol("n", "DENY", conditions={"field": "tool.category", "op": "eq", "value": "email"})
    result = evaluate(SHELL, [nomatch])
    assert result.decision == "ALLOW"
    assert result.explanation == "No policy matched; default ALLOW applied"
    assert result.deciding_policy_id is None and result.restrictions == {}
    audited = evaluate(SHELL, [nomatch], default_decision="audit")
    assert audited.decision == "AUDIT"
    assert audited.explanation == "No policy matched; default AUDIT applied"


def test_empty_policy_set_and_empty_conditions():
    assert evaluate(SHELL, []).decision == "ALLOW"
    assert evaluate(SHELL, [pol("blank", "DENY", conditions={})]).decision == "ALLOW"


def test_invalid_default_decision_is_rejected():
    with pytest.raises(ValueError):
        evaluate(SHELL, [], default_decision="MAYBE")


# ---- restrictions ----------------------------------------------------------------------------

def test_restrictions_merge_to_the_strictest_combination():
    r1 = {"redact_secrets": False, "allowed_path_globs": ["/srv/app/*", "/tmp/*"], "deny_path_globs": ["*.pem"],
          "max_argument_bytes": 8192}
    r2 = {"redact_secrets": True, "allowed_path_globs": ["/srv/*"], "deny_path_globs": ["*.pem", "*/.env"],
          "max_argument_bytes": 2048}
    result = evaluate(SHELL, [pol("r1", "RESTRICT", restrictions=r1), pol("r2", "RESTRICT", restrictions=r2),
                              pol("a", "AUDIT")])
    assert result.decision == "RESTRICT"
    assert result.restrictions == {
        "redact_secrets": True,
        "allowed_path_globs": ["/srv/app/*"],  # /tmp/* is not inside /srv/*; /srv/* is wider than /srv/app/*
        "deny_path_globs": ["*.pem", "*/.env"],
        "max_argument_bytes": 2048,
    }
    assert "Restrictions:" in result.explanation and "2048 bytes" in result.explanation


def test_disjoint_allowlists_allow_no_path():
    result = evaluate(SHELL, [
        pol("r1", "RESTRICT", restrictions={"allowed_path_globs": ["/srv/*"]}),
        pol("r2", "RESTRICT", restrictions={"allowed_path_globs": ["/home/*"]}),
    ])
    assert result.decision == "RESTRICT"
    assert result.restrictions["allowed_path_globs"] == []
    assert "no file path is allowed" in result.explanation


def test_restrictions_are_only_returned_when_restrict_wins():
    result = evaluate(SHELL, [pol("r", "RESTRICT", restrictions={"redact_secrets": True}), pol("d", "DENY")])
    assert result.decision == "DENY"
    assert result.restrictions == {}


@pytest.mark.parametrize(
    "restrictions",
    [{}, {"max_argument_bytes": "big"}, {"allowed_path_globs": "src/*"}, {"redact_secret": True}],
)
def test_restrict_that_cannot_be_applied_fails_closed(restrictions):
    result = evaluate(SHELL, [pol("r", "RESTRICT", restrictions=restrictions)])
    assert result.decision == "DENY"
    assert result.restrictions == {}
    assert result.explanation.startswith('DENY (fail closed): policy "r" requires RESTRICT')
    assert result.evaluation_errors


# ---- explanations ----------------------------------------------------------------------------

def test_explanation_names_deciding_policy_and_observed_values():
    cond = {"all": [IS_SHELL, {"field": "arguments.command", "op": "glob", "value": "ls *"}]}
    result = evaluate(SHELL, [pol("p", "AUDIT", name="Audit listings", priority=42, severity="low", conditions=cond)])
    assert result.explanation == (
        'AUDIT by policy "Audit listings" (low, priority 42). Matched because tool.category is shell '
        "(observed: shell) AND arguments.command matches ls * (observed: ls -la /srv/app)"
    )
    assert result.matched[0].explanation.startswith("Matched because tool.category is shell")


def test_explanation_lists_other_matches_and_missing_fields():
    cond = {"all": [IS_SHELL, {"not": {"field": "destination.classification", "op": "eq", "value": "TRUSTED"}}]}
    result = evaluate(SHELL, [pol("d", "DENY", conditions=cond), pol("a", "AUDIT", name="Audit shell")])
    assert "Not present in the input: destination.classification" in result.matched[0].explanation
    assert 'Also matched: "Audit shell" (AUDIT)' in result.explanation


def test_explanations_truncate_long_observed_values():
    long_cmd = "echo " + "x" * 500
    inp = EvaluationInput(tool={"category": "shell"}, arguments={"command": long_cmd})
    result = evaluate(inp, [pol("p", "AUDIT", conditions={"field": "arguments.command", "op": "contains", "value": "echo"})])
    assert "x" * 100 not in result.explanation
    assert "…" in result.explanation


# ---- broken policies -------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("spec", "fragment"),
    [
        (pol("bad", "DENY", conditions={"all": []}), "invalid conditions"),
        (pol("bad", "DENY", conditions={"field": "tool.category", "op": "like", "value": "s"}), "invalid conditions"),
        (pol("bad", "BLOCK"), "unknown outcome"),
        (pol("bad", "DENY", mode="shadow"), "unknown mode"),
    ],
)
def test_policies_that_cannot_be_evaluated_never_match_and_are_reported(spec, fragment):
    result = evaluate(SHELL, [spec, pol("ok", "AUDIT")])
    assert result.decision == "AUDIT"
    assert [e["policy_id"] for e in result.evaluation_errors] == ["bad"]
    assert fragment in result.evaluation_errors[0]["error"]
    assert "Could not evaluate 1 policy" in result.explanation


# ---- data types ------------------------------------------------------------------------------

def test_evaluation_input_round_trip():
    full = EvaluationInput(
        agent={"id": "agt_1", "name": "a", "environment": "production", "labels": ["x"], "framework": "langchain"},
        tool={"name": "send_email", "category": "email", "provider": "sdk", "server": None, "risk_level": "high"},
        arguments={"to": "x@example.com", "body": "[REDACTED:aws_access_key:1a2b3c4d]"},
        resources=[{"kind": "email", "id": "x@example.com", "sensitive": False, "reason": None}],
        sensitive_resources=["/app/.env"],
        destination={"kind": "email", "identifier": "x@example.com", "classification": "EXTERNAL", "checks": []},
        secrets_in_arguments=[{"type": "aws_access_key", "fingerprint": "1a2b3c4d5e6f7a8b"}],
        session_secret_matches=[{"type": "aws_access_key", "fingerprint": "1a2b3c4d5e6f7a8b"}],
        session={"score": 81, "level": "critical", "untrusted_exposure": True, "sensitive_access": True,
                 "outbound_channel": True, "trifecta": True},
        context={"lowest_trust": "SUSPICIOUS", "untrusted_item_count": 2, "suspicious_source_ids": ["src_1"],
                 "injection_detected": True, "max_detection_severity": "high"},
        detection={"rule_ids": ["TOOL-EXFIL-1"], "max_severity": "high", "categories": ["exfiltration"]},
        integration={"kind": "python_sdk", "supports_enforcement": True},
    )
    assert EvaluationInput.from_dict(full.to_dict()) == full
    assert EvaluationInput.from_dict(full.to_dict()).to_dict() == full.to_dict()


def test_from_dict_tolerates_old_snapshots():
    restored = EvaluationInput.from_dict({"tool": {"name": "Bash"}, "destination": None, "future_field": 1})
    assert restored.tool == {"name": "Bash"}
    assert restored.destination == {}
    assert EvaluationInput.from_dict({}) == EvaluationInput()


def test_policy_match_to_dict():
    match = evaluate(SHELL, [pol("p", "AUDIT")]).matched[0]
    assert set(match.to_dict()) == {"policy_id", "name", "version", "outcome", "mode", "severity", "explanation"}
