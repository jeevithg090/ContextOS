"""validate_conditions / validate_restrictions and the field catalog."""

from __future__ import annotations

from dataclasses import fields

import pytest

from app.engines.policy import (
    FIELD_CATALOG,
    OPERATORS,
    EvaluationInput,
    validate_conditions,
    validate_restrictions,
)
from app.engines.policy.conditions import MAX_DEPTH
from app.engines.policy.fields import OPS, canonical_path, lookup_field
from app.engines.policy.validation import MAX_NODES


def leaf(field: str, op: str, value=None) -> dict:
    node = {"field": field, "op": op}
    if value is not None:
        node["value"] = value
    return node


def one_error(cond) -> str:
    errors = validate_conditions(cond)
    assert len(errors) == 1, errors
    return errors[0]


def test_valid_conditions_have_no_errors():
    cond = {
        "all": [
            leaf("tool.category", "in", ["http", "EMAIL"]),
            {"any": [leaf("secrets_in_arguments", "not_empty"), leaf("session.score", "gte", 80)]},
            {"not": leaf("destination.classification", "in", ["TRUSTED", "approved"])},
            leaf("resources[*].sensitive", "is_true"),
            leaf("resources[0].id", "glob", "*.env"),
            leaf("detection.max_severity", "gte", "high"),
            leaf("detection.rule_ids", "any_glob", ["TOOL-*"]),
            leaf("arguments.headers.host", "eq", "pastebin.com"),
            leaf("arguments.size", "gt", 1000),
            leaf("agent.labels", "contains", "pci"),
        ]
    }
    assert validate_conditions(cond) == []


@pytest.mark.parametrize("cond", [{}, None, [], "tool.category == http"])
def test_empty_or_non_object_conditions_are_rejected(cond):
    assert validate_conditions(cond)


def test_unknown_field_suggests_the_closest_path():
    err = one_error(leaf("tool.categry", "eq", "http"))
    assert err == 'conditions: unknown field "tool.categry" (did you mean "tool.category"?)'


def test_unknown_operator_is_reported_with_location():
    err = one_error({"all": [leaf("tool.name", "exists"), leaf("tool.name", "equals", "Bash")]})
    assert err.startswith("conditions.all[1]: unknown operator 'equals'")


def test_type_mismatch_comparison_on_string():
    err = one_error(leaf("tool.name", "gt", "a"))
    assert 'operator "gt" is not supported for string field tool.name' in err
    assert "comparisons need a number field or an ordered enum" in err


def test_comparison_on_unordered_enum_is_rejected_but_ordered_enum_is_fine():
    assert validate_conditions(leaf("tool.category", "gte", "http"))
    assert validate_conditions(leaf("session.level", "gte", "high")) == []
    assert validate_conditions(leaf("context.lowest_trust", "lt", "EXTERNAL")) == []


def test_number_field_needs_number_values():
    assert 'operator "gt" needs a number' in one_error(leaf("session.score", "gt", "80"))
    assert "value must be a number" in one_error(leaf("session.score", "eq", True))
    assert "value[1]" in one_error(leaf("context.untrusted_item_count", "in", [1, "two"]))


def test_list_and_boolean_fields_get_operator_hints():
    assert '"contains"' in one_error(leaf("agent.labels", "eq", "pci"))
    assert "any_glob" in one_error(leaf("detection.rule_ids", "glob", "TOOL-*"))
    assert "value must be true or false" in one_error(leaf("session.trifecta", "eq", "yes"))
    assert "not supported for string field" in one_error(leaf("tool.name", "is_true"))


@pytest.mark.parametrize(
    ("path", "bad"),
    [
        ("tool.category", "web"),
        ("destination.classification", "TRUSTWORTHY"),
        ("session.level", "extreme"),
        ("agent.environment", "prod"),
        ("context.lowest_trust", "SAFE"),
        ("detection.max_severity", "urgent"),
        ("destination.kind", "url"),
        ("tool.risk_level", "none"),
    ],
)
def test_unknown_enum_values_are_rejected(path, bad):
    err = one_error(leaf(path, "eq", bad))
    assert f'unknown value "{bad}" for {path}' in err


def test_enum_item_values_in_lists_are_checked():
    err = one_error(leaf("detection.categories", "contains", "prompt-injection"))
    assert 'unknown item value "prompt-injection"' in err
    assert 'did you mean "prompt_injection"' in err
    assert validate_conditions(leaf("detection.categories", "contains", "PROMPT_INJECTION")) == []


def test_enum_values_in_lists_are_checked_per_item():
    err = one_error(leaf("tool.category", "in", ["http", "smtp"]))
    assert err.startswith("conditions: value[1]: unknown value")


def test_value_shape_rules():
    assert "non-empty list" in one_error(leaf("tool.category", "in", "http"))
    assert "non-empty list" in one_error(leaf("tool.category", "not_in", []))
    assert "takes no value" in one_error(leaf("tool.name", "exists", True))
    assert "requires a" in one_error(leaf("tool.name", "eq"))
    assert "glob string" in one_error(leaf("tool.name", "glob", ["", "x"]))
    assert "single string" in one_error(leaf("tool.name", "eq", ["Bash"]))
    assert "needs a number" in one_error(leaf("arguments.size", "gt", "big"))


@pytest.mark.parametrize(
    ("cond", "fragment"),
    [
        ({"all": [], "any": []}, "only one of all/any/not"),
        ({"all": []}, "conditions.all: must be a non-empty list"),
        ({"any": {"field": "tool.name"}}, "conditions.any: must be a non-empty list"),
        ({"not": {}}, "conditions.not: empty condition"),
        ({"all": ["tool.name"]}, "conditions.all[0]: a condition must be an object"),
        ({"fields": "tool.name", "op": "exists"}, "'field' must be a non-empty string"),
        ({"field": "tool.name", "op": "exists", "values": 1}, "unexpected keys ['values']"),
        ({"match": "tool.name"}, "unrecognised keys"),
        (leaf("resources[x].id", "exists"), "malformed field path"),
        (leaf("agent", "exists"), 'unknown field "agent"'),
    ],
)
def test_structural_errors(cond, fragment):
    errors = validate_conditions(cond)
    assert any(fragment in e for e in errors), errors


def test_depth_and_size_limits():
    deep: dict = leaf("tool.name", "exists")
    for _ in range(MAX_DEPTH + 1):
        deep = {"not": deep}
    assert any("nested deeper" in e for e in validate_conditions(deep))
    wide = {"any": [leaf("tool.name", "exists")] * (MAX_NODES + 5)}
    errors = validate_conditions(wide)
    assert errors == [f"conditions: more than {MAX_NODES} condition nodes; simplify the policy"]


def test_multiple_errors_are_all_reported():
    errors = validate_conditions({"all": [leaf("tool.categry", "eq", "x"), leaf("session.score", "gt", "x")]})
    assert len(errors) == 2


# ---- restrictions ----------------------------------------------------------------------------


def test_valid_restrictions():
    r = {
        "redact_secrets": True,
        "allowed_path_globs": ["src/*"],
        "deny_path_globs": ["*.pem"],
        "max_argument_bytes": 4096,
    }
    assert validate_restrictions(r, outcome="RESTRICT") == []
    assert validate_restrictions({}, outcome="DENY") == []


@pytest.mark.parametrize(
    ("restrictions", "outcome", "fragment"),
    [
        ({"redact": True}, None, 'unknown key "redact"'),
        ({"redact_secrets": "yes"}, None, "true or false"),
        ({"deny_path_globs": "*.pem"}, None, "list of non-empty glob strings"),
        ({"allowed_path_globs": []}, None, "allows no path"),
        ({"max_argument_bytes": 0}, None, "max_argument_bytes"),
        ({"max_argument_bytes": True}, None, "max_argument_bytes"),
        ({}, "RESTRICT", "at least one restriction"),
        ({"redact_secrets": False}, "RESTRICT", "at least one restriction"),
        ({"redact_secrets": True}, "DENY", "only RESTRICT policies"),
        ("x", None, "must be a JSON object"),
    ],
)
def test_invalid_restrictions(restrictions, outcome, fragment):
    errors = validate_restrictions(restrictions, outcome=outcome)
    assert any(fragment in e for e in errors), errors


# ---- catalog ---------------------------------------------------------------------------------


def test_catalog_covers_every_evaluation_input_field():
    roots = {e["path"].split(".")[0].split("[")[0] for e in FIELD_CATALOG}
    assert roots == {f.name for f in fields(EvaluationInput)}


def test_catalog_entries_are_well_formed():
    paths = [e["path"] for e in FIELD_CATALOG]
    assert len(paths) == len(set(paths))
    for entry in FIELD_CATALOG:
        assert entry["type"] in {"string", "number", "boolean", "list", "enum", "any"}
        assert entry["description"] and "example" in entry
        assert entry["ops"] and set(entry["ops"]) <= OPS
        if entry["type"] == "enum":
            assert entry["values"] and isinstance(entry["ordered"], bool)
        if entry["type"] == "list":
            assert entry["item_type"] in {"string", "enum", "object"}
    assert {o["op"] for o in OPERATORS} == OPS


@pytest.mark.parametrize(
    "path",
    [
        "agent.name",
        "agent.environment",
        "agent.labels",
        "agent.framework",
        "tool.name",
        "tool.category",
        "tool.provider",
        "tool.server",
        "tool.risk_level",
        "resources[*].kind",
        "resources[*].id",
        "resources[*].sensitive",
        "sensitive_resources",
        "destination.kind",
        "destination.identifier",
        "destination.classification",
        "secrets_in_arguments",
        "session_secret_matches",
        "session.score",
        "session.level",
        "session.untrusted_exposure",
        "session.sensitive_access",
        "session.outbound_channel",
        "session.trifecta",
        "context.lowest_trust",
        "context.untrusted_item_count",
        "context.injection_detected",
        "context.max_detection_severity",
        "detection.rule_ids",
        "detection.max_severity",
        "detection.categories",
        "integration.kind",
        "integration.supports_enforcement",
    ],
)
def test_catalog_contains_documented_paths(path):
    assert lookup_field(path) is not None


def test_path_canonicalisation():
    assert canonical_path("resources[3].id") == "resources[*].id"
    assert canonical_path("arguments.headers.host") == "arguments.*"
    assert canonical_path("arguments") == "arguments"
    assert canonical_path("tool..name") is None
    assert lookup_field("tool.nope") is None
