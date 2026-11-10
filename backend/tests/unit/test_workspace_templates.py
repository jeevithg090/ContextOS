"""Board templates and column validation."""

from __future__ import annotations

import json

import pytest

from app.workspace.templates import (
    BOARD_TEMPLATES,
    COLOR_TOKENS,
    DEFAULT_TEMPLATE,
    STATUS_KEYS,
    get_template,
    list_templates,
    validate_columns,
)

EXPECTED_KEYS = {
    "software_development", "security_remediation", "incident_response", "bug_tracking",
    "feature_development", "technical_debt", "research_experiments",
}


def test_all_required_templates_exist_and_default_is_software_development():
    assert set(BOARD_TEMPLATES) == EXPECTED_KEYS
    assert DEFAULT_TEMPLATE == "software_development"


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_every_template_is_valid_and_json_serialisable(key):
    tpl = BOARD_TEMPLATES[key]
    assert tpl["name"] and tpl["description"]
    assert validate_columns(tpl["columns"]) == []
    for col in tpl["columns"]:
        assert col["status_key"] in STATUS_KEYS
        assert col["color"] in COLOR_TOKENS
        assert set(col) == {"name", "description", "color", "status_key", "wip_limit", "is_done_column",
                            "requires_verification"}
    assert tpl["columns"][-1]["is_done_column"] is True
    json.dumps(tpl)


def test_software_development_columns_match_spec():
    names = [c["name"] for c in BOARD_TEMPLATES["software_development"]["columns"]]
    assert names == ["Backlog", "To Do", "Investigating", "Ready for Fix", "In Progress", "Code Review", "Testing", "Done"]


def test_security_remediation_requires_verification_only_on_verified_column():
    cols = BOARD_TEMPLATES["security_remediation"]["columns"]
    assert [c["name"] for c in cols] == ["Triage", "Investigating", "Fix Planned", "In Progress", "Review", "Testing",
                                         "Verified", "Done"]
    assert [c["name"] for c in cols if c["requires_verification"]] == ["Verified"]
    assert next(c for c in cols if c["name"] == "Verified")["status_key"] == "verified"


def test_get_template_returns_independent_copy_and_rejects_unknown():
    copy = get_template("bug_tracking")
    copy["columns"][0]["name"] = "Changed"
    assert BOARD_TEMPLATES["bug_tracking"]["columns"][0]["name"] == "Reported"
    assert copy["key"] == "bug_tracking"
    with pytest.raises(KeyError):
        get_template("kanban_deluxe")


def test_validate_columns_reports_plain_language_problems():
    errors = validate_columns([
        {"name": "A", "status_key": "nope", "color": "pink", "wip_limit": 0},
        {"name": "a", "status_key": "todo", "color": "#12345g", "is_done_column": True},
    ])
    text = " ".join(errors)
    assert "unknown status_key" in text
    assert "colour" in text
    assert "WIP limit" in text
    assert "used more than once" in text
    assert "status_key is not 'done'" in text
    assert validate_columns([]) == ["A board needs at least one column."]
    assert any("done column" in e for e in validate_columns([{"name": "X", "status_key": "todo", "color": "slate"}]))


def test_validate_columns_accepts_hex_colours_and_list_templates_summarises():
    cols = [{"name": "Done", "status_key": "done", "color": "#a1B2c3", "is_done_column": True}]
    assert validate_columns(cols) == []
    summary = {t["key"]: t for t in list_templates()}
    assert summary["security_remediation"]["requires_verification"] is True
    assert summary["software_development"]["requires_verification"] is False
    assert summary["technical_debt"]["columns"][0] == "Identified"
