"""Trust engine: source assessment (precedence, defaults, inheritance, evidence)."""

from __future__ import annotations

import pytest

from app.engines.trust import SourceHistory, TrustRuleSpec, assess_source


def rule(rid: str, pattern: str, level: str, **kw) -> TrustRuleSpec:
    return TrustRuleSpec(id=rid, name=kw.pop("name", rid), pattern=pattern, trust_level=level, **kw)


def _sentences(reasons: list[str]) -> None:
    for reason in reasons:
        assert reason[:1].isupper() and reason.endswith("."), reason


@pytest.mark.parametrize(
    ("source_type", "level", "capabilities"),
    [
        ("user_prompt", "TRUSTED", ["read", "instruct", "execute"]),
        ("system", "TRUSTED", ["read", "instruct", "execute"]),
        ("web", "UNKNOWN", ["read"]),
        ("email", "UNKNOWN", ["read"]),
        ("mcp_tool", "UNKNOWN", ["read"]),
        ("file", "UNKNOWN", ["read"]),
        ("repository", "UNKNOWN", ["read"]),
    ],
)
def test_defaults_without_rules(source_type: str, level: str, capabilities: list[str]) -> None:
    result = assess_source(source_type, "x-identifier", rules=[])
    assert result.level == level
    assert result.capabilities == capabilities
    assert result.matched_rule_id is None
    _sentences(result.reasons)


def test_file_default_reason_says_content_is_data() -> None:
    result = assess_source("file", "/repo/README.md", rules=[])
    assert "not instructions" in result.reasons[0] and "No trust rule classifies" in result.reasons[0]
    assert not result.can_instruct


def test_rule_sets_level_and_default_capabilities() -> None:
    rules = [rule("r1", "docs.acme.com", "EXTERNAL", match_field="domain")]
    result = assess_source("web", "https://docs.acme.com/x", rules=rules)
    assert (result.level, result.capabilities, result.matched_rule_id) == ("EXTERNAL", ["read"], "r1")
    assert "'r1'" in result.reasons[0] and "EXTERNAL" in result.reasons[0]


def test_rule_capabilities_override_defaults() -> None:
    rules = [rule("r1", "github.com/acme/*", "APPROVED", capabilities=("read", "instruct"))]
    result = assess_source("repository", "acme/api", rules=rules)
    assert result.capabilities == ["read", "instruct"]
    assert result.can_instruct


def test_data_only_levels_never_get_instruct_even_if_a_rule_asks() -> None:
    rules = [rule("r1", "*.example.com", "EXTERNAL", match_field="domain", capabilities=("read", "instruct"))]
    result = assess_source("web", "https://example.com", rules=rules)
    assert result.capabilities == ["read"]
    assert any("'instruct'" in r and "not applied" in r for r in result.reasons)


def test_blocked_has_no_capabilities() -> None:
    rules = [rule("r1", "*.evil.com", "BLOCKED", match_field="domain", capabilities=("read",))]
    result = assess_source("web", "https://evil.com/x", rules=rules)
    assert result.level == "BLOCKED" and result.capabilities == []


def test_manual_classification_wins_over_rules() -> None:
    rules = [rule("r1", "*.example.com", "EXTERNAL", match_field="domain")]
    history = SourceHistory(
        manually_classified=True, current_level="APPROVED", current_capabilities=("read",)
    )
    result = assess_source("web", "https://example.com", rules=rules, history=history)
    assert result.level == "APPROVED" and result.matched_rule_id is None
    assert "manually" in result.reasons[0]
    assert any("r1" in r and "EXTERNAL" in r for r in result.reasons)


def test_manual_flag_without_level_falls_back_to_rules() -> None:
    rules = [rule("r1", "*.example.com", "EXTERNAL", match_field="domain")]
    history = SourceHistory(manually_classified=True, current_level=None)
    assert assess_source("web", "https://example.com", rules=rules, history=history).matched_rule_id == "r1"


@pytest.mark.parametrize("source_type", ["tool_output", "agent_output"])
def test_produced_output_inherits_level(source_type: str) -> None:
    result = assess_source(source_type, "Task", rules=[], history=SourceHistory(inherited_level="SUSPICIOUS"))
    assert result.level == "SUSPICIOUS" and result.capabilities == ["read"]
    assert "never treated as more trusted than what it read" in result.reasons[0]


def test_produced_output_without_inheritance_is_unknown() -> None:
    result = assess_source("agent_output", "researcher", rules=[])
    assert result.level == "UNKNOWN"
    assert "sub-agent" in result.reasons[0] and "nothing was recorded" in result.reasons[0]


def test_trusted_inheritance_passes_through() -> None:
    result = assess_source("tool_output", "Read", rules=[], history=SourceHistory(inherited_level="TRUSTED"))
    assert result.level == "TRUSTED" and result.can_instruct


def test_rule_cannot_make_output_more_trusted_than_its_inputs() -> None:
    rules = [rule("r1", "*", "TRUSTED", source_type="agent_output")]
    result = assess_source(
        "agent_output", "helper", rules=rules, history=SourceHistory(inherited_level="EXTERNAL")
    )
    assert result.level == "EXTERNAL" and result.capabilities == ["read"]
    assert any("capped at EXTERNAL" in r for r in result.reasons)


def test_high_severity_findings_downgrade_rule_trust() -> None:
    rules = [rule("r1", "github.com/acme/*", "TRUSTED")]
    history = SourceHistory(finding_count=2, max_finding_severity="high")
    result = assess_source("repository", "acme/api", rules=rules, history=history)
    assert result.level == "SUSPICIOUS"
    assert result.capabilities == ["read"]
    assert result.matched_rule_id == "r1"
    assert any("2 findings were observed" in r and "highest severity: high" in r for r in result.reasons)
    _sentences(result.reasons)


def test_evidence_downgrades_even_manually_trusted_sources() -> None:
    history = SourceHistory(
        manually_classified=True,
        current_level="TRUSTED",
        current_capabilities=("read", "instruct", "execute"),
        finding_count=3,
        max_finding_severity="critical",
    )
    result = assess_source("web", "https://wiki.acme.com/page", rules=[], history=history)
    assert result.level == "SUSPICIOUS" and not result.can_instruct and "execute" not in result.capabilities
    evidence = result.reasons[-1]
    assert evidence.startswith("It was manually classified as TRUSTED, but 3 findings were observed")
    assert "SUSPICIOUS until the findings are reviewed" in evidence


def test_single_finding_reason_uses_singular() -> None:
    history = SourceHistory(finding_count=1, max_finding_severity="high")
    result = assess_source("web", "https://x.example", rules=[], history=history)
    assert any("1 finding was observed" in r for r in result.reasons)


def test_medium_findings_do_not_downgrade_but_are_explained() -> None:
    rules = [rule("r1", "*.acme.com", "APPROVED", match_field="domain")]
    history = SourceHistory(finding_count=4, max_finding_severity="medium")
    result = assess_source("web", "https://acme.com", rules=rules, history=history)
    assert result.level == "APPROVED"
    assert any("does not change the classification" in r for r in result.reasons)


def test_blocked_stays_blocked_with_evidence() -> None:
    rules = [rule("r1", "*.evil.com", "BLOCKED", match_field="domain")]
    history = SourceHistory(finding_count=5, max_finding_severity="critical")
    result = assess_source("web", "https://evil.com", rules=rules, history=history)
    assert result.level == "BLOCKED" and result.capabilities == []
    assert any("remains BLOCKED" in r for r in result.reasons)


def test_findings_without_severity_do_not_downgrade() -> None:
    history = SourceHistory(finding_count=2, max_finding_severity=None)
    assert assess_source("user_prompt", "p", rules=[], history=history).level == "TRUSTED"


def test_assessment_carries_canonical_identifier_and_domain() -> None:
    result = assess_source("web", "HTTPS://Docs.Acme.co.uk/Guide/?utm_source=x", rules=[])
    assert result.canonical_identifier == "https://docs.acme.co.uk/Guide"
    assert result.domain == "acme.co.uk"
