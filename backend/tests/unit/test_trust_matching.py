"""Trust engine: glob semantics and rule precedence."""

from __future__ import annotations

import pytest

from app.engines.trust import TrustRuleSpec, assess_source, glob_match
from app.engines.trust.matching import matching_rules


def rule(rid: str, pattern: str, level: str, **kw) -> TrustRuleSpec:
    return TrustRuleSpec(id=rid, name=kw.pop("name", rid), pattern=pattern, trust_level=level, **kw)


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("*.acme.com", "acme.com", True),
        ("*.acme.com", "api.acme.com", True),
        ("*.acme.com", "a.b.acme.com", True),
        ("*.acme.com", "evilacme.com", False),
        ("*.acme.com", "acme.com.evil.io", False),
        ("*.ACME.com", "API.acme.COM", True),
        ("github.com/acme/*", "github.com/acme", True),
        ("github.com/acme/*", "github.com/acme/api/blob/main/x.py", True),
        ("github.com/acme/*", "github.com/acme-evil/api", False),
        ("github.com/acme/*", "github.com/other/acme", False),
        ("github.com/*/docs", "github.com/acme/docs", True),
        ("github.com/*/docs", "github.com/acme/api/docs", False),
        ("https://docs.acme.com/*", "docs.acme.com/guide", True),
        ("docs.acme.com/*", "https://docs.acme.com/guide", True),
        ("docs.acme.com/guide/", "docs.acme.com/guide", True),
        ("*", "anything/at/all?x=1", True),
        ("**", "anything", True),
        ("*@acme.com", "bob@acme.com", True),
        ("*@acme.com", "bob@evil.com", False),
        ("file?.txt", "file1.txt", True),
        ("/srv/**", "/srv/a/b/c", True),
    ],
)
def test_glob_semantics(pattern: str, value: str, expected: bool) -> None:
    assert glob_match(pattern, value) is expected


def test_star_does_not_cross_path_or_query_boundaries() -> None:
    # An attacker-controlled path or query must never satisfy a host pattern.
    assert not glob_match("*.acme.com", "evil.com/?q=.acme.com")
    assert not glob_match("*.acme.com", "evil.com/x.acme.com")


def test_empty_pattern_matches_nothing() -> None:
    assert not glob_match("", "acme.com")
    assert not glob_match("   ", "acme.com")


def test_domain_field_matches_host_and_registrable_domain() -> None:
    by_domain = [rule("r1", "acme.com", "APPROVED", match_field="domain")]
    assert assess_source("web", "https://docs.acme.com/x", rules=by_domain).matched_rule_id == "r1"
    exact_host = [rule("r2", "docs.acme.com", "APPROVED", match_field="domain")]
    assert assess_source("web", "https://blog.acme.com/x", rules=exact_host).matched_rule_id is None


def test_private_suffix_tenants_do_not_share_a_domain_rule() -> None:
    rules = [rule("r1", "github.io", "TRUSTED", match_field="domain")]
    assert assess_source("web", "https://attacker.github.io/payload", rules=rules).matched_rule_id is None


def test_highest_priority_wins() -> None:
    rules = [
        rule("broad", "github.com/*", "EXTERNAL", priority=10),
        rule("ours", "github.com/acme/*", "APPROVED", priority=100),
    ]
    assert assess_source("repository", "acme/api", rules=rules).matched_rule_id == "ours"
    assert assess_source("repository", "other/api", rules=rules).matched_rule_id == "broad"


def test_priority_tie_prefers_more_restrictive_level() -> None:
    rules = [
        rule("allow", "*.acme.com", "TRUSTED", match_field="domain", priority=100),
        rule("block", "evil.acme.com", "BLOCKED", match_field="domain", priority=100),
    ]
    assert assess_source("web", "https://evil.acme.com", rules=rules).level == "BLOCKED"


def test_disabled_invalid_and_wrong_scope_rules_are_ignored() -> None:
    rules = [
        rule("off", "*", "TRUSTED", enabled=False),
        rule("bad-level", "*", "SUPER_TRUSTED"),
        rule("dest-only", "*", "TRUSTED", applies_to="destination"),
        rule("bad-field", "*", "TRUSTED", match_field="body"),
    ]
    assert assess_source("web", "https://example.com", rules=rules).matched_rule_id is None


def test_source_type_filter() -> None:
    rules = [rule("emails", "*.acme.com", "APPROVED", match_field="domain", source_type="email")]
    assert assess_source("email", "bob@acme.com", rules=rules).matched_rule_id == "emails"
    assert assess_source("web", "https://acme.com", rules=rules).matched_rule_id is None


def test_both_scope_applies_to_sources_and_destinations() -> None:
    both = rule("b", "*.acme.com", "APPROVED", match_field="domain", applies_to="both", source_type="web")
    assert matching_rules([both], scope="source", source_type="web", identifiers=[], domains=["acme.com"])
    # source_type is a source filter only; it does not restrict destination matching.
    assert matching_rules([both], scope="destination", identifiers=[], domains=["acme.com"])


def test_pathological_patterns_match_in_linear_time() -> None:
    import time

    value = "a" * 2000
    started = time.perf_counter()
    assert not glob_match("*a*a*a*a*a*a*a*a*a*a*a*a*b", value)
    assert not glob_match("**a**a**a**a**a**a**b", value)
    assert time.perf_counter() - started < 1.0
