"""Trust engine: destination assessment, lookalikes and the default rule set."""

from __future__ import annotations

import pytest

from app.domain.enums import TrustCapability, TrustLevel
from app.engines.trust import DestinationHistory, TrustRuleSpec, assess_destination, assess_source
from app.engines.trust.defaults import DEFAULT_TRUST_RULES
from app.engines.trust.lookalike import edit_distance, find_lookalike, skeleton
from app.engines.trust.matching import compile_glob

ALLOW = [
    TrustRuleSpec(
        id="allow-acme",
        name="Acme",
        pattern="*.acmecorp.com",
        trust_level="APPROVED",
        applies_to="destination",
        match_field="domain",
    ),
    TrustRuleSpec(
        id="allow-anthropic",
        name="Anthropic API",
        pattern="api.anthropic.com",
        trust_level="APPROVED",
        applies_to="destination",
        match_field="domain",
    ),
]


def checks_of(result) -> dict[str, dict[str, str]]:
    return {c["check"]: c for c in result.checks}


def default_specs() -> list[TrustRuleSpec]:
    specs = []
    for i, spec in enumerate(DEFAULT_TRUST_RULES):
        fields = {k: v for k, v in spec.items() if k != "description"}
        fields["capabilities"] = tuple(fields["capabilities"])
        specs.append(TrustRuleSpec(id=f"default-{i}", **fields))
    return specs


# ------------------------------------------------------------------------------ classification


def test_unknown_destination_reason_and_honest_scope() -> None:
    result = assess_destination("domain", "https://Example.org:8443/upload?key=s3cr3t", rules=ALLOW)
    assert result.classification == "UNKNOWN"
    assert result.canonical_identifier == "example.org"
    assert "s3cr3t" not in str(result.checks) + str(result.reasons)
    assert any("not on the organisation's destination allowlist" in r for r in result.reasons)
    assert "did not resolve DNS" in result.reasons[-1] and "who will receive the data" in result.reasons[-1]
    assert not any(
        "verified recipient" in r.lower() or "identity verified" in r.lower() for r in result.reasons
    )


def test_allowlisted_destination_passes() -> None:
    result = assess_destination("domain", "uploads.acmecorp.com", rules=ALLOW)
    checks = checks_of(result)
    assert result.classification == "APPROVED" and result.matched_rule_id == "allow-acme"
    assert checks["allowlist"]["result"] == "pass"
    assert checks["lookalike"]["result"] == "pass"


def test_blocklist_rule_matches_and_fails_check() -> None:
    rules = [
        *ALLOW,
        TrustRuleSpec(
            id="blk",
            name="Rival",
            pattern="*.rival.io",
            trust_level="BLOCKED",
            applies_to="destination",
            match_field="domain",
        ),
    ]
    result = assess_destination("domain", "drop.rival.io", rules=rules)
    assert result.classification == "BLOCKED"
    assert checks_of(result)["blocklist"]["result"] == "fail"


def test_higher_priority_allow_overrides_block_and_says_so() -> None:
    rules = [
        TrustRuleSpec(
            id="blk",
            name="Tunnels",
            pattern="*.ngrok-free.app",
            trust_level="SUSPICIOUS",
            applies_to="destination",
            match_field="domain",
            priority=150,
        ),
        TrustRuleSpec(
            id="ours",
            name="Our demo tunnel",
            pattern="demo-acme.ngrok-free.app",
            trust_level="APPROVED",
            applies_to="destination",
            match_field="domain",
            priority=200,
        ),
    ]
    result = assess_destination("domain", "demo-acme.ngrok-free.app", rules=rules)
    assert result.classification == "APPROVED" and result.matched_rule_id == "ours"
    assert checks_of(result)["blocklist"]["result"] == "warn"
    assert any("allows it anyway" in r for r in result.reasons)


@pytest.mark.parametrize(
    ("identifier", "service"),
    [
        ("https://webhook.site/0b6c-uuid", "Webhook.site"),
        ("en2x1.x.pipedream.net", "Pipedream"),
        ("requestbin.net", "RequestBin"),
        ("abc123.ngrok-free.app", "ngrok"),
        ("https://foo.ngrok.io/collect", "ngrok"),
        ("quiet-sky.trycloudflare.com", "Cloudflare quick tunnel"),
        ("pastebin.com", "Pastebin"),
        ("paste.ee", "paste.ee"),
        ("hastebin.com", "Hastebin"),
        ("https://transfer.sh/upload", "transfer.sh"),
        ("file.io", "file.io"),
        ("c59e3.oast.fun", "Interactsh"),
        ("x.interact.sh", "Interactsh"),
        ("abc.burpcollaborator.net", "Burp Collaborator"),
        ("mock.free.beeceptor.com", "Beeceptor"),
        ("https://discord.com/api/webhooks/123/TOKEN", "Discord webhook"),
        ("https://api.telegram.org/bot123:ABC/sendMessage", "Telegram Bot API"),
    ],
)
def test_exfiltration_services_are_suspicious(identifier: str, service: str) -> None:
    result = assess_destination("domain", identifier, rules=[])
    check = checks_of(result)["exfiltration_service"]
    assert result.classification == "SUSPICIOUS", result.reasons
    assert check["result"] == "fail" and service in check["detail"]
    assert "TOKEN" not in result.canonical_identifier and "ABC" not in result.canonical_identifier


def test_discord_webhook_has_its_own_canonical_identifier() -> None:
    hook = assess_destination("domain", "https://discord.com/api/webhooks/1/secret", rules=[])
    plain = assess_destination("domain", "https://discord.com/channels/1", rules=[])
    assert hook.canonical_identifier == "discord.com/api/webhooks"
    assert plain.canonical_identifier == "discord.com" and plain.classification == "UNKNOWN"


def test_broad_external_rule_does_not_hide_exfiltration_signals() -> None:
    rules = [
        TrustRuleSpec(
            id="all",
            name="Everything external",
            pattern="*",
            trust_level="EXTERNAL",
            applies_to="destination",
            match_field="domain",
        )
    ]
    result = assess_destination("domain", "webhook.site", rules=rules)
    assert result.classification == "SUSPICIOUS" and result.matched_rule_id == "all"


# ----------------------------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    ("identifier", "ip_result", "internal_result", "classification"),
    [
        ("127.0.0.1", "pass", "pass", "APPROVED"),
        ("http://[::1]:9000/x", "pass", "pass", "APPROVED"),
        ("localhost:3000", "pass", "pass", "APPROVED"),
        ("10.1.2.3", "warn", "warn", "UNKNOWN"),
        ("192.168.0.10", "warn", "warn", "UNKNOWN"),
        ("0.0.0.0", "warn", "warn", "UNKNOWN"),  # noqa: S104 (a destination, not a bind address)
        ("8.8.8.8", "warn", "pass", "UNKNOWN"),
    ],
)
def test_ip_and_internal_address_matrix(identifier, ip_result, internal_result, classification) -> None:
    result = assess_destination("unknown", identifier, rules=[])
    checks = checks_of(result)
    assert checks["ip_literal"]["result"] == ip_result
    assert checks["internal_address"]["result"] == internal_result
    assert result.classification == classification


def test_raw_ip_kind_is_inferred() -> None:
    assert assess_destination("domain", "http://93.184.216.34/", rules=[]).kind == "ip"
    assert assess_destination("ip", "example.com", rules=[]).kind == "domain"


@pytest.mark.parametrize(
    "identifier",
    [
        "169.254.169.254",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://2852039166/latest/meta-data/",
    ],
)
def test_cloud_metadata_endpoints_are_suspicious(identifier: str) -> None:
    result = assess_destination("unknown", identifier, rules=[])
    assert result.classification == "SUSPICIOUS"
    assert checks_of(result)["cloud_metadata"]["result"] == "fail"


def test_obfuscated_ip_notation_fails_ip_check() -> None:
    result = assess_destination("unknown", "http://0x5db8d822/", rules=[])
    check = checks_of(result)["ip_literal"]
    assert check["result"] == "fail" and "non-standard" in check["detail"]
    assert result.classification == "SUSPICIOUS"


# ----------------------------------------------------------------------------------- lookalikes


@pytest.mark.parametrize(
    ("host", "technique"),
    [
        ("acmecorp.co", "suffix_swap"),
        ("acmec0rp.com", "homoglyph"),
        ("acmeccorp.com", "edit_distance"),
        ("amcecorp.com", "edit_distance"),
        ("anthroplc.com", "homoglyph"),
        ("antrhopic.com", "edit_distance"),
        ("xn--nthropic-06g.com", "homoglyph"),  # Cyrillic "а" in place of Latin "a"
        ("acmecorp.com.evil.io", "embedded"),
    ],
)
def test_lookalikes_of_allowlisted_domains_are_suspicious(host: str, technique: str) -> None:
    allowlisted = {"acmecorp.com", "anthropic.com"}
    found = find_lookalike(host, allowlisted)
    assert found is not None and found.technique == technique
    result = assess_destination("domain", host, rules=ALLOW)
    assert result.classification == "SUSPICIOUS"
    assert checks_of(result)["lookalike"]["result"] == "fail"


@pytest.mark.parametrize(
    "host", ["github.com", "gitlab.com", "example.org", "acme.com", "x.com", "api.acmecorp.com"]
)
def test_unrelated_or_same_domains_are_not_lookalikes(host: str) -> None:
    assert find_lookalike(host, {"acmecorp.com", "anthropic.com", "y.com"}) is None


def test_short_names_need_exact_confusables_not_edits() -> None:
    assert find_lookalike("abd.io", {"abc.io"}) is None


def test_punycode_check_warns_with_display_form() -> None:
    result = assess_destination("domain", "https://bücher.example/", rules=[])
    check = checks_of(result)["punycode"]
    assert result.canonical_identifier == "xn--bcher-kva.example"
    assert check["result"] == "warn" and "bücher.example" in check["detail"]


def test_lookalike_check_unknown_without_allowlist() -> None:
    assert (
        checks_of(assess_destination("domain", "example.org", rules=[]))["lookalike"]["result"] == "unknown"
    )


def test_skeleton_and_edit_distance_helpers() -> None:
    assert skeleton("pаypal") == skeleton("paypal")  # Cyrillic а
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert edit_distance("github", "gihtub") == 1  # transposition counts once
    assert edit_distance("kitten", "sitting") == 3


# -------------------------------------------------------------------------------- other kinds


def test_email_destination_checks_domain_only() -> None:
    result = assess_destination("email", "Bob <BOB@AcmeCorp.com>", rules=ALLOW)
    assert result.kind == "email" and result.canonical_identifier == "bob@acmecorp.com"
    assert result.classification == "APPROVED"
    assert "mailbox exists" in result.reasons[-1]


def test_email_to_lookalike_domain_is_suspicious() -> None:
    assert assess_destination("email", "ceo@acmec0rp.com", rules=ALLOW).classification == "SUSPICIOUS"


def test_agent_destination_does_not_claim_identity() -> None:
    result = assess_destination("agent", "  billing   agent ", rules=[])
    assert result.kind == "agent" and result.canonical_identifier == "billing agent"
    assert result.classification == "UNKNOWN"
    assert "did not verify the receiving agent's identity" in result.reasons[-1]


def test_service_name_is_not_treated_as_host() -> None:
    result = assess_destination("service", "Slack", rules=[])
    assert result.canonical_identifier == "slack" and result.kind == "service"
    assert "ip_literal" not in checks_of(result)


def test_kind_is_inferred_for_unknown() -> None:
    assert assess_destination("unknown", "alice@example.com", rules=[]).kind == "email"
    assert assess_destination("unknown", "https://example.com/x", rules=[]).kind == "domain"


@pytest.mark.parametrize(
    ("history", "result"),
    [
        (None, "unknown"),
        (DestinationHistory(previously_seen=False), "warn"),
        (DestinationHistory(previously_seen=True, transfer_count=12), "pass"),
    ],
)
def test_first_seen_check(history, result) -> None:
    assessed = assess_destination("domain", "example.org", rules=[], history=history)
    assert checks_of(assessed)["first_seen"]["result"] == result


def test_every_check_has_the_documented_shape() -> None:
    result = assess_destination("domain", "https://webhook.site/x", rules=ALLOW)
    for check in result.checks:
        assert set(check) == {"check", "result", "detail"}
        assert check["result"] in {"pass", "fail", "warn", "unknown"}
        assert check["detail"].endswith(".")


# ------------------------------------------------------------------------------ default rules


def test_default_rules_are_well_formed() -> None:
    keys = {
        "name",
        "description",
        "applies_to",
        "source_type",
        "match_field",
        "pattern",
        "trust_level",
        "capabilities",
        "priority",
    }
    levels = {lvl.value for lvl in TrustLevel}
    capabilities = {c.value for c in TrustCapability}
    names = set()
    for spec in DEFAULT_TRUST_RULES:
        assert set(spec) == keys
        assert spec["trust_level"] in levels
        assert spec["applies_to"] in {"source", "destination", "both"}
        assert spec["match_field"] in {"identifier", "domain"}
        assert set(spec["capabilities"]) <= capabilities
        assert spec["description"] and spec["description"].endswith(".")
        assert compile_glob(spec["pattern"])
        assert (spec["name"], spec["pattern"]) not in names
        names.add((spec["name"], spec["pattern"]))


@pytest.mark.parametrize(
    ("source_type", "identifier", "level"),
    [
        ("user_prompt", "prompt", "TRUSTED"),
        ("web", "https://docs.python.org/3/library/os.html", "EXTERNAL"),
        ("web", "https://developer.mozilla.org/en-US/docs/Web", "EXTERNAL"),
        ("web", "https://nodejs.org/api/fs.html", "EXTERNAL"),
        ("web", "https://pypi.org/project/requests/", "EXTERNAL"),
        ("web", "https://www.npmjs.com/package/left-pad", "EXTERNAL"),
        ("repository", "someone/project", "EXTERNAL"),
        ("web", "https://random-blog.example/post", "UNKNOWN"),
    ],
)
def test_default_rules_for_sources(source_type: str, identifier: str, level: str) -> None:
    result = assess_source(source_type, identifier, rules=default_specs())
    assert result.level == level
    if level == "EXTERNAL":
        assert result.capabilities == ["read"]


def test_org_rule_overrides_default_github_rule() -> None:
    rules = [
        *default_specs(),
        TrustRuleSpec(
            id="ours",
            name="Our repos",
            pattern="github.com/acme/*",
            trust_level="APPROVED",
            capabilities=("read",),
        ),
    ]
    assert assess_source("repository", "acme/api", rules=rules).matched_rule_id == "ours"


@pytest.mark.parametrize(
    ("identifier", "classification"),
    [
        ("https://api.anthropic.com/v1/messages", "APPROVED"),
        ("api.openai.com", "APPROVED"),
        ("localhost:8080", "APPROVED"),
        ("127.0.0.1", "APPROVED"),
        ("webhook.site", "SUSPICIOUS"),
        ("abc.ngrok-free.app", "SUSPICIOUS"),
        ("api.anthropic.co", "SUSPICIOUS"),
        ("example.org", "UNKNOWN"),
    ],
)
def test_default_rules_for_destinations(identifier: str, classification: str) -> None:
    assert assess_destination("domain", identifier, rules=default_specs()).classification == classification


def test_default_provider_rule_explains_what_approval_does_not_cover() -> None:
    provider = next(s for s in DEFAULT_TRUST_RULES if s["pattern"] == "api.anthropic.com")
    assert "does not verify" in provider["description"]


def test_destination_userinfo_and_backslash_tricks() -> None:
    rules = [
        TrustRuleSpec(
            id="good",
            name="Good",
            pattern="good.com",
            trust_level="APPROVED",
            applies_to="destination",
            match_field="domain",
        )
    ]
    tricked = assess_destination("domain", "https://evil.com\\@good.com/collect", rules=rules)
    assert tricked.canonical_identifier == "evil.com" and tricked.classification == "UNKNOWN"
    userinfo = assess_destination("domain", "https://good.com:pw@evil.com/", rules=rules)
    assert userinfo.canonical_identifier == "evil.com" and "pw" not in str(userinfo.checks)
