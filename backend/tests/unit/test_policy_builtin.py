"""Built-in policy pack: shape, validity, and a positive + negative case for every policy."""

from __future__ import annotations

import copy

import pytest

from app.domain.enums import DECISION_PRECEDENCE, SEVERITY_RANK, PolicyMode
from app.engines.policy import EvaluationInput, evaluate, validate_conditions, validate_restrictions
from app.engines.policy.builtin import BUILTIN_POLICIES, builtin_policy_specs

REQUIRED_KEYS = {"builtin_key", "name", "description", "outcome", "mode", "priority", "severity", "conditions",
                 "restrictions", "tags"}
SPECS = {s.id: s for s in builtin_policy_specs()}

BASE = {
    "agent": {"id": "agt_1", "name": "dev-assistant", "environment": "development", "labels": [],
              "framework": "claude_code"},
    "tool": {"name": "Read", "category": "file_read", "provider": "claude_code", "server": None, "risk_level": "low"},
    "arguments": {"file_path": "/srv/app/README.md"},
    "resources": [{"kind": "file", "id": "/srv/app/README.md", "sensitive": False, "reason": None}],
    "sensitive_resources": [],
    "destination": {},
    "secrets_in_arguments": [],
    "session_secret_matches": [],
    "session": {"score": 10, "level": "low", "untrusted_exposure": False, "sensitive_access": False,
                "outbound_channel": False, "trifecta": False},
    "context": {"lowest_trust": "TRUSTED", "untrusted_item_count": 0, "suspicious_source_ids": [],
                "injection_detected": False, "max_detection_severity": None},
    "detection": {"rule_ids": [], "max_severity": None, "categories": []},
    "integration": {"kind": "claude_code", "supports_enforcement": True},
}


def make(**overrides) -> EvaluationInput:
    """BASE (a benign README read) with top-level fields shallow-merged/replaced."""
    data = copy.deepcopy(BASE)
    for key, value in overrides.items():
        data[key] = {**data[key], **value} if isinstance(value, dict) and isinstance(data[key], dict) else value
    return EvaluationInput.from_dict(data)


HTTP = {"name": "WebFetch", "category": "http", "provider": "claude_code", "risk_level": "medium"}
SHELL = {"name": "Bash", "category": "shell", "risk_level": "high"}
SECRET = [{"type": "aws_access_key", "fingerprint": "0f1e2d3c4b5a6978"}]
DEST_UNKNOWN = {"kind": "domain", "identifier": "collector.example.net", "classification": "UNKNOWN", "checks": []}
DEST_TRUSTED = {"kind": "domain", "identifier": "api.github.com", "classification": "TRUSTED", "checks": []}
SENSITIVE_READ = {
    "arguments": {"file_path": "/srv/app/.env"},
    "resources": [{"kind": "file", "id": "/srv/app/.env", "sensitive": True, "reason": "environment file"}],
    "sensitive_resources": ["/srv/app/.env"],
}
TRIFECTA = {"untrusted_exposure": True, "sensitive_access": True, "outbound_channel": True, "trifecta": True,
            "score": 85, "level": "critical"}

CASES = [
    ("builtin.block-credential-exfiltration",
     [make(tool=HTTP, secrets_in_arguments=SECRET, destination=DEST_UNKNOWN),
      make(tool={"name": "send_email", "category": "email"}, session_secret_matches=SECRET,
           destination={"kind": "email", "identifier": "drop@mail.example", "classification": "EXTERNAL"}),
      make(tool=HTTP, secrets_in_arguments=SECRET)],  # no destination extracted: still outbound, fail closed
     [make(tool=HTTP, secrets_in_arguments=SECRET, destination=DEST_TRUSTED),
      make(tool={"name": "Write", "category": "file_write"}, secrets_in_arguments=SECRET),
      make(tool=HTTP, destination=DEST_UNKNOWN)]),
    ("builtin.block-blocked-destinations",
     [make(tool=HTTP, destination={**DEST_UNKNOWN, "classification": "BLOCKED"})],
     [make(tool=HTTP, destination={**DEST_UNKNOWN, "classification": "EXTERNAL"}), make()]),
    ("builtin.deny-sensitive-access-after-injection",
     [make(context={"injection_detected": True, "lowest_trust": "SUSPICIOUS"}, **SENSITIVE_READ),
      make(context={"injection_detected": True}, sensitive_resources=["/home/dev/.ssh/id_rsa"])],
     [make(context={"injection_detected": True}), make(**SENSITIVE_READ)]),
    ("builtin.deny-destructive-shell",
     [make(tool=SHELL, arguments={"command": "rm -rf /"}, detection={"rule_ids": ["TOOL-DESTRUCTIVE-RM-RF"]})],
     [make(tool=SHELL, arguments={"command": "env"}, detection={"rule_ids": ["TOOL-ENV-DUMP"]})]),
    ("builtin.deny-agent-config-tampering",
     [make(tool={"name": "Edit", "category": "file_write"}, detection={"categories": ["permission_escalation"]})],
     [make(tool={"name": "Edit", "category": "file_write"}, detection={"categories": ["credential_access"]})]),
    ("builtin.approve-outbound-under-trifecta",
     [make(tool=HTTP, destination=DEST_TRUSTED, session=TRIFECTA),
      make(tool={"name": "slack_post", "category": "messaging"}, session=TRIFECTA)],
     [make(tool=HTTP, destination=DEST_TRUSTED), make(session=TRIFECTA)]),
    ("builtin.approve-suspicious-destinations",
     [make(tool=HTTP, destination={**DEST_UNKNOWN, "classification": "SUSPICIOUS"})],
     [make(tool=HTTP, destination=DEST_UNKNOWN)]),
    ("builtin.approve-production-infrastructure",
     [make(agent={"environment": "production"}, tool={"name": "terraform_apply", "category": "infrastructure"})],
     [make(agent={"environment": "staging"}, tool={"name": "terraform_apply", "category": "infrastructure"}),
      make(agent={"environment": "production"}, tool=SHELL)]),
    ("builtin.monitor-http-unknown-destinations",
     [make(tool=HTTP, destination=DEST_UNKNOWN)],
     [make(tool=HTTP, destination={**DEST_UNKNOWN, "classification": "EXTERNAL"}),
      make(tool=SHELL, destination=DEST_UNKNOWN)]),
    ("builtin.audit-sensitive-file-reads",
     [make(**SENSITIVE_READ)],
     [make(), make(tool={"name": "Write", "category": "file_write"}, **SENSITIVE_READ)]),
    ("builtin.audit-shell-commands",
     [make(tool=SHELL, arguments={"command": "ls"})],
     [make()]),
]


def test_every_builtin_policy_has_cases():
    assert {key for key, _, _ in CASES} == {p["builtin_key"] for p in BUILTIN_POLICIES}


@pytest.mark.parametrize(("key", "positives", "negatives"), CASES, ids=[c[0] for c in CASES])
def test_builtin_policy_matches_positive_and_not_negative(key, positives, negatives):
    spec = SPECS[key]
    for inp in positives:
        result = evaluate(inp, [spec])
        assert not result.evaluation_errors
        if spec.mode == PolicyMode.MONITOR:
            assert result.decision == "ALLOW"
            assert [m.policy_id for m in result.monitor_matches] == [key]
        else:
            assert result.decision == spec.outcome, result.explanation
            assert result.deciding_policy_id == key
            assert spec.name in result.explanation
    for inp in negatives:
        result = evaluate(inp, [spec])
        assert result.matched == [] and result.monitor_matches == [], result.explanation
        assert result.decision == "ALLOW"


# ---- pack shape ------------------------------------------------------------------------------

def test_pack_shape():
    keys = [p["builtin_key"] for p in BUILTIN_POLICIES]
    assert len(keys) == len(set(keys)) and all(k.startswith("builtin.") for k in keys)
    assert len({p["name"] for p in BUILTIN_POLICIES}) == len(BUILTIN_POLICIES)
    for p in BUILTIN_POLICIES:
        assert set(p) == REQUIRED_KEYS, p["builtin_key"]
        assert p["outcome"] in DECISION_PRECEDENCE
        assert p["mode"] in {m.value for m in PolicyMode}
        assert p["severity"] in SEVERITY_RANK
        assert isinstance(p["priority"], int) and p["tags"]
        assert p["description"].startswith("Threat:")


@pytest.mark.parametrize("policy", BUILTIN_POLICIES, ids=[p["builtin_key"] for p in BUILTIN_POLICIES])
def test_builtin_conditions_and_restrictions_validate(policy):
    assert validate_conditions(policy["conditions"]) == []
    assert validate_restrictions(policy["restrictions"], outcome=policy["outcome"]) == []


def test_pack_contains_a_monitor_mode_dry_run():
    monitors = [p for p in BUILTIN_POLICIES if p["mode"] == "monitor"]
    assert [p["builtin_key"] for p in monitors] == ["builtin.monitor-http-unknown-destinations"]


def test_policies_do_not_share_condition_objects():
    def nodes(obj):
        if isinstance(obj, dict | list):
            yield id(obj)
            for child in obj.values() if isinstance(obj, dict) else obj:
                yield from nodes(child)

    seen: dict[int, str] = {}
    for p in BUILTIN_POLICIES:
        for node_id in nodes(p["conditions"]):
            assert node_id not in seen or seen[node_id] == p["builtin_key"]
            seen[node_id] = p["builtin_key"]


# ---- whole-pack scenarios --------------------------------------------------------------------

def run_pack(inp: EvaluationInput):
    return evaluate(inp, builtin_policy_specs())


def test_benign_read_is_allowed_with_nothing_matched():
    result = run_pack(make())
    assert result.decision == "ALLOW"
    assert result.explanation == "No policy matched; default ALLOW applied"


def test_credential_exfiltration_under_trifecta_is_denied_by_the_critical_policy():
    result = run_pack(make(tool=HTTP, secrets_in_arguments=SECRET, destination=DEST_UNKNOWN, session=TRIFECTA))
    assert result.decision == "DENY"
    assert result.deciding_policy_id == "builtin.block-credential-exfiltration"
    assert [m.outcome for m in result.matched] == ["DENY", "REQUIRE_APPROVAL"]
    assert [m.policy_id for m in result.monitor_matches] == ["builtin.monitor-http-unknown-destinations"]
    assert "observed: [aws_access_key]" in result.explanation
    assert "0f1e2d3c4b5a6978" not in result.explanation  # fingerprints are not echoed


def test_destructive_shell_is_denied_and_also_audited():
    result = run_pack(make(tool=SHELL, arguments={"command": "rm -rf /"},
                           detection={"rule_ids": ["TOOL-DESTRUCTIVE-RM-RF"], "max_severity": "critical"}))
    assert result.decision == "DENY"
    assert result.deciding_policy_id == "builtin.deny-destructive-shell"
    assert [m.policy_id for m in result.matched][-1] == "builtin.audit-shell-commands"


def test_unknown_http_destination_is_allowed_with_a_dry_run_record():
    result = run_pack(make(tool=HTTP, destination=DEST_UNKNOWN))
    assert result.decision == "ALLOW"
    assert result.monitor_matches and result.monitor_matches[0].outcome == "REQUIRE_APPROVAL"
    assert "would have applied" in result.explanation


def test_injection_then_env_read_is_denied_over_audit():
    result = run_pack(make(context={"injection_detected": True}, **SENSITIVE_READ))
    assert result.decision == "DENY"
    assert {m.policy_id for m in result.matched} == {
        "builtin.deny-sensitive-access-after-injection", "builtin.audit-sensitive-file-reads",
    }
