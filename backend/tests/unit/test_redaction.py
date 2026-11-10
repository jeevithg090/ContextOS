"""Secret detection & text redaction: every detector, placeholders/negatives, offsets, fingerprints.

Test credentials are generated at runtime from a seeded RNG so no secret-shaped literal lives in
the repository (and push-protection scanners stay quiet).
"""

from __future__ import annotations

import random
import re
import string
import time

import pytest

from app.core.security import keyed_hmac
from app.engines.redaction import (
    HIGH_CONFIDENCE,
    MAX_SCAN_CHARS,
    detect_secrets,
    fingerprint_secret,
    redact_text,
)

_RNG = random.Random(20261110)
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX = "0123456789abcdef"
UPPER = string.ascii_uppercase + string.digits


def rnd(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def types_of(text: str) -> list[str]:
    return [m.secret_type for m in detect_secrets(text)]


def only_match(text: str):
    matches = detect_secrets(text)
    assert len(matches) == 1, (text, matches)
    return matches[0]


# --- positives: one case per detector ---------------------------------------------------------

POSITIVES = [
    ("aws_access_key", lambda: f"aws key id: AKIA{rnd(16, UPPER)}", None),
    ("aws_access_key", lambda: f"temporary ASIA{rnd(16, UPPER)} issued", None),
    ("aws_secret_key", lambda: f"aws_secret_access_key = {rnd(38, B64)}a1", None),
    ("github_token", lambda: f"GITHUB_TOKEN ghp_{rnd(36)}", None),
    ("github_token", lambda: f"oauth gho_{rnd(36)} done", " done"),
    ("github_token", lambda: f"github_pat_{rnd(22)}_{rnd(59)}", None),
    ("gitlab_token", lambda: f"glpat-{rnd(20, ALNUM + '_-')}", None),
    ("slack_token", lambda: f"xoxb-{rnd(12, string.digits)}-{rnd(12, string.digits)}-{rnd(24)}", None),
    ("slack_webhook", lambda: f"https://hooks.slack.com/services/T{rnd(8, UPPER)}/B{rnd(8, UPPER)}/{rnd(24)}", None),
    ("stripe_live_key", lambda: f"sk_live_{rnd(24)}", None),
    ("stripe_live_key", lambda: f"restricted rk_live_{rnd(24)}", None),
    ("stripe_test_key", lambda: f"sk_test_{rnd(24)}", None),
    ("openai_api_key", lambda: f"OPENAI sk-proj-{rnd(48, ALNUM + '_-')}", None),
    ("openai_api_key", lambda: f"sk-{rnd(20)}T3BlbkFJ{rnd(20)}", None),
    ("anthropic_api_key", lambda: f"sk-ant-api03-{rnd(90, ALNUM + '_-')}", None),
    ("google_api_key", lambda: f"AIza{rnd(35, ALNUM + '_-')}", None),
    ("twilio_api_key", lambda: f"SK{rnd(32, HEX)}", None),
    ("twilio_auth_token", lambda: f"TWILIO_ACCOUNT auth token is {rnd(32, HEX)}", None),
    ("sendgrid_api_key", lambda: f"SG.{rnd(22, B64URL)}.{rnd(43, B64URL)}", None),
    ("npm_token", lambda: f"npm_{rnd(36)}", None),
    ("npm_token", lambda: f"//registry.npmjs.org/:_authToken={rnd(36)}", None),
    ("huggingface_token", lambda: f"hf_{rnd(34)}", None),
    ("contextos_api_key", lambda: f"ctxk_{rnd(43, B64URL)}", None),
    ("database_credentials", lambda: f"postgres://app:{rnd(16)}@db.internal:5432/app", "@db.internal"),
    ("database_credentials", lambda: f"mongodb+srv://admin:{rnd(14)}@cluster0.mongodb.net/x", "@cluster0"),
    ("database_credentials", lambda: f"amqp://svc:{rnd(14)}@rabbit:5672//", "@rabbit"),
    ("url_credentials", lambda: f"https://deploy:{rnd(18)}@git.example.org/repo.git", "@git.example.org"),
    ("bearer_token", lambda: f"Authorization: Bearer {rnd(40)}", "Authorization: Bearer "),
    ("bearer_token", lambda: f'{{"authorization": "token {rnd(30)}"}}', '"authorization": "token '),
    ("basic_auth", lambda: "Authorization: Basic YWxpY2U6czNjcjN0LXBhc3M=", "Authorization: Basic "),
    ("basic_auth", lambda: f"curl -u admin:{rnd(12)} https://api.internal/v1", "curl -u admin:"),
    ("session_cookie", lambda: f"Cookie: theme=dark; sessionid={rnd(32)}", "theme=dark"),
    ("generic_password", lambda: 'db_password = "Tr0ub4dor&3x"', 'db_password = "'),
    ("generic_password", lambda: f"mysql --password {rnd(6)}9!", "mysql --password "),
    ("generic_api_key", lambda: f'{{"x-api-key": "{rnd(32)}"}}', '"x-api-key": "'),
    ("generic_token", lambda: f"auth_token: {rnd(28)}", "auth_token: "),
    ("generic_secret", lambda: f"CLIENT_SECRET={rnd(26)}", "CLIENT_SECRET="),
    ("password_hash", lambda: f"root:$6$saltsalt${rnd(86, ALNUM + './')}:19000:0:99999:7:::", "root:"),
]


@pytest.mark.parametrize(("expected", "make", "kept"), POSITIVES, ids=[f"{p[0]}-{i}" for i, p in enumerate(POSITIVES)])
def test_each_secret_type_is_detected_and_redacted(expected, make, kept):
    text = make()
    result = redact_text(text)
    assert expected in [m.secret_type for m in result.matches], (text, result.matches)
    assert f"[REDACTED:{expected}:" in result.text
    for m in result.matches:
        assert text[m.start : m.end] not in result.text  # the raw value is gone
    if kept:
        assert kept in result.text  # surrounding context (host, header name) survives


def test_jwt_detected_with_header_validation():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + rnd(43, B64URL)
    m = only_match(f"session={token};")
    assert m.secret_type == "jwt"
    m = only_match(f"jwt {token}")
    assert m.secret_type == "jwt" and m.confidence >= 0.9


def test_pem_private_key_block_including_json_escaped_newlines():
    body = "\n".join(rnd(64, B64) for _ in range(6))
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    m = only_match(f"key file:\n{pem}\ntrailing")
    assert m.secret_type == "private_key" and m.confidence >= 0.95
    escaped = '{"private_key": "' + pem.replace("\n", "\\n") + '\\n", "x": 1}'
    m2 = only_match(escaped)
    assert m2.secret_type == "private_key"
    assert m2.fingerprint == m.fingerprint  # same key, different encoding -> same fingerprint
    assert redact_text(escaped).text.endswith('\\n", "x": 1}')


def test_openssh_and_truncated_private_keys():
    body = "\n".join(rnd(70, B64) for _ in range(4))
    openssh = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
    assert types_of(openssh) == ["private_key"]
    truncated = f"-----BEGIN PRIVATE KEY-----\n{body}"  # e.g. a tool output cut short
    assert types_of(truncated) == ["private_key"]


def test_azure_connection_string_redacts_only_the_account_key():
    key = rnd(86, B64) + "=="
    text = f"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={key};EndpointSuffix=core.windows.net"
    result = redact_text(text)
    assert [m.secret_type for m in result.matches] == ["azure_storage_key"]
    assert "AccountName=acct;AccountKey=[REDACTED:azure_storage_key:" in result.text
    assert key not in result.text


def test_env_lines_including_json_escaped_file_content():
    text = f'DB_PASSWORD=supersecretvalue\nexport STRIPE_KEY={rnd(30)}\nDEBUG=true\nPORT=8080'
    result = redact_text(text)
    assert [m.secret_type for m in result.matches] == ["generic_password", "generic_api_key"]
    assert "DEBUG=true\nPORT=8080" in result.text
    escaped = '{"content": "FOO=1\\nGITHUB_SECRET=' + rnd(24) + '\\nBAR=2"}'
    assert types_of(escaped) == ["generic_secret"]


# --- placeholders and negatives -----------------------------------------------------------------

PLACEHOLDERS = [
    'api_key = "your-api-key"',
    "OPENAI_API_KEY=sk-your-key-here",
    "token: <token>",
    'secret = "${SECRET}"',
    "GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}",
    "password: changeme",
    "password: ********",
    "api_key: xxxxxxxxxxxxxxxxxxxxxxxx",
    "ghp_" + "x" * 36,
    "AKIAIOSFODNN7EXAMPLE",  # AWS documentation key
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Authorization: Bearer $TOKEN",
    "Authorization: Bearer <access-token>",
    "Authorization: Bearer YOUR_ACCESS_TOKEN",
    "postgres://user:password@localhost:5432/db",
    "TOKEN=$API_TOKEN",
    "password: required",
    "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
]


@pytest.mark.parametrize("text", PLACEHOLDERS)
def test_documentation_placeholders_are_not_reported(text):
    assert detect_secrets(text) == []


NEGATIVES = [
    "commit 3f786850e387550fdab836ed7e6dc881de23001b (HEAD -> main)",
    "request_id=550e8400-e29b-41d4-a716-446655440000",
    '"integrity": "sha512-' + rnd(86, B64) + '=="',
    "sha256:" + rnd(64, HEX),
    "def get_password(self):\n    return self.password",
    "password: str = Field(..., min_length=8)",
    'token = os.environ["TOKEN"]',
    "api_key = settings.OPENAI_API_KEY",
    'secret = get_secret("db")',
    '{"password": "Password", "token": "Token", "token_type": "bearer"}',
    "max_tokens=1024 tokenizer=cl100k_base",
    "if password == confirm_password: pass",
    "risk-assessment task-runner sk-learn",
    "kubectl create secret generic my-app-secret --from-file=./cert",
    "The session_id is ses_01HZY3K7Q8 and the api_key_id is key_01HZY3",
]


@pytest.mark.parametrize("text", NEGATIVES)
def test_common_non_secrets_are_not_flagged(text):
    assert detect_secrets(text) == [], detect_secrets(text)


def test_base64_images_are_ignored_even_if_they_contain_token_shapes():
    image = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg" + "+AKIA" + rnd(16, string.ascii_uppercase) + "/" + rnd(200, B64)
    assert detect_secrets(f'<img src="{image}">') == []


def test_looks_fake_tokens_get_low_confidence():
    m = only_match("ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789")
    assert m.secret_type == "github_token" and m.confidence < HIGH_CONFIDENCE


# --- overlaps, offsets and fingerprints ---------------------------------------------------------


def test_overlapping_matches_keep_the_most_specific_detector():
    proj = "sk-proj-" + rnd(40, B64URL)
    assert types_of(f"OPENAI_API_KEY={proj}") == ["openai_api_key"]
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + rnd(43, B64URL)
    assert types_of(f"Authorization: Bearer {jwt}") == ["jwt"]
    gh = "ghp_" + rnd(36)
    assert types_of(f"https://x-access-token:{gh}@github.com/org/repo.git") == ["github_token"]
    assert types_of(f"AWS_SECRET_ACCESS_KEY={rnd(38, B64)}9/") == ["aws_secret_key"]


def test_offsets_refer_to_original_text_and_reconstruct_redaction():
    secrets = ["ghp_" + rnd(36), "sk_live_" + rnd(24), "AKIA" + rnd(16, UPPER)]
    text = f"İstanbul notes: first {secrets[0]}, then\n\tstripe={secrets[1]} and finally ({secrets[2]})."
    result = redact_text(text)
    assert [text[m.start : m.end] for m in result.matches] == secrets
    starts = [m.start for m in result.matches]
    assert starts == sorted(starts)
    rebuilt, pos = [], 0
    for m in result.matches:
        rebuilt += [text[pos : m.start], f"[REDACTED:{m.secret_type}:{m.fingerprint[:8]}]"]
        pos = m.end
    assert "".join(rebuilt) + text[pos:] == result.text


def test_fingerprints_are_stable_keyed_and_never_expose_the_raw_value():
    raw = "ghp_" + rnd(36)
    fp = fingerprint_secret(raw)
    assert re.fullmatch(r"[0-9a-f]{16}", fp)
    assert fp == fingerprint_secret(raw) == keyed_hmac(raw, purpose="secret-fingerprint-v1")[:16]
    assert fp != fingerprint_secret(raw[:-1] + ("A" if raw[-1] != "A" else "B"))
    first, second = detect_secrets(f"a {raw}"), detect_secrets(f"different context: token={raw}")
    assert first[0].fingerprint == second[0].fingerprint == fp
    result = redact_text(f"push with {raw}")
    assert raw not in result.text and raw not in repr(result.matches)
    assert f"[REDACTED:github_token:{fp[:8]}]" in result.text


def test_redaction_is_idempotent():
    text = f"token ghp_{rnd(36)} and password = 'S3cr3t!pw'"
    once = redact_text(text)
    twice = redact_text(once.text)
    assert twice.text == once.text and twice.matches == []


def test_empty_and_clean_inputs():
    assert redact_text("").text == "" and not redact_text("").contains_secrets
    clean = redact_text("nothing to see here")
    assert clean.text == "nothing to see here" and clean.matches == []
    assert detect_secrets("") == []


# --- limits and performance -------------------------------------------------------------------


def test_input_beyond_scan_cap_is_dropped_not_passed_through():
    tail_secret = "ghp_" + rnd(36)
    text = "a" * MAX_SCAN_CHARS + " " + tail_secret
    result = redact_text(text)
    assert tail_secret not in result.text
    assert result.text[:MAX_SCAN_CHARS] == text[:MAX_SCAN_CHARS]
    assert result.text[MAX_SCAN_CHARS:].startswith("\n[TRUNCATED:41 characters")


def test_pem_with_an_invalid_earlier_header_still_finds_the_real_key():
    body = "\n".join(rnd(64, B64) for _ in range(4))
    text = (
        '-----BEGIN RSA PRIVATE KEY----- "quoted" '
        f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    )
    result = redact_text(text)
    assert [m.secret_type for m in result.matches] == ["private_key"]
    assert body not in result.text and result.text.startswith('-----BEGIN RSA PRIVATE KEY----- "quoted" ')


ADVERSARIAL = {
    "pem_headers": "-----BEGIN RSA PRIVATE KEY-----" * 13000 + "-----END PRIVATE KEY-----",
    "jwt_prefix_run": "eyJ" * 130000,
    "slack_prefixes": "xoxb-" * 80000,
    "auth_headers": "authorization:" * 28000,
    "cookie_headers": "cookie:" * 57000,
    "aws_anchors": "aws" * 130000,
    "hint_words": "pass" * 100000,
    "assignments": "password='aB3$xY9!q'\n" * 19000,
    "long_spaces": "password" + " " * 400000 + "= x",
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_adversarial_inputs_scan_in_linear_time(name):
    started = time.perf_counter()
    detect_secrets(ADVERSARIAL[name])
    assert time.perf_counter() - started < 10, name  # quadratic paths take minutes at this size


def test_large_and_adversarial_inputs_scan_in_bounded_time():
    noisy = ("password: x token= key: auth=" * 20000) + ("a" * 300000) + ("-----BEGIN PRIVATE KEY-----" * 2000)
    started = time.perf_counter()
    detect_secrets(noisy)
    assert time.perf_counter() - started < 20  # generous: CI machines are shared
