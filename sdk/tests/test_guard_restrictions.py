"""RESTRICT decisions: applied fully or treated as DENY (fail closed). Includes adversarial path cases."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from contextos import ToolDenied, guard
from contextos.redact import is_secret_key, mask_value, sensitive_path_reason
from contextos.restrictions import apply_restrictions, check_paths, extract_paths, scan_reports_secrets

from .sdk_fakes import FakeServer, decision_body

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTEXTOS_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)


def _restrict(server: FakeServer, **restrictions) -> None:
    server.route("POST", "/api/v1/decide", decision_body("RESTRICT", reason="Restricted by policy", restrictions=restrictions))


# -- redact_secrets ----------------------------------------------------------------------------

def test_redact_secrets_masks_arguments_before_the_call(tmp_path: Path) -> None:
    server = FakeServer()
    _restrict(server, redact_secrets=True)
    server.route("POST", "/api/v1/scan", {"hits": [], "secrets": []})
    received = {}

    @guard("post_message", category_hint="messaging", client=server.client(tmp_path))
    def post_message(channel: str, text: str, headers: dict) -> str:
        received.update(channel=channel, text=text, headers=headers)
        return "ok"

    post_message("#ops", f"deploy key is {GH} ok", {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456"})
    assert GH not in received["text"] and "[REDACTED:github_token]" in received["text"]
    assert received["headers"]["Authorization"] == "[REDACTED:credential_field]"
    # The server re-checked the MASKED arguments, never seeing the raw secret again.
    scanned = server.bodies("POST", "/api/v1/scan")[0]["content"]
    assert GH not in scanned and "[REDACTED:github_token]" in scanned
    meta = server.events_of("tool.completed")[0]["metadata"]
    assert meta["restrictions_applied"] == ["redacted 2 secret(s) in the arguments"]


@pytest.mark.parametrize(
    ("scan_response", "message"),
    [({"hits": [], "secrets": [{"type": "custom_token"}]}, "still detects a secret"),
     ({"unexpected": True}, "could not re-check"),
     ],
)
def test_redaction_that_cannot_be_verified_fails_closed(tmp_path: Path, scan_response: dict, message: str) -> None:
    server = FakeServer()
    _restrict(server, redact_secrets=True)
    server.route("POST", "/api/v1/scan", scan_response)
    ran = []
    with pytest.raises(ToolDenied, match=message):
        guard("t", client=server.client(tmp_path))(lambda text: ran.append(text))("internal token zq-secret-format")
    assert ran == []


def test_redaction_fails_closed_when_scan_is_unreachable(tmp_path: Path) -> None:
    server = FakeServer()
    _restrict(server, redact_secrets=True)
    server.route("POST", "/api/v1/scan", {}, status=503)
    with pytest.raises(ToolDenied, match="could not re-check"):
        guard("t", client=server.client(tmp_path, max_retries=0))(lambda text: text)("hello")


# -- path restrictions -------------------------------------------------------------------------

def test_paths_inside_the_allowlist_run(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    server = FakeServer()
    _restrict(server, allowed_path_globs=["workspace/*"], deny_path_globs=["*.env"])
    tool = guard("write_file", category_hint="file_write", client=server.client(tmp_path))(lambda path, content: f"wrote {path}")
    assert tool("workspace/notes.md", "hello") == "wrote workspace/notes.md"


@pytest.mark.parametrize(
    "path",
    [
        "workspace/../../etc/passwd",   # traversal out of the allowlist
        "/etc/passwd",                  # absolute path outside
        "workspace/../secrets.txt",     # sibling escape
    ],
)
def test_paths_escaping_the_allowlist_are_denied(tmp_path: Path, path: str) -> None:
    (tmp_path / "workspace").mkdir()
    server = FakeServer()
    _restrict(server, allowed_path_globs=["workspace/*"])
    with pytest.raises(ToolDenied, match="outside the allowed patterns"):
        guard("read_file", category_hint="file_read", client=server.client(tmp_path))(lambda path: "data")(path)


def test_symlink_out_of_the_allowlist_is_denied(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    (tmp_path / "outside.txt").write_text("secret")
    os.symlink(tmp_path / "outside.txt", tmp_path / "workspace" / "link.txt")
    assert check_paths(["workspace/link.txt"], ["workspace/*"], None, str(tmp_path)) is not None
    assert check_paths(["workspace/real.txt"], ["workspace/*"], None, str(tmp_path)) is None


@pytest.mark.parametrize("path", ["~/.ssh/id_rsa", "~/.SSH/ID_RSA", "file://~/.ssh/id_rsa", "./.ssh/../.ssh/id_rsa"])
def test_deny_globs_match_any_spelling(tmp_path: Path, path: str) -> None:
    reason = check_paths([path], None, ["*/.ssh/*", "~/.ssh/*"], str(tmp_path))
    assert reason is not None and "denied pattern" in reason


def test_path_restrictions_on_shell_tools_fail_closed(tmp_path: Path) -> None:
    server = FakeServer()
    _restrict(server, deny_path_globs=["*/.ssh/*"])
    with pytest.raises(ToolDenied, match="cannot be checked for a shell tool"):
        guard("bash", category_hint="shell", client=server.client(tmp_path))(lambda command: "ran")("cat notes.txt")


def test_declared_path_args_override_the_heuristics() -> None:
    args = {"source_file": "a.txt", "dest": "b.txt", "note": "/not/a/path/really"}
    assert extract_paths(args) == ["a.txt", "b.txt", "/not/a/path/really"]
    assert extract_paths(args, path_args=["source_file"]) == ["a.txt"]
    assert extract_paths({"files": ["x.py", "y.py"], "url": "https://e.com/a"}) == ["x.py", "y.py"]


def test_empty_allowlist_allows_nothing(tmp_path: Path) -> None:
    assert "allows no file paths" in check_paths(["a.txt"], [], None, str(tmp_path))


# -- size, unknown keys, empty restrictions ----------------------------------------------------

def test_max_argument_bytes_is_enforced(tmp_path: Path) -> None:
    server = FakeServer()
    _restrict(server, max_argument_bytes=50)
    tool = guard("upload", client=server.client(tmp_path))(lambda data: "ok")
    assert tool("small") == "ok"
    with pytest.raises(ToolDenied, match="the policy allows at most 50"):
        tool("x" * 100)


@pytest.mark.parametrize("restrictions", [{}, {"rewrite_urls": True}, {"max_argument_bytes": "big"}])
def test_restrictions_the_sdk_cannot_apply_are_treated_as_deny(restrictions: dict) -> None:
    outcome = apply_restrictions(restrictions, {"a": 1})
    assert not outcome.allowed and "fail closed" in (outcome.reason or "")


def test_redaction_without_a_verifier_fails_closed() -> None:
    outcome = apply_restrictions({"redact_secrets": True}, {"k": AWS})
    assert not outcome.allowed


# -- client-side redaction helpers -------------------------------------------------------------

def test_mask_value_masks_known_formats_and_credential_fields() -> None:
    value = {
        "aws": f"key={AWS}",
        "db": "postgres://app:s3cr3tPassw0rd@db.internal:5432/app",
        "nested": [{"password": "hunter2!"}, {"token_count": 12, "session_id": "ses_1"}],
        "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + "A" * 80 + "\n-----END RSA PRIVATE KEY-----",
        "placeholder": "api_key=${API_KEY}",
    }
    masked, kinds = mask_value(value)
    text = json.dumps(masked)
    assert AWS not in text and "s3cr3tPassw0rd" not in text and "hunter2!" not in text and "MIIEow" not in text
    assert masked["nested"][1] == {"token_count": 12, "session_id": "ses_1"}  # metadata fields untouched
    assert masked["placeholder"] == "api_key=${API_KEY}"
    assert {"aws_access_key", "url_credentials", "credential_field", "private_key"} <= set(kinds)


@pytest.mark.parametrize(("key", "secret"), [("DB_PASSWORD", True), ("apiKey", True), ("X-Api-Key", True),
                                              ("github_token", True), ("max_tokens", False), ("secret_type", False),
                                              ("api_key_id", False), ("path", False)])
def test_secret_key_classification(key: str, secret: bool) -> None:
    assert is_secret_key(key) is secret


@pytest.mark.parametrize(("path", "sensitive"), [(".env", True), ("config/.env.production", True), (".env.example", False),
                                                  ("~/.ssh/id_ed25519", True), ("deploy/server.pem", True),
                                                  ("home/.aws/credentials", True), ("src/app.py", False), ("README.md", False)])
def test_sensitive_paths(path: str, sensitive: bool) -> None:
    assert (sensitive_path_reason(path) is not None) is sensitive


def test_scan_response_interpretation() -> None:
    assert scan_reports_secrets({"secrets": [{"type": "aws"}]}) is True
    assert scan_reports_secrets({"hits": [{"category": "secret_exposure"}]}) is True
    assert scan_reports_secrets({"hits": [{"category": "prompt_injection"}], "secrets": []}) is False
    assert scan_reports_secrets({"secret_count": 0}) is False
    assert scan_reports_secrets({"score": 0.1}) is None
    assert scan_reports_secrets(None) is None
