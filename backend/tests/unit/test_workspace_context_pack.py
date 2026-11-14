"""Context-pack building: filesystem safety, sensitive files, budgets, redaction, tests and git history."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.workspace.context_pack import OVER_BUDGET, PROFILES, build_context_pack, describe_profiles
from app.workspace.repo_files import MAX_FILE_BYTES, resolve_repo_path
from app.workspace.text import estimate_tokens

GH_TOKEN = "ghp_R8xk2LmQ9vTz4WcY7pJn3HbFd6SaEu1Go0Ki"
AWS_KEY = "AKIAQ3EGRV7WZK5LJ4XN"


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "src" / "app.py").write_text("def handler():\n    return 'ok'\n")
    (root / "CLAUDE.md").write_text("# Rules\nAlways write tests.\n")
    (root / "docs" / "ARCHITECTURE.md").write_text("# Architecture\nModular monolith.\n")
    (tmp_path / "outside.txt").write_text("OUTSIDE-SECRET-CONTENT\n")
    return root


def _by_ref(items, ref):
    return next(i for i in items if i["ref"] == ref)


def _all_text(items) -> str:
    return json.dumps(items)


def test_related_file_inside_repo_is_verified_and_included(repo):
    items, total = build_context_pack(
        str(repo), related_files=["src/app.py", "./src/app.py"], profile="standard"
    )
    item = _by_ref(items, "src/app.py")
    assert item["verified"] is True and item["included"] is True and item["kind"] == "source_file"
    assert "def handler" in item["excerpt"]
    assert sum(1 for i in items if i["ref"] == "src/app.py") == 1  # de-duplicated
    assert total == sum(i["token_estimate"] for i in items if i["included"])
    assert {
        "key",
        "kind",
        "ref",
        "title",
        "category",
        "reason",
        "verified",
        "included",
        "token_estimate",
        "excerpt",
    } <= set(item)


def test_profile_documents_are_selected_and_missing_ones_skipped(repo):
    items, _ = build_context_pack(str(repo), profile="standard")
    refs = {i["ref"] for i in items if i["kind"] == "doc"}
    assert refs == {"CLAUDE.md", "docs/ARCHITECTURE.md"}  # AGENTS.md / CONTEXT.md do not exist here
    assert all(i["origin"] == "profile" for i in items if i["kind"] == "doc")


def test_traversal_outside_root_is_rejected_and_never_read(repo):
    items, _ = build_context_pack(str(repo), related_files=["../outside.txt", "src/../../outside.txt"])
    rejected = [i for i in items if i["status"] == "rejected"]
    assert len(rejected) == 2
    assert all(not i["verified"] and not i["included"] for i in rejected)
    assert "OUTSIDE-SECRET-CONTENT" not in _all_text(items)


def test_absolute_paths_outside_are_rejected_inside_are_normalised(repo, tmp_path):
    items, _ = build_context_pack(
        str(repo),
        related_files=[str(tmp_path / "outside.txt"), str(repo / "src/app.py"), "C:\\Windows\\win.ini"],
    )
    assert _by_ref(items, "src/app.py")["verified"] is True
    assert sum(1 for i in items if i["status"] == "rejected") == 2
    assert "OUTSIDE-SECRET-CONTENT" not in _all_text(items)


def test_symlink_escaping_root_is_rejected(repo, tmp_path):
    os.symlink(tmp_path / "outside.txt", repo / "src" / "link.txt")
    os.symlink(tmp_path, repo / "escape_dir")
    items, _ = build_context_pack(str(repo), related_files=["src/link.txt", "escape_dir/outside.txt"])
    for ref in ("src/link.txt", "escape_dir/outside.txt"):
        item = next(i for i in items if i["status"] == "rejected" and ref in i["ref"])
        assert "Symbolic link" in item["reason"]
    assert "OUTSIDE-SECRET-CONTENT" not in _all_text(items)


def test_sensitive_files_are_listed_as_excluded_and_never_read(repo):
    (repo / ".env").write_text(f"GITHUB_TOKEN={GH_TOKEN}\n")
    (repo / "config").mkdir()
    (repo / "config" / "secrets.yml").write_text("password: hunter2-very-secret\n")
    (repo / "id_rsa").write_text("PRIVATE KEY MATERIAL\n")
    os.symlink(repo / ".env", repo / "src" / "settings.txt")  # innocuous name pointing at a sensitive file
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[remote]\nurl = https://user:pw-in-url@example.com/x.git\n")
    items, _ = build_context_pack(
        str(repo),
        related_files=[".env", "config/secrets.yml", "id_rsa", "src/settings.txt", ".git/config"],
        include_git=False,
    )
    excluded = [i for i in items if i["status"] == "excluded_sensitive"]
    assert {i["ref"] for i in excluded} == {".env", "config/secrets.yml", "id_rsa", ".git/config"}
    assert all(not i["included"] and not i["verified"] and i["excerpt"] == "" for i in excluded)
    blob = _all_text(items)
    for leaked in (GH_TOKEN, "hunter2-very-secret", "PRIVATE KEY MATERIAL", "pw-in-url"):
        assert leaked not in blob
    assert all(i["reason"].startswith("Excluded:") for i in excluded)


def test_binary_large_and_directory_entries_are_not_read(repo):
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00binary")
    (repo / "big.log").write_text("x" * (MAX_FILE_BYTES + 10))
    (repo / "latin1.txt").write_bytes("caf\xe9".encode("latin-1"))
    items, _ = build_context_pack(str(repo), related_files=["logo.png", "big.log", "latin1.txt", "src"])
    assert "Binary" in _by_ref(items, "logo.png")["reason"]
    assert "larger than" in _by_ref(items, "big.log")["reason"]
    assert "Binary or non-UTF-8" in _by_ref(items, "latin1.txt")["reason"]
    for ref in ("logo.png", "big.log", "latin1.txt"):
        assert _by_ref(items, ref)["included"] is False and _by_ref(items, ref)["excerpt"] == ""
    assert _by_ref(items, "src")["status"] == "reference"


def test_missing_files_are_unverified(repo):
    items, _ = build_context_pack(str(repo), related_files=["src/does_not_exist.py"])
    item = _by_ref(items, "src/does_not_exist.py")
    assert item["verified"] is False and item["status"] == "missing" and item["category"] == "assumption"


def test_budget_truncates_then_marks_remaining_over_budget(repo):
    big = "\n".join(f"line {n} " + "y" * 60 for n in range(800))
    names = [f"src/{c}.py" for c in "abcde"]
    for name in names:
        (repo / name).write_text(big)
    items, total = build_context_pack(str(repo), related_files=names, profile="minimal")
    budget = PROFILES["minimal"].token_budget
    assert total <= budget
    a = _by_ref(items, "src/a.py")
    assert a["included"] is True and "truncated" in a["excerpt"] and "truncated" in a["reason"]
    assert a["token_estimate"] <= PROFILES["minimal"].max_item_tokens + 16
    over = [i for i in items if i["status"] == "over_budget"]
    assert over, "expected at least one item to exceed the minimal budget"
    assert all(i["reason"] == OVER_BUDGET and not i["included"] and i["excerpt"] == "" for i in over)
    assert all(i["token_estimate"] > 0 for i in over)


def test_budget_prioritises_records_and_instruction_docs(repo):
    (repo / "src" / "huge.py").write_text("z = 1\n" * 20_000)
    records = [{"ref": "finding:fnd_1", "title": "Injection", "summary": "Recorded injection attempt."}]
    items, total = build_context_pack(
        str(repo), related_files=["src/huge.py"], profile="minimal", records=records
    )
    order = [i["ref"] for i in items if i["included"]]
    assert order[0] == "finding:fnd_1" and "CLAUDE.md" in order
    assert total <= PROFILES["minimal"].token_budget


def test_excerpts_and_records_are_redacted(repo):
    (repo / "src" / "config.py").write_text(f"GITHUB = '{GH_TOKEN}'\naws_access_key_id = '{AWS_KEY}'\n")
    records = [
        {"ref": "event:evt_1", "title": "Tool call", "summary": f"curl -H 'Authorization: token {GH_TOKEN}'"}
    ]
    items, _ = build_context_pack(str(repo), related_files=["src/config.py"], records=records)
    blob = _all_text(items)
    assert GH_TOKEN not in blob and AWS_KEY not in blob
    assert "[REDACTED:" in _by_ref(items, "src/config.py")["excerpt"]
    record = _by_ref(items, "event:evt_1")
    assert (
        record["verified"] is True and record["category"] == "evidence" and "[REDACTED:" in record["excerpt"]
    )


def test_related_tests_are_discovered_heuristically(repo):
    (repo / "tests" / "unit").mkdir(parents=True)
    (repo / "tests" / "unit" / "test_app.py").write_text("def test_handler(): pass\n")
    (repo / "tests" / "unit" / "test_app_routes.py").write_text("def test_routes(): pass\n")
    (repo / "tests" / "unit" / "test_other.py").write_text("def test_other(): pass\n")
    (repo / "web" / "__tests__").mkdir(parents=True)
    (repo / "web" / "Button.tsx").write_text("export const Button = () => null;\n")
    (repo / "web" / "Button.test.tsx").write_text("test('renders', () => {});\n")
    (repo / "web" / "__tests__" / "Button.tsx").write_text("test('x', () => {});\n")
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "test_app.py").write_text("ignored\n")
    items, _ = build_context_pack(str(repo), related_files=["src/app.py", "web/Button.tsx"], profile="deep")
    tests = {i["ref"] for i in items if i["kind"] == "test_file"}
    assert {"tests/unit/test_app.py", "tests/unit/test_app_routes.py"} <= tests
    assert {"web/Button.test.tsx", "web/__tests__/Button.tsx"} <= tests
    assert "tests/unit/test_other.py" not in tests
    assert not any(t.startswith("node_modules") for t in tests)
    discovered = [i for i in items if i["origin"] == "discovered"]
    assert discovered and all(
        "not proven coverage" in i["reason"] or "truncated" in i["reason"] for i in discovered
    )


def test_minimal_profile_skips_tests_and_git(repo):
    (repo / "tests").mkdir()
    (repo / "tests" / "test_app.py").write_text("def test_x(): pass\n")
    items, _ = build_context_pack(str(repo), related_files=["src/app.py"], profile="minimal")
    assert not [i for i in items if i["kind"] in ("test_file", "git_history")]


def test_no_repository_marks_paths_unverified_without_reading(tmp_path):
    items, total = build_context_pack(
        None, related_files=["src/app.py", "../etc/hosts", "/abs/path.py", ".env"]
    )
    assert _by_ref(items, "src/app.py")["status"] == "unverified"
    assert sum(1 for i in items if i["status"] == "rejected") == 2
    assert _by_ref(items, ".env")["status"] == "excluded_sensitive"
    assert any(i["kind"] == "note" and "No repository" in i["title"] for i in items)
    assert total == 0


def test_inaccessible_repository_root_is_reported(tmp_path):
    items, _ = build_context_pack(str(tmp_path / "missing-root"), related_files=["a.py"])
    assert any(i["kind"] == "note" and "not accessible" in i["title"] for i in items)
    assert _by_ref(items, "a.py")["verified"] is False


def test_related_file_limit_and_profile_validation(repo):
    many = [f"src/f{n}.py" for n in range(PROFILES["minimal"].max_related_files + 3)]
    items, _ = build_context_pack(str(repo), related_files=many, profile="minimal")
    assert any(i["key"] == "note:related_files_limit" for i in items)
    with pytest.raises(ValueError, match="profile"):
        build_context_pack(str(repo), profile="galaxy_brain")
    with pytest.raises(ValueError, match="ref"):
        build_context_pack(str(repo), records=[{"title": "no ref"}])
    assert {p["key"] for p in describe_profiles()} == {
        "minimal",
        "standard",
        "deep",
        "security_critical",
        "full",
    }
    assert [
        PROFILES[k].token_budget for k in ("minimal", "standard", "deep", "security_critical", "full")
    ] == sorted(PROFILES[k].token_budget for k in PROFILES)


def test_security_critical_profile_prioritises_security_docs(repo):
    (repo / "docs" / "SECURITY_MODEL.md").write_text("# Security model\n")
    (repo / "docs" / "THREAT_MODEL.md").write_text("# Threat model\n")
    items, _ = build_context_pack(str(repo), profile="security_critical")
    refs = [i["ref"] for i in items if i["kind"] == "doc"]
    assert refs.index("docs/SECURITY_MODEL.md") < refs.index("docs/ARCHITECTURE.md")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_history_is_collected_and_redacted(repo):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }

    git_bin = shutil.which("git")
    assert git_bin is not None

    def git(*args: str) -> None:
        subprocess.run([git_bin, "-C", str(repo), *args], check=True, capture_output=True, env=env)  # noqa: S603

    git("init", "-q")
    git("add", "src/app.py")
    git("-c", "commit.gpgsign=false", "commit", "-q", "-m", f"Add handler with {GH_TOKEN}")
    items, _ = build_context_pack(str(repo), related_files=["src/app.py"], profile="standard")
    history = _by_ref(items, "recent")
    assert history["kind"] == "git_history" and history["included"] is True
    assert "Add handler" in history["excerpt"] and "src/app.py" in history["excerpt"]
    assert GH_TOKEN not in history["excerpt"]


def test_git_failure_becomes_a_note(repo):
    (repo / ".git").mkdir()  # an empty .git directory is not a valid repository
    items, _ = build_context_pack(str(repo), related_files=["src/app.py"], profile="standard")
    note = _by_ref(items, "git_history")
    assert note["kind"] == "note" and note["included"] is False and note["reason"]


def test_resolve_repo_path_edge_cases(repo):
    root = repo.resolve()
    assert resolve_repo_path(root, "").status == "rejected"
    assert resolve_repo_path(root, "src/\x00app.py").status == "rejected"
    assert resolve_repo_path(root, ".").status == "rejected"
    assert resolve_repo_path(root, "src\\app.py").rel == "src/app.py"
    assert resolve_repo_path(root, "file://src/app.py").status == "ok"


def test_estimate_tokens():
    assert estimate_tokens("") == 0 and estimate_tokens(None) == 0
    assert estimate_tokens("abcd") == 1 and estimate_tokens("abcde") == 2
