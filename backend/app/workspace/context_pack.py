"""Context packs: a token-budgeted, verified bundle of repository context for a coding agent.

``build_context_pack`` selects project documents (per profile), the task's related files, tests
that look related by filename, recent Git history and DB-derived record summaries, then fits them
into the profile's token budget in priority order. Every item records whether it was *verified*
(confirmed to exist in the repository, or a persisted ContextOS record), whether it was *included*
in the prompt, and why. Sensitive files are listed as excluded and never read. Excerpts are
redacted. See :mod:`app.workspace.repo_files` for the filesystem safety rules.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from app.workspace import repo_files as rf
from app.workspace.text import clean, estimate_tokens, inline, truncate_lines

ITEM_KINDS = ("doc", "source_file", "test_file", "record", "policy", "note", "git_history")
ITEM_OVERHEAD_TOKENS = 16  # heading/ref line rendered around each excerpt
MIN_USEFUL_TOKENS = 48
OVER_BUDGET = "over budget"
_RECORD_EXCERPT_CHARS = 4000

DOC_TITLES = {
    "CLAUDE.md": "Project instructions for Claude Code",
    "AGENTS.md": "Project instructions for coding agents",
    "CONTEXT.md": "Current project state",
    "docs/ARCHITECTURE.md": "Architecture",
    "docs/SECURITY_MODEL.md": "Security model",
    "docs/THREAT_MODEL.md": "Threat model",
    "docs/DATA_MODEL.md": "Data model",
    "docs/API_SPECIFICATION.md": "API specification",
}
_INSTRUCTIONS = ("CLAUDE.md", "AGENTS.md", "CONTEXT.md")


@dataclass(frozen=True)
class PackProfile:
    key: str
    label: str
    description: str
    token_budget: int
    priority_docs: tuple[str, ...]
    supporting_docs: tuple[str, ...]
    max_item_tokens: int
    max_related_files: int
    tests_per_file: int
    include_git: bool


PROFILES: dict[str, PackProfile] = {
    "minimal": PackProfile(
        "minimal", "Minimal", "Project instructions, related records and the most relevant files only.",
        2_000, ("CLAUDE.md", "AGENTS.md"), (), 600, 5, 0, False,
    ),
    "standard": PackProfile(
        "standard", "Standard", "Instructions, architecture, related files and their tests.",
        8_000, _INSTRUCTIONS, ("docs/ARCHITECTURE.md",), 2_500, 15, 2, True,
    ),
    "deep": PackProfile(
        "deep", "Deep", "Adds the data model and API specification for cross-cutting changes.",
        20_000, _INSTRUCTIONS, ("docs/ARCHITECTURE.md", "docs/DATA_MODEL.md", "docs/API_SPECIFICATION.md"),
        5_000, 30, 3, True,
    ),
    "security_critical": PackProfile(
        "security_critical", "Security critical", "Security and threat models are prioritised alongside instructions.",
        24_000, _INSTRUCTIONS + ("docs/SECURITY_MODEL.md", "docs/THREAT_MODEL.md"),
        ("docs/ARCHITECTURE.md", "docs/DATA_MODEL.md"), 5_000, 30, 3, True,
    ),
    "full": PackProfile(
        "full", "Full", "Every standard project document plus related files, tests and history.",
        60_000, _INSTRUCTIONS,
        ("docs/ARCHITECTURE.md", "docs/SECURITY_MODEL.md", "docs/THREAT_MODEL.md", "docs/DATA_MODEL.md",
         "docs/API_SPECIFICATION.md"),
        12_000, 50, 3, True,
    ),
}

# Priority tiers: lower is included first when the budget is tight.
_P_RECORD, _P_INSTRUCTION_DOC, _P_RELATED, _P_TEST, _P_SUPPORT_DOC, _P_GIT = range(6)


def get_profile(key: str) -> PackProfile:
    if key not in PROFILES:
        raise ValueError(f"Unknown context pack profile {key!r}; expected one of: {', '.join(PROFILES)}")
    return PROFILES[key]


def describe_profiles() -> list[dict[str, Any]]:
    return [
        {"key": p.key, "label": p.label, "description": p.description, "token_budget": p.token_budget,
         "documents": list(p.priority_docs + p.supporting_docs), "includes_tests": p.tests_per_file > 0,
         "includes_git_history": p.include_git}
        for p in PROFILES.values()
    ]


def _item(kind: str, ref: str, *, title: str, category: str, reason: str, verified: bool, status: str,
          origin: str, priority: int, content: str | None = None) -> dict[str, Any]:
    return {
        "key": f"{kind}:{ref}",
        "kind": kind,
        "ref": ref,
        "title": title,
        "category": category,
        "reason": reason,
        "verified": verified,
        "included": False,
        "token_estimate": 0,
        "excerpt": "",
        # Extensions beyond the persisted schema's required keys:
        "status": status,  # included|over_budget|excluded_sensitive|rejected|missing|unverified|skipped|reference|note
        "origin": origin,  # profile|related_file|discovered|record|git|system
        "_priority": priority,
        "_content": content,
    }


def _file_item(root: Path | None, raw: object, *, kind_hint: str | None, origin: str, priority: int,
               reason: str, title: str | None = None) -> dict[str, Any]:
    res = rf.resolve_repo_path(root, raw)
    kind = kind_hint or _kind_for(res.rel)
    name = title or DOC_TITLES.get(res.rel) or PurePosixPath(res.rel).name or res.rel
    common = {"title": name, "origin": origin, "priority": priority}
    if res.status == "sensitive":
        return _item(kind, res.rel, category="assumption", verified=False, status="excluded_sensitive",
                     reason=f"Excluded: {res.reason}. Sensitive files are never read.", **common)
    if res.status == "rejected":
        return _item(kind, res.rel, category="assumption", verified=False, status="rejected",
                     reason=f"Rejected: {res.reason}", **common)
    if res.status in ("missing", "unverified"):
        return _item(kind, res.rel, category="assumption", verified=False, status=res.status, reason=res.reason, **common)
    if res.status == "directory":
        return _item(kind, res.rel, category="fact", verified=True, status="reference",
                     reason=f"{reason} Directory; list the specific files you need.", **common)
    if res.status == "not_regular":
        return _item(kind, res.rel, category="fact", verified=True, status="skipped", reason=res.reason, **common)
    if res.abs_path is None:  # resolve_repo_path always sets it for "ok"; never read an unresolved path
        return _item(kind, res.rel, category="assumption", verified=False, status="rejected",
                     reason="Rejected: path could not be resolved.", **common)
    status, text = rf.read_text_file(res.abs_path)
    if status != "ok" or text is None:
        why = {
            "too_large": f"File is larger than {rf.MAX_FILE_BYTES // (1024 * 1024)} MB; not read.",
            "binary": "Binary or non-UTF-8 file; not read.",
            "not_regular": "Not a regular file; not read.",
        }.get(status, "File could not be read.")
        return _item(kind, res.rel, category="fact", verified=True, status="skipped", reason=why, **common)
    content = clean(text, limit=len(text) + 1) if text.strip() else ""
    if not content:
        return _item(kind, res.rel, category="fact", verified=True, status="reference",
                     reason=f"{reason} File is empty.", **common)
    return _item(kind, res.rel, category="fact", verified=True, status="candidate", reason=reason,
                 content=content, **common)


def _kind_for(rel: str) -> str:
    if rf.is_test_file(rel):
        return "test_file"
    if PurePosixPath(rel).suffix.lower() in (".md", ".mdx", ".rst", ".txt", ".adoc"):
        return "doc"
    return "source_file"


def _record_item(record: Mapping[str, Any]) -> dict[str, Any]:
    ref = record.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("Each context-pack record needs a non-empty 'ref' (for example 'finding:fnd_…').")
    kind = record.get("kind") or "record"
    if kind not in ("record", "policy", "note"):
        raise ValueError(f"Record kind must be record, policy or note, not {kind!r}")
    default_category = {"record": "evidence", "policy": "fact", "note": "assumption"}[kind]
    category = record.get("category") or default_category
    if category not in ("fact", "evidence", "assumption", "hypothesis", "recommendation"):
        raise ValueError(f"Invalid record category {category!r}")
    body = record.get("summary") or record.get("excerpt") or ""
    content = clean(body, limit=_RECORD_EXCERPT_CHARS)
    return _item(kind, inline(ref, 120), title=inline(record.get("title") or ref, 200), category=category,
                 reason=inline(record.get("reason") or "Linked ContextOS record.", 300),
                 verified=kind != "note", status="candidate" if content else "reference", origin="record",
                 priority=_P_RECORD, content=content or None)


def _note(ref: str, title: str, reason: str) -> dict[str, Any]:
    return _item("note", ref, title=title, category="assumption", reason=reason, verified=False, status="note",
                 origin="system", priority=_P_GIT)


def _apply_budget(items: list[dict[str, Any]], profile: PackProfile) -> int:
    remaining = profile.token_budget
    for item in sorted(items, key=lambda i: i["_priority"]):  # stable: keeps order within a tier
        content = item["_content"]
        if not content:
            continue
        full_cost = estimate_tokens(content) + ITEM_OVERHEAD_TOKENS
        cap = min(profile.max_item_tokens, remaining - ITEM_OVERHEAD_TOKENS)
        if cap < MIN_USEFUL_TOKENS:
            item.update(status="over_budget", included=False, token_estimate=full_cost, reason=OVER_BUDGET)
            continue
        excerpt, truncated = truncate_lines(content, cap)
        cost = estimate_tokens(excerpt) + ITEM_OVERHEAD_TOKENS
        while cost > remaining and cap > MIN_USEFUL_TOKENS:
            cap = max(MIN_USEFUL_TOKENS, cap - 32)
            excerpt, truncated = truncate_lines(content, cap)
            cost = estimate_tokens(excerpt) + ITEM_OVERHEAD_TOKENS
        if cost > remaining:
            item.update(status="over_budget", included=False, token_estimate=full_cost, reason=OVER_BUDGET)
            continue
        remaining -= cost
        reason = item["reason"] + (" Excerpt truncated to fit the token budget." if truncated else "")
        item.update(status="included", included=True, token_estimate=cost, excerpt=excerpt, reason=reason.strip())
    return profile.token_budget - remaining


def build_context_pack(
    repo_root: str | None,
    *,
    related_files: Sequence[str] = (),
    profile: str = "standard",
    records: Sequence[Mapping[str, Any]] = (),
    include_git: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """Build a context pack. Returns ``(items, token_estimate)`` where the estimate covers included items."""
    spec = get_profile(profile)
    items: list[dict[str, Any]] = [_record_item(r) for r in records]
    root = _resolve_root(repo_root, items)

    seen: set[str] = set()

    def add(item: dict[str, Any]) -> None:
        if item["ref"] in seen and item["kind"] not in ("note",):
            return
        seen.add(item["ref"])
        items.append(item)

    if root is not None:
        for doc in spec.priority_docs + spec.supporting_docs:
            if not (root / doc).exists():
                continue  # profile documents are optional; absent ones are simply not part of this repo
            tier = _P_INSTRUCTION_DOC if doc in spec.priority_docs else _P_SUPPORT_DOC
            add(_file_item(root, doc, kind_hint="doc", origin="profile", priority=tier,
                           reason=f"Selected by the '{spec.key}' profile."))

    unique_related = list(dict.fromkeys(f for f in related_files if isinstance(f, str)))
    accepted = unique_related[: spec.max_related_files]
    related_items = [
        _file_item(root, raw, kind_hint=None, origin="related_file", priority=_P_RELATED,
                   reason="Listed as a related file on the task.")
        for raw in accepted
    ]
    for item in related_items:
        add(item)
    if len(unique_related) > len(accepted):
        add(_note("related_files_limit", "Some related files were not processed",
                  f"{len(unique_related) - len(accepted)} related file(s) beyond the '{spec.key}' profile limit of "
                  f"{spec.max_related_files} were not processed."))

    verified_sources = [i["ref"] for i in related_items
                        if i["verified"] and i["kind"] == "source_file" and i["status"] != "reference"]
    if root is not None and spec.tests_per_file > 0 and verified_sources:
        for source, tests in rf.discover_related_tests(root, verified_sources, spec.tests_per_file).items():
            for test in tests:
                if test in seen:
                    continue
                add(_file_item(root, test, kind_hint="test_file", origin="discovered", priority=_P_TEST,
                               reason=f"Test whose filename matches {source}; likely related (not proven coverage)."))

    if root is not None and include_git and spec.include_git:
        verified_files = [i["ref"] for i in related_items if i["verified"] and i["kind"] != "note"]
        ok, output = rf.git_recent_history(root, verified_files)
        if ok:
            add(_item("git_history", "recent", title="Recent commits touching the related files", category="evidence",
                      reason="Output of git log -n 10 for the verified related files.", verified=True,
                      status="candidate", origin="git", priority=_P_GIT, content=output))
        elif verified_files:
            add(_note("git_history", "Git history unavailable", output))

    total = _apply_budget(items, spec)
    return [_public(i) for i in items], total


def _resolve_root(repo_root: str | None, items: list[dict[str, Any]]) -> Path | None:
    if repo_root is None:
        items.append(_note("repository", "No repository connected",
                           "No repository root is configured, so documents and source files were not read "
                           "and related paths could not be verified."))
        return None
    try:
        root = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError):
        root = None
    if root is None or not root.is_dir():
        items.append(_note("repository", "Repository not accessible",
                           "The configured repository root does not exist or is not a directory; "
                           "related paths could not be verified."))
        return None
    return root


def _public(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if not k.startswith("_")}
