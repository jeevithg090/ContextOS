"""Section builders for repository context: codebase references and related documentation.

Rule: a path is presented as a *verified reference* only when a context-pack item says
``verified=True``. Paths the user supplied that could not be confirmed are listed under
"Unverified references (could not be confirmed in the repository)". Sensitive or out-of-repo
paths are listed as excluded. Nothing here invents a path or symbol.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from app.workspace.fix_input import BuildContext
from app.workspace.repo_files import resolve_repo_path
from app.workspace.section import Parts
from app.workspace.text import bullets, clean, code, fence, inline

UNVERIFIED_TITLE = "Unverified references (could not be confirmed in the repository)"
EXCLUDED_TITLE = "Excluded for safety (do not open, print or copy these)"
_FILE_KINDS = ("source_file", "test_file")
_EXCERPT_LIMIT = 250_000
_LANG = {
    ".py": "python", ".ts": "ts", ".tsx": "tsx", ".js": "js", ".jsx": "jsx", ".mjs": "js", ".cjs": "js",
    ".json": "json", ".md": "markdown", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".sql": "sql",
    ".sh": "bash", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".css": "css",
    ".html": "html", ".ini": "ini", ".cfg": "ini",
}


def _lang(path: str) -> str:
    return _LANG.get(PurePosixPath(path).suffix.lower(), "")


def _status_note(item: Mapping[str, Any]) -> str:
    if item.get("included"):
        return "excerpt below"
    status = item.get("status")
    if status == "over_budget":
        return "excerpt not included: over the token budget — open the file yourself"
    return inline(item.get("reason") or "not included", 200)


def _normalise(path: str) -> str:
    text = path.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _classify(ctx: BuildContext) -> dict[str, list[Mapping[str, Any]]]:
    groups: dict[str, list[Mapping[str, Any]]] = {"verified": [], "unverified": [], "excluded": [], "notes": [],
                                                  "git": [], "docs": [], "unverified_docs": []}
    for item in ctx.data.context_pack_items:
        kind, status = item.get("kind"), item.get("status")
        if kind == "note":
            groups["notes"].append(item)
        elif kind == "git_history":
            groups["git"].append(item)
        elif kind in _FILE_KINDS + ("doc",):
            if status in ("excluded_sensitive", "rejected"):
                groups["excluded"].append(item)
            elif item.get("verified") is True:
                groups["docs" if kind == "doc" else "verified"].append(item)
            elif item.get("origin") == "related_file" or kind != "doc":
                groups["unverified_docs" if kind == "doc" else "unverified"].append(item)
    known = {_normalise(str(i.get("ref") or "")) for i in ctx.data.context_pack_items}
    for raw in ctx.task.get("related_files") or []:
        if not isinstance(raw, str) or _normalise(raw) in known:
            continue
        known.add(_normalise(raw))
        res = resolve_repo_path(None, raw)  # lexical checks only: these were never checked against a repo
        entry = {"ref": res.rel, "title": PurePosixPath(res.rel).name, "kind": "source_file"}
        if res.status in ("sensitive", "rejected"):
            groups["excluded"].append({**entry, "reason": res.reason})
        else:
            groups["unverified"].append({**entry, "reason": "Listed on the task but not checked against the repository."})
    return groups


def codebase_context(ctx: BuildContext, p: Parts) -> None:
    g = _classify(ctx)
    if g["verified"]:
        rows = [f"{code(str(i['ref']))} — {inline(i.get('title'), 120)} ({_status_note(i)})" for i in g["verified"]]
        p.add("fact", "Verified references (confirmed to exist in the repository when the context pack was built):\n\n"
              + bullets(rows))
        for item in g["verified"]:
            p.source(f"context_pack:{item.get('key')}")
            if item.get("included") and item.get("excerpt"):
                body = clean(item["excerpt"], limit=_EXCERPT_LIMIT)
                p.add("fact", f"#### {code(str(item['ref']))}\n\n" + fence(body, _lang(str(item["ref"]))))
    if g["docs"]:
        p.add("fact", "Project documents are listed under Related documentation.")
    for item in g["git"]:
        if item.get("included") and item.get("excerpt"):
            p.add("evidence", "Recent commits touching the verified files (`git log`), oldest last:\n\n"
                  + fence(clean(item["excerpt"], limit=_EXCERPT_LIMIT), "text"))
            p.source(f"context_pack:{item.get('key')}")
        else:
            p.add("fact", f"Recent Git history was collected but not included ({_status_note(item)}).")
    if g["notes"]:
        p.add("fact", "Context pack notes:\n\n" + bullets(
            [f"{inline(n.get('title'), 120)}: {inline(n.get('reason'), 300)}" for n in g["notes"]]))
    if g["unverified"]:
        p.add("assumption", "These paths were supplied for this task but are not confirmed to exist. Do not rely on "
                            "them until you have checked:\n\n"
              + bullets([f"{code(str(i['ref']))} — {inline(i.get('reason'), 200)}" for i in g["unverified"]]),
              title=UNVERIFIED_TITLE)
    if g["excluded"]:
        p.add("instruction", bullets([f"{code(str(i['ref']))} — {inline(i.get('reason'), 200)}" for i in g["excluded"]]),
              title=EXCLUDED_TITLE)
    if not g["verified"]:
        p.add("fact", "No source or test files were verified for this task.")
    p.add("instruction", "Only the verified references above were confirmed to exist. Find any other code by searching "
                         "the repository; do not assume file, function or module names that you have not opened.")


def related_documentation(ctx: BuildContext, p: Parts) -> None:
    g = _classify(ctx)
    for item in g["docs"]:
        p.add("fact", f"{code(str(item['ref']))} — {inline(item.get('title'), 120)} ({_status_note(item)})")
        p.source(f"context_pack:{item.get('key')}")
    for item in g["docs"]:
        if item.get("included") and item.get("excerpt"):
            p.add("fact", f"#### {code(str(item['ref']))}\n\n" + fence(clean(item["excerpt"], limit=_EXCERPT_LIMIT),
                                                                          "markdown"))
    verified_refs = {str(i.get("ref")) for i in g["docs"]}
    unverified = [f"{code(str(i['ref']))} — {inline(i.get('reason'), 200)}" for i in g["unverified_docs"]]
    for doc in ctx.data.repo_docs:
        entry = _doc_entry(doc)
        if entry is None or entry["ref"] in verified_refs:
            continue
        label = code(entry["ref"]) + (f" — {entry['title']}" if entry["title"] else "")
        if entry["verified"]:
            p.add("fact", label)
            verified_refs.add(entry["ref"])
        else:
            unverified.append(label + " — supplied as related documentation; not confirmed")
    if unverified:
        p.add("assumption", bullets(unverified), title=UNVERIFIED_TITLE)
    instruction_file = ctx.preset.instruction_file
    if instruction_file and instruction_file in verified_refs:
        p.add("instruction", f"{ctx.preset.label} reads {code(instruction_file)}; its rules apply to this task.")
    if not p:
        p.add("fact", "No project documentation was attached to this prompt.")
        p.add("instruction", "Look for project instruction files in the repository root (for example a README) before "
                             "starting, and follow them if present.")


def _doc_entry(doc: Any) -> dict[str, Any] | None:
    if isinstance(doc, str) and doc.strip():
        return {"ref": inline(doc, 300), "title": "", "verified": False}
    if isinstance(doc, Mapping):
        target = doc.get("path") or doc.get("url") or doc.get("ref")
        if isinstance(target, str) and target.strip():
            is_url = target.startswith(("http://", "https://"))
            return {"ref": inline(target, 300), "title": inline(doc.get("title") or "", 120),
                    "verified": bool(doc.get("verified")) and not is_url}
    return None
