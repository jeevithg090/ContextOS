#!/usr/bin/env python3
"""Find repository paths and Python modules referenced in Markdown that do not exist.

    backend/.venv/bin/python .claude/skills/repo-audit/scripts/doc_paths.py            # default doc set
    backend/.venv/bin/python .claude/skills/repo-audit/scripts/doc_paths.py docs/ARCHITECTURE.md
    ... --strict   # exit 1 when anything is missing

Checks inline code spans (`backend/app/core/errors.py`, `app.services.scoping.scoped`) and relative
Markdown links. A path is resolved against the repository root, the document's folder, and the
package roots docs commonly abbreviate (`backend/`, `frontend/`, `sdk/`). Globs must match at least
one file. Dotted names starting with `app.` or `contextos.` must resolve to a module, optionally
followed by one attribute that appears in that module's source.

Skipped on purpose: spans with spaces (commands), placeholders (`<name>`, `...`), URLs, absolute or
home paths, API paths (`/api/v1/...`) and paths in the user's own project (HOST_PATHS).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
DEFAULT_DOCS = ["CLAUDE.md", "AGENTS.md", "CONTEXT.md", "README.md", "docs/**/*.md", ".claude/**/*.md",
                "sdk/README.md", "examples/**/*.md"]
BASES = ["", "backend", "frontend", "sdk"]
PY_ROOTS = {"app": REPO / "backend" / "app", "contextos": REPO / "sdk" / "contextos"}
HOST_PATHS = {  # files in the project ContextOS is installed into, or in the user's tools — not here
    ".claude/settings.json", ".claude/settings.local.json", ".claude/settings.json.contextos-backup",
    ".mcp.json", ".cursor/mcp.json", "claude_desktop_config.json", ".env",
    "hooks.json", "config.toml", "hooks.json.contextos-backup",  # Codex (~/.codex or <project>/.codex)
}
# runtime / generated, the user's Codex configuration, and paths in the Codex source repository
HOST_PREFIXES = (".contextos/", "backend/data/", "frontend/dist/", "node_modules/", ".codex/", "codex-rs/")
KNOWN_ROOTS = {"backend", "frontend", "sdk", "docs", "examples", "scripts", ".claude", "app", "src", "tests",
               "contextos", "alembic"}
SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
             "data"}
EXTENSIONS = (".md", ".py", ".ts", ".tsx", ".js", ".json", ".toml", ".ini", ".yaml", ".yml", ".css",
              ".html", ".sh", ".mako", ".txt", ".cfg")
_SPAN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_DOTTED = re.compile(r"^(app|contextos)(\.[A-Za-z_][A-Za-z0-9_]*)+$")


@dataclass(frozen=True)
class Missing:
    doc: str
    line: int
    ref: str
    reason: str


def _expand_braces(pattern: str) -> list[str]:
    m = re.search(r"\{([^{}]*,[^{}]*)\}", pattern)
    if not m:
        return [pattern]
    return [x for alt in m.group(1).split(",") for x in _expand_braces(pattern[:m.start()] + alt + pattern[m.end():])]


def looks_like_path(token: str) -> bool:
    """Heuristic: is this code span a repository path (rather than a command, URL, MCP method, CIDR …)?"""
    if any(c in token for c in " <>|$") or "..." in token or "://" in token:
        return False
    if token.startswith(("/", "~", "-", "@", "#", "http")) or re.match(r"^[\d./]+$", token):
        return False
    if not re.match(r"^[\w.*{},\-/\[\]]+$", token):
        return False
    if token.endswith(EXTENSIONS) or token.endswith("/"):
        return True
    if "/" not in token:  # `*Out`, `trust-*`, `Page[T]`, `CONTEXTOS_*` are names, not paths
        return False
    return any(c in token for c in "*{[") or token.split("/", 1)[0] in KNOWN_ROOTS  # backend/app/engines


@lru_cache(maxsize=1)
def repo_index() -> tuple[str, ...]:
    """Every file and directory in the repository (posix, relative), minus generated/vendor trees."""
    entries: list[str] = []
    stack = [REPO]
    while stack:
        folder = stack.pop()
        for child in folder.iterdir():
            if child.name in SKIP_DIRS:
                continue
            rel = child.relative_to(REPO).as_posix()
            if child.is_dir():
                entries.append(rel + "/")
                stack.append(child)
            else:
                entries.append(rel)
    return tuple(entries)


def _exists(candidate: str, doc_dir: Path) -> bool:
    """Exact path from the repo root, a package root or the document's folder; else any path ending
    with ``candidate`` (docs abbreviate, e.g. ``integrations/claude_code/enforce.py``)."""
    for pattern in _expand_braces(candidate):
        is_dir = pattern.endswith("/")
        bare = pattern.rstrip("/")
        if any(ch in bare for ch in "*?["):
            if any(fnmatch(e.rstrip("/"), bare) or fnmatch(e.rstrip("/"), "*/" + bare) for e in repo_index()):
                return True
            continue
        if any((root / bare).exists() for root in [REPO / b for b in BASES] + [doc_dir]):
            return True
        suffix = bare + ("/" if is_dir else "")
        if any(e == suffix or e.endswith("/" + suffix) or (not is_dir and e.rstrip("/").endswith("/" + bare))
               for e in repo_index()):
            return True
    return False


def _is_host_path(token: str) -> bool:
    return token in HOST_PATHS or token.startswith(HOST_PREFIXES)


def check_dotted(name: str) -> str | None:
    """None when ``name`` resolves to a module (plus at most one attribute present in its source)."""
    parts = name.split(".")
    root = PY_ROOTS[parts[0]]
    for i in range(len(parts), 0, -1):
        base = root.joinpath(*parts[1:i])
        module = base / "__init__.py" if base.is_dir() else base.with_suffix(".py")
        if module.is_file():
            rest = parts[i:]
            if not rest:
                return None
            if len(rest) == 1 and re.search(rf"\b{re.escape(rest[0])}\b", module.read_text(encoding="utf-8")):
                return None
            return f"'{'.'.join(rest)}' not found in {module.relative_to(REPO)}"
    return "module not found"


def _dotted_alternatives(token: str) -> list[str]:
    """``app.services.scoping.scoped/get_scoped`` → both names; [] when not a dotted module reference."""
    head, *alts = token.split("/")
    if not _DOTTED.match(head) or not all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", a) for a in alts):
        return []
    parent = head.rsplit(".", 1)[0]
    return [head] + [f"{parent}.{a}" for a in alts]


def scan_document(doc: Path) -> list[Missing]:
    rel = str(doc.relative_to(REPO)) if doc.is_relative_to(REPO) else str(doc)
    problems: list[Missing] = []
    in_fence = False
    for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        refs = [m.group(1).strip() for m in _SPAN.finditer(line)]
        refs += [m.group(1) for m in _LINK.finditer(line) if not m.group(1).startswith(("http", "#", "mailto:"))]
        for ref in refs:
            token = re.sub(r"(#[\w\-]*|:\d+(-\d+)?)$", "", ref).rstrip(".,;:")
            dotted = _dotted_alternatives(token)
            if dotted:
                for name in dotted:
                    reason = check_dotted(name)
                    if reason:
                        problems.append(Missing(rel, lineno, ref, reason))
            elif looks_like_path(token) and not _is_host_path(token) and not _exists(token, doc.parent):
                problems.append(Missing(rel, lineno, ref, "path not found"))
    return problems


def default_documents() -> list[Path]:
    seen: dict[Path, None] = {}
    for pattern in DEFAULT_DOCS:
        for path in sorted(REPO.glob(pattern)):
            if path.is_file() and "node_modules" not in path.parts and ".venv" not in path.parts:
                seen[path] = None
    return list(seen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("docs", nargs="*", help="Markdown files (default: the repository doc set)")
    parser.add_argument("--strict", action="store_true", help="exit 1 when anything is missing")
    args = parser.parse_args(argv)
    docs = [Path(d).resolve() for d in args.docs] if args.docs else default_documents()
    problems = [p for doc in docs for p in scan_document(doc)]
    for p in problems:
        print(f"{p.doc}:{p.line}: `{p.ref}` — {p.reason}")
    print(f"{len(docs)} documents checked, {len(problems)} missing reference(s)")
    return 1 if args.strict and problems else 0


if __name__ == "__main__":
    sys.exit(main())
