"""Safe, read-only access to a repository working copy for context packs.

Security properties (each covered by unit tests):

- Every path is resolved (symlinks followed) and must stay inside the resolved repository root;
  ``..`` traversal, absolute paths elsewhere and symlinks that escape the root are rejected.
- Sensitive files (``.env``, keys, cloud credentials, ... per ``redaction.is_sensitive_path``) and
  Git metadata are never opened — not even stat'ed when the requested name is already sensitive.
- Only regular UTF-8 text files up to :data:`MAX_FILE_BYTES` are read; files are opened with
  ``O_NOFOLLOW`` on the already-resolved path and re-checked with ``fstat``.
- ``git log`` runs without a shell, with a timeout, with pagers/fsmonitor/signature checks off.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.engines.redaction import is_sensitive_path, redact_text

MAX_FILE_BYTES = 1024 * 1024
MAX_PATH_CHARS = 1024
MAX_WALK_FILES = 50_000
GIT_TIMEOUT_S = 5.0
_GIT_OUTPUT_CAP = 16_000

SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".next", ".nuxt", "coverage", ".idea", "target", ".cache",
    ".turbo", ".gradle",
})
_GENERIC_STEMS = frozenset({"__init__", "__main__", "index", "conftest", "setup"})
_WINDOWS_ABS = re.compile(r"^[A-Za-z]:/")
_JS_TEST = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$")
_JS_EXT = re.compile(r"\.[cm]?[jt]sx?$")


@dataclass(frozen=True)
class ResolvedPath:
    """Outcome of resolving a user/record supplied path against the repository root.

    ``status``: ok | directory | missing | not_regular | rejected | sensitive | unverified.
    ``rel`` is the normalised repository-relative path when known, otherwise the cleaned input.
    """

    status: str
    rel: str
    reason: str
    abs_path: Path | None = None


def _clean_input(raw: object) -> tuple[str | None, str | None]:
    if not isinstance(raw, str) or not raw.strip():
        return None, "Empty path."
    if "\x00" in raw or len(raw) > MAX_PATH_CHARS:
        return None, "Path contains invalid characters or is too long."
    text = raw.strip().strip("\"'`").replace("\\", "/")
    if text.lower().startswith("file://"):
        text = text[7:]
    return text, None


def display_path(raw: object) -> str:
    """Redacted, length-capped rendering of an input path for item refs and messages."""
    text = raw if isinstance(raw, str) else repr(raw)
    text = text.replace("\x00", "").strip()
    return redact_text(text[:300]).text


def _sensitive(path: str) -> str | None:
    is_sens, reason = is_sensitive_path(path)
    if is_sens:
        return reason or "Sensitive file"
    parts = PurePosixPath(path.lower()).parts
    if ".git" in parts:
        return "Git metadata directory — remote URLs and config may embed credentials"
    return None


def resolve_repo_path(root: Path | None, raw: object) -> ResolvedPath:
    """Resolve ``raw`` inside ``root`` (already ``resolve()``-d). ``root=None`` → lexical checks only."""
    text, problem = _clean_input(raw)
    if text is None:
        return ResolvedPath("rejected", display_path(raw), problem or "Invalid path.")
    shown = display_path(text)
    if (reason := _sensitive(text)) is not None:
        return ResolvedPath("sensitive", shown, reason)
    is_abs = text.startswith("/") or bool(_WINDOWS_ABS.match(text))

    if root is None:
        if is_abs:
            return ResolvedPath("rejected", shown, "Absolute paths are not accepted; use a repository-relative path.")
        normal = os.path.normpath(text)
        if normal == ".." or normal.startswith("../"):
            return ResolvedPath("rejected", shown, "Path points outside the repository.")
        return ResolvedPath("unverified", PurePosixPath(normal).as_posix(),
                            "No repository is available to the server, so this path could not be verified.")

    if _WINDOWS_ABS.match(text):
        return ResolvedPath("rejected", shown, "Path is outside the repository root.")
    candidate = Path(text) if is_abs else root / text
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return ResolvedPath("rejected", shown, "Path could not be resolved (for example a symbolic-link loop).")
    if resolved != root and not resolved.is_relative_to(root):
        lexical = Path(os.path.normpath(candidate))
        if lexical == root or lexical.is_relative_to(root):
            return ResolvedPath("rejected", shown, "Symbolic link points outside the repository root.")
        return ResolvedPath("rejected", shown, "Path is outside the repository root.")
    rel = resolved.relative_to(root).as_posix()
    if rel in ("", "."):
        return ResolvedPath("rejected", shown, "The repository root itself is not a file.")
    if (reason := _sensitive(rel)) is not None:
        return ResolvedPath("sensitive", rel, reason)
    try:
        st = resolved.stat()
    except FileNotFoundError:
        return ResolvedPath("missing", rel, "Could not be found in the repository.")
    except OSError:
        return ResolvedPath("missing", rel, "Could not be accessed in the repository.")
    if stat.S_ISDIR(st.st_mode):
        return ResolvedPath("directory", rel, "Directory in the repository.", resolved)
    if not stat.S_ISREG(st.st_mode):
        return ResolvedPath("not_regular", rel, "Not a regular file (device, socket or pipe); not read.", resolved)
    return ResolvedPath("ok", rel, "", resolved)


def read_text_file(path: Path) -> tuple[str, str | None]:
    """Read a regular UTF-8 text file. Returns ``(status, text)``.

    ``status``: ok | too_large | binary | not_regular | unreadable. ``text`` is the raw (unredacted)
    content only for ``ok`` — callers must redact before storing or rendering it.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return "unreadable", None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "not_regular", None
        if st.st_size > MAX_FILE_BYTES:
            return "too_large", None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return "unreadable", None
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        return "too_large", None
    if b"\x00" in data[:8192]:
        return "binary", None
    try:
        return "ok", data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", None


def is_test_file(rel: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name
    if name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
        return True
    if _JS_TEST.search(name):
        return True
    return "__tests__" in p.parts[:-1] and bool(_JS_EXT.search(name))


def _iter_repo_files(root: Path):
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_WALK_FILES:
                return
            yield Path(dirpath, name)


def _matches_stem(rel: str, stem: str) -> bool:
    p = PurePosixPath(rel)
    name = p.name
    if name.endswith(".py"):
        return name.startswith(f"test_{stem}") or name == f"{stem}_test.py"
    if _JS_TEST.search(name):
        return name.split(".", 1)[0] == stem
    if "__tests__" in p.parts[:-1]:
        return name.split(".", 1)[0] == stem
    return False


def _shared_prefix(a: str, b: str) -> int:
    count = 0
    for x, y in zip(PurePosixPath(a).parts[:-1], PurePosixPath(b).parts[:-1], strict=False):
        if x != y:
            break
        count += 1
    return count


def discover_related_tests(root: Path, source_rels: list[str], per_file: int) -> dict[str, list[str]]:
    """Heuristic test discovery by filename convention (``test_<stem>*.py``, ``<stem>.test.ts(x)``,
    ``__tests__/<stem>.*``). Results are candidates found by name, not proven coverage."""
    wanted = {rel: PurePosixPath(rel).name.split(".", 1)[0] for rel in source_rels}
    wanted = {rel: stem for rel, stem in wanted.items() if stem and stem not in _GENERIC_STEMS}
    if not wanted or per_file <= 0:
        return {}
    candidates: list[str] = []
    for path in _iter_repo_files(root):
        rel = path.relative_to(root).as_posix()
        if is_test_file(rel) and path.is_file() and not path.is_symlink():
            candidates.append(rel)
    found: dict[str, list[str]] = {}
    for rel, stem in wanted.items():
        matches = [c for c in candidates if c != rel and _matches_stem(c, stem)]
        matches.sort(key=lambda c: (-_shared_prefix(rel, c), len(c), c))
        if matches:
            found[rel] = matches[:per_file]
    return found


def git_recent_history(root: Path, rels: list[str], limit: int = 10) -> tuple[bool, str]:
    """``git log`` for ``rels``. Returns ``(True, redacted_output)`` or ``(False, plain reason)``."""
    if not rels:
        return False, "No verified files to look up."
    if not (root / ".git").exists():
        return False, "The repository has no .git directory."
    git = shutil.which("git")
    if git is None:
        return False, "Git is not installed on the server."
    cmd = [
        git, "--no-pager", "-C", str(root),
        "-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "core.quotePath=false",
        "log", "-n", str(limit), "--name-only", "--no-color", "--no-decorate", "--format=commit %h %as %s",
        "--", *rels,
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "PAGER": "cat"}
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, paths after "--"
            cmd, capture_output=True, text=True, timeout=GIT_TIMEOUT_S, check=False, env=env,
            stdin=subprocess.DEVNULL, errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False, f"git log timed out after {GIT_TIMEOUT_S:g} seconds."
    except OSError as exc:
        return False, f"git could not be run ({exc.__class__.__name__})."
    if proc.returncode != 0:
        first = (proc.stderr or "").strip().splitlines()[:1]
        detail = redact_text(first[0][:200]).text if first else f"exit code {proc.returncode}"
        return False, f"git log failed: {detail}"
    output = proc.stdout.strip()
    if not output:
        return False, "No commits touch the related files."
    return True, redact_text(output[:_GIT_OUTPUT_CAP]).text
