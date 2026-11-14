"""Install, remove and inspect the ContextOS hooks in Claude Code settings files.

Scopes (Claude Code's settings files):

- ``project`` → ``<project>/.claude/settings.json`` (shared with the team, usually committed)
- ``local``   → ``<project>/.claude/settings.local.json`` (this machine only)
- ``user``    → ``~/.claude/settings.json`` (every project; ``CLAUDE_CONFIG_DIR`` is honoured)

Installing merges into the file without touching anything else: existing hooks, permissions and
other settings are preserved, the first version of the file is kept as
``<file>.contextos-backup``, and running it again changes nothing. ContextOS hooks are recognised
by their command (``… contextos hook <Event>``), so ``uninstall_hooks`` removes only those.

Installed events: PreToolUse (timeout 60 s, all tools) is the enforcement point; PostToolUse and
PostToolUseFailure (all tools), UserPromptSubmit, SessionStart, SubagentStop and SessionEnd
(timeout 15 s each) are observation only.

Run as a module for a quick check: ``python -m contextos.integrations.claude_code.install status``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCOPES = ("project", "local", "user")
BACKUP_SUFFIX = ".contextos-backup"
PRE_TOOL_STATUS = "ContextOS policy check"
OBSERVATION_TIMEOUT_S = 15
# (event, matcher or None for events where Claude Code matches everything when it is omitted)
HOOK_EVENTS: tuple[tuple[str, str | None], ...] = (
    ("PreToolUse", "*"),
    ("PostToolUse", "*"),
    ("PostToolUseFailure", "*"),
    ("UserPromptSubmit", None),
    ("SessionStart", None),
    ("SubagentStop", None),
    ("SessionEnd", None),
)
_OURS_RE = re.compile(r"""(?:^|[\s/\\"'])contextos(?:\.exe)?["']?\s+hook\s+([A-Za-z]+)\s*$""")


@dataclass
class InstallReport:
    path: Path
    scope: str
    changed: bool = False
    events: list[str] = field(default_factory=list)
    backup: Path | None = None
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        state = "updated" if self.changed else "already up to date"
        return f"{self.path} ({state})"


def claude_user_dir(home: Path | None = None) -> Path:
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override and home is None:
        return Path(override).expanduser()
    return (home or Path.home()) / ".claude"


def settings_path(project_dir: Path, scope: str = "project", *, home: Path | None = None) -> Path:
    if scope == "project":
        return Path(project_dir).resolve() / ".claude" / "settings.json"
    if scope == "local":
        return Path(project_dir).resolve() / ".claude" / "settings.local.json"
    if scope == "user":
        return claude_user_dir(home) / "settings.json"
    raise ValueError(f"scope must be one of {', '.join(SCOPES)} (got {scope!r})")


def _quote(part: str) -> str:
    if os.name == "nt":
        return f'"{part}"' if any(c.isspace() for c in part) else part
    return shlex.quote(part)


def default_command() -> str:
    """Absolute command for this installation: ``<python> -m contextos`` (never depends on PATH).

    A hook command that cannot start at all is a non-blocking error in Claude Code and the tool
    would run unchecked, so the installer pins the interpreter that has this package.
    """
    return f"{_quote(sys.executable)} -m contextos"


def hook_command(base: str, event: str) -> str:
    return f"{base.strip()} hook {event}"


def is_contextos_hook(handler: Any) -> str | None:
    """The event name when ``handler`` is a ContextOS hook handler, else ``None``."""
    if not isinstance(handler, dict) or handler.get("type") != "command":
        return None
    match = _OURS_RE.search(str(handler.get("command") or ""))
    return match.group(1) if match else None


def _desired(event: str, matcher: str | None, base: str, timeout: int) -> dict[str, Any]:
    handler: dict[str, Any] = {
        "type": "command",
        "command": hook_command(base, event),
        "timeout": timeout if event == "PreToolUse" else min(timeout, OBSERVATION_TIMEOUT_S),
    }
    if event == "PreToolUse":
        handler["statusMessage"] = PRE_TOOL_STATUS
    group: dict[str, Any] = {"hooks": [handler]}
    if matcher is not None:
        group = {"matcher": matcher, **group}
    return group


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from None
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path} is not valid JSON (line {exc.lineno}); fix it before installing hooks"
        ) from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")  # noqa: TRY004 - a file-content error, like bad JSON
    return data


def _hooks_section(settings: dict[str, Any], path: Path) -> dict[str, Any]:
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {path} is not an object; refusing to modify it")  # noqa: TRY004
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError(f"'hooks.{event}' in {path} is not a list; refusing to modify it")  # noqa: TRY004
    return hooks


def _without_ours(groups: list[Any]) -> list[Any]:
    """Groups with every ContextOS handler removed; groups left empty by that are dropped."""
    kept: list[Any] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            kept.append(group)
            continue
        handlers = [h for h in group["hooks"] if not is_contextos_hook(h)]
        if handlers:
            kept.append({**group, "hooks": handlers})
        elif not group["hooks"]:
            kept.append(group)  # an empty group that was never ours
    return kept


def _write(path: Path, settings: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(settings, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if not backup.exists():  # keep the very first version: that is the user's original file
        shutil.copy2(path, backup)
    return backup


def apply_hooks(
    project_dir: Path,
    scope: str = "project",
    command: str | None = None,
    timeout: int = 60,
    *,
    home: Path | None = None,
) -> InstallReport:
    """Merge the ContextOS hooks into the settings file for ``scope``; see the module docstring."""
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= 600:
        raise ValueError("timeout must be an integer number of seconds between 10 and 600")
    base = (command or default_command()).strip()
    if not base:
        raise ValueError("command must not be empty")
    path = settings_path(project_dir, scope, home=home)
    settings = _load(path)
    hooks = dict(_hooks_section(settings, path))
    report = InstallReport(path=path, scope=scope, events=[e for e, _ in HOOK_EVENTS])
    for event, matcher in HOOK_EVENTS:
        desired = _desired(event, matcher, base, timeout)
        groups = list(hooks.get(event, []))
        ours = [
            g
            for g in groups
            if isinstance(g, dict)
            and isinstance(g.get("hooks"), list)
            and any(is_contextos_hook(h) for h in g["hooks"])
        ]
        if len(ours) == 1 and ours[0] == desired:
            continue  # already exactly as wanted: leave the file untouched
        hooks[event] = [*_without_ours(groups), desired]
    if settings.get("disableAllHooks") is True:
        report.warnings.append(f"{path} sets disableAllHooks: true, so Claude Code runs no hooks at all")
    new_settings = {**settings, "hooks": hooks}
    if new_settings != settings:
        report.backup = _backup(path)
        _write(path, new_settings)
        report.changed = True
    return report


def install_hooks(
    project_dir: Path,
    scope: str = "project",
    command: str | None = None,
    timeout: int = 60,
    *,
    home: Path | None = None,
) -> Path:
    """Install (or update) the hooks; returns the settings file. Idempotent."""
    return apply_hooks(project_dir, scope, command, timeout, home=home).path


def uninstall_hooks(project_dir: Path, scope: str = "project", *, home: Path | None = None) -> InstallReport:
    """Remove only the ContextOS hooks from the settings file for ``scope``."""
    path = settings_path(project_dir, scope, home=home)
    settings = _load(path)
    report = InstallReport(path=path, scope=scope)
    if not settings or "hooks" not in settings:
        return report
    hooks = _hooks_section(settings, path)
    cleaned: dict[str, Any] = {}
    for event, groups in hooks.items():
        if any(
            isinstance(g, dict)
            and isinstance(g.get("hooks"), list)
            and any(is_contextos_hook(h) for h in g["hooks"])
            for g in groups
        ):
            report.events.append(event)
            remaining = _without_ours(groups)
            if remaining:
                cleaned[event] = remaining
        else:
            cleaned[event] = groups
    if not report.events:
        return report
    new_settings = dict(settings)
    if cleaned:
        new_settings["hooks"] = cleaned
    else:
        new_settings.pop("hooks")
    _write(path, new_settings)
    report.changed = True
    return report


def _command_resolvable(command: str) -> bool:
    try:
        parts = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return False
    if not parts:
        return False
    exe = parts[0].strip('"')
    expanded = os.path.expandvars(os.path.expanduser(exe))
    if os.path.isabs(expanded):
        return os.path.isfile(expanded) and os.access(expanded, os.X_OK)
    return shutil.which(expanded) is not None


def hooks_status(project_dir: Path, *, home: Path | None = None) -> dict[str, Any]:
    """What ``contextos doctor`` reports: where the hooks are installed and whether they can run."""
    scopes: dict[str, Any] = {}
    enforcing: list[str] = []
    broken: list[str] = []
    disabled: list[str] = []
    for scope in SCOPES:
        path = settings_path(project_dir, scope, home=home)
        entry: dict[str, Any] = {"path": str(path), "exists": path.exists(), "events": []}
        try:
            settings = _load(path)
            hooks = _hooks_section(settings, path) if settings else {}
        except ValueError as exc:
            entry["error"] = str(exc)
            scopes[scope] = entry
            continue
        if settings.get("disableAllHooks") is True:
            disabled.append(scope)
        for event, groups in hooks.items():
            for group in groups:
                for handler in (group.get("hooks") or []) if isinstance(group, dict) else []:
                    if is_contextos_hook(handler) == event:
                        entry["events"].append(event)
                        if event == "PreToolUse":
                            entry["pre_tool_use_command"] = handler.get("command")
                            entry["pre_tool_use_timeout"] = handler.get("timeout")
                            ok = _command_resolvable(str(handler.get("command") or ""))
                            entry["command_resolvable"] = ok
                            (enforcing if ok else broken).append(scope)
        entry["events"] = sorted(set(entry["events"]))
        entry["missing"] = [e for e, _ in HOOK_EVENTS if e not in entry["events"]] if entry["events"] else []
        scopes[scope] = entry
    installed = bool(enforcing) and not disabled
    if disabled:
        detail = f"disableAllHooks is true in the {', '.join(disabled)} settings: Claude Code runs no hooks"
    elif broken and not enforcing:
        detail = (
            f"the PreToolUse command in the {', '.join(broken)} settings cannot be started; Claude Code "
            "would run tools unchecked. Re-run `contextos init --claude-code`"
        )
    elif enforcing:
        missing = sorted({m for s in enforcing for m in scopes[s]["missing"]})
        detail = f"enforcing via PreToolUse ({', '.join(enforcing)} scope)"
        if missing:
            detail += f"; not observed: {', '.join(missing)}"
    elif any(scopes[s]["events"] for s in SCOPES):
        detail = "observation hooks only: PreToolUse (enforcement) is not installed"
    else:
        detail = "not installed (optional): contextos init --claude-code"
    return {"installed": installed, "ok": not broken and not disabled, "detail": detail, "scopes": scopes}


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m contextos.integrations.claude_code.install",
        description="Manage the ContextOS hooks in Claude Code settings.",
    )
    parser.add_argument("action", choices=("install", "uninstall", "status"))
    parser.add_argument("--project-dir", default=".", type=Path)
    parser.add_argument("--scope", default="project", choices=SCOPES)
    parser.add_argument(
        "--timeout", default=60, type=int, help="PreToolUse hook timeout in seconds (default 60)"
    )
    args = parser.parse_args(argv)
    try:
        if args.action == "install":
            report = apply_hooks(args.project_dir, args.scope, timeout=args.timeout)
            print(f"ContextOS hooks: {report}")
            for warning in report.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            if report.backup:
                print(f"original settings kept at {report.backup}")
        elif args.action == "uninstall":
            report = uninstall_hooks(args.project_dir, args.scope)
            print(
                f"Removed ContextOS hooks for {', '.join(report.events)} from {report.path}"
                if report.changed
                else f"No ContextOS hooks in {report.path}"
            )
        else:
            print(json.dumps(hooks_status(args.project_dir), indent=2))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


__all__ = [
    "HOOK_EVENTS",
    "SCOPES",
    "InstallReport",
    "apply_hooks",
    "default_command",
    "hook_command",
    "hooks_status",
    "install_hooks",
    "is_contextos_hook",
    "settings_path",
    "uninstall_hooks",
]

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
