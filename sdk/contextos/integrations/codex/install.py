"""Install, remove and inspect the ContextOS hooks in Codex ``hooks.json`` files.

Scopes (Codex config layers that read a ``hooks.json``):

- ``project`` → ``<project>/.codex/hooks.json`` (Codex loads it only when the project is trusted)
- ``user``    → ``$CODEX_HOME/hooks.json`` (default ``~/.codex/hooks.json``; every project)

The file format is Codex's ``HooksFile`` (``codex-rs/config/src/hook_config.rs``):
``{"description"?: str, "hooks": {"<Event>": [{"matcher"?: str, "hooks": [{"type": "command",
"command": str, "timeout"?: seconds, "statusMessage"?: str}]}]}}``.

Installing merges into the file without touching anything else: existing hooks keep their position
(so the trust Codex recorded for them stays valid), the ContextOS groups are appended, the first
version of the file is kept as ``hooks.json.contextos-backup``, and running it again changes
nothing. ContextOS hooks are recognised by their command (``… contextos codex-hook <Event>``).

Codex runs a hook from ``hooks.json`` only after a person reviewed and trusted it in Codex
(``/hooks``); trust is pinned to a hash of the hook, so a changed hook must be trusted again. The
installer never writes that trust for you: deciding to run a command for every tool call is the
user's call, made in Codex. ``hooks_status`` (used by ``contextos doctor``) reports what Codex has
recorded in ``$CODEX_HOME/config.toml`` (``[hooks.state."<file>:<event>:<group>:<handler>"]``).

Installed events: PreToolUse (timeout 60 s, every tool) is the enforcement point; PostToolUse
(every tool), UserPromptSubmit, SessionStart, SubagentStop (timeout 15 s each) and SessionEnd
(3 s, Codex's maximum) are observation only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contextos.integrations.claude_code.install import default_command

SCOPES = ("project", "user")
BACKUP_SUFFIX = ".contextos-backup"
PRE_TOOL_STATUS = "ContextOS policy check"
OBSERVATION_TIMEOUT_S = 15
SESSION_END_TIMEOUT_S = 3  # Codex clamps SessionEnd hooks to 1-3 s
# (event, matcher or None = every source/agent type, Codex's trust-key label)
HOOK_EVENTS: tuple[tuple[str, str | None, str], ...] = (
    ("PreToolUse", "*", "pre_tool_use"),
    ("PostToolUse", "*", "post_tool_use"),
    ("UserPromptSubmit", None, "user_prompt_submit"),
    ("SessionStart", None, "session_start"),
    ("SubagentStop", None, "subagent_stop"),
    ("SessionEnd", None, "session_end"),
)
EVENT_LABELS = {event: label for event, _, label in HOOK_EVENTS}
_OURS_RE = re.compile(r"""(?:^|[\s/\\"'])contextos(?:\.exe)?["']?\s+codex-hook\s+([A-Za-z]+)\s*$""")


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


def codex_home(home: Path | None = None) -> Path:
    override = os.environ.get("CODEX_HOME")
    if override and home is None:
        return Path(override).expanduser()
    return (home or Path.home()) / ".codex"


def hooks_path(project_dir: Path, scope: str = "project", *, home: Path | None = None) -> Path:
    if scope == "project":
        return Path(project_dir).resolve() / ".codex" / "hooks.json"
    if scope == "user":
        return codex_home(home) / "hooks.json"
    raise ValueError(f"Codex hook scope must be one of {', '.join(SCOPES)} (got {scope!r})")


def hook_command(base: str, event: str) -> str:
    return f"{base.strip()} codex-hook {event}"


def is_contextos_hook(handler: Any) -> str | None:
    """The event name when ``handler`` is a ContextOS Codex hook handler, else ``None``."""
    if not isinstance(handler, dict) or handler.get("type") != "command":
        return None
    match = _OURS_RE.search(str(handler.get("command") or ""))
    return match.group(1) if match else None


def _timeout_for(event: str, pre_tool_timeout: int) -> int:
    if event == "PreToolUse":
        return pre_tool_timeout
    if event == "SessionEnd":
        return SESSION_END_TIMEOUT_S
    return min(pre_tool_timeout, OBSERVATION_TIMEOUT_S)


def _desired(event: str, matcher: str | None, base: str, timeout: int) -> dict[str, Any]:
    handler: dict[str, Any] = {"type": "command", "command": hook_command(base, event),
                               "timeout": _timeout_for(event, timeout)}
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
        raise ValueError(f"{path} is not valid JSON (line {exc.lineno}); fix it before installing hooks") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")  # noqa: TRY004 - a file-content error, like bad JSON
    return data


def _hooks_section(data: dict[str, Any], path: Path) -> dict[str, Any]:
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {path} is not an object; refusing to modify it")  # noqa: TRY004
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError(f"'hooks.{event}' in {path} is not a list; refusing to modify it")  # noqa: TRY004
    return hooks


def _ours(group: Any) -> bool:
    return isinstance(group, dict) and isinstance(group.get("hooks"), list) and any(
        is_contextos_hook(h) for h in group["hooks"])


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


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
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


def _toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _hooks_feature_off(*config_files: Path) -> list[str]:
    off = []
    for path in config_files:
        features = _toml(path).get("features")
        if isinstance(features, dict) and (features.get("hooks") is False or features.get("codex_hooks") is False):
            off.append(str(path))
    return off


def apply_hooks(project_dir: Path, scope: str = "project", command: str | None = None, timeout: int = 60, *,
                home: Path | None = None) -> InstallReport:
    """Merge the ContextOS hooks into the ``hooks.json`` for ``scope``; see the module docstring."""
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= 600:
        raise ValueError("timeout must be an integer number of seconds between 10 and 600")
    base = (command or default_command()).strip()
    if not base:
        raise ValueError("command must not be empty")
    path = hooks_path(project_dir, scope, home=home)
    data = _load(path)
    hooks = dict(_hooks_section(data, path))
    report = InstallReport(path=path, scope=scope, events=[e for e, _, _ in HOOK_EVENTS])
    for event, matcher, _ in HOOK_EVENTS:
        desired = _desired(event, matcher, base, timeout)
        groups = list(hooks.get(event, []))
        ours = [i for i, g in enumerate(groups) if _ours(g)]
        if len(ours) == 1 and groups[ours[0]] == desired:
            continue  # already exactly as wanted: leave the file untouched
        if ours and groups[ours[0]].get("hooks") and all(is_contextos_hook(h) for h in groups[ours[0]]["hooks"]):
            # Update our group where it is, so the groups after it keep their index (and their trust).
            first = ours[0]
            hooks[event] = [*_without_ours(groups[:first]), desired, *_without_ours(groups[first + 1:])]
        else:
            hooks[event] = [*_without_ours(groups), desired]
    new_data = {**data, "hooks": hooks}
    if new_data != data:
        report.backup = _backup(path)
        _write(path, new_data)
        report.changed = True
    report.warnings.append("Codex runs these hooks only after you review and trust them: start Codex in the project "
                           "and open /hooks (trust is pinned to each hook's hash; review again after any change).")
    if scope == "project":
        report.warnings.append("Project hooks load only when Codex trusts the project (it asks the first time you "
                               "start it there).")
    off = _hooks_feature_off(codex_home(home) / "config.toml", Path(project_dir).resolve() / ".codex" / "config.toml")
    if off:
        report.warnings.append(f"[features] hooks = false in {', '.join(off)}: Codex runs no hooks at all")
    return report


def install_hooks(project_dir: Path, scope: str = "project", command: str | None = None, timeout: int = 60, *,
                  home: Path | None = None) -> InstallReport:
    """Install (or update) the hooks. Idempotent; returns the report (path, backup, warnings)."""
    return apply_hooks(project_dir, scope, command, timeout, home=home)


def uninstall_hooks(project_dir: Path, scope: str = "project", *, home: Path | None = None) -> InstallReport:
    """Remove only the ContextOS hooks from the ``hooks.json`` for ``scope``."""
    path = hooks_path(project_dir, scope, home=home)
    data = _load(path)
    report = InstallReport(path=path, scope=scope)
    if not data or "hooks" not in data:
        return report
    hooks = _hooks_section(data, path)
    cleaned: dict[str, Any] = {}
    for event, groups in hooks.items():
        if any(_ours(g) for g in groups):
            report.events.append(event)
            remaining = _without_ours(groups)
            if remaining:
                cleaned[event] = remaining
        else:
            cleaned[event] = groups
    if not report.events:
        return report
    _write(path, {**data, "hooks": cleaned})
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


def login_shell_prints_to_stdout(env: dict[str, str] | None = None, timeout_s: float = 10.0) -> bool | None:
    """Whether ``$SHELL -lc true`` writes to stdout (``None`` when it cannot be checked).

    Codex starts hook commands through ``$SHELL -lc``. Text a login profile prints on stdout lands
    in front of the hook's JSON answer, Codex can no longer parse it and ignores the answer (the
    tool runs). Blocking answers use exit code 2 and are not affected; RESTRICT rewrites are.
    """
    environ = dict(os.environ if env is None else env)
    shell = environ.get("SHELL") or "/bin/sh"
    if os.name == "nt" or not Path(shell).is_file():
        return None
    try:
        done = subprocess.run([shell, "-lc", "true"], capture_output=True, timeout=timeout_s, env=environ,
                              stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(done.stdout.strip())


def _trust(states: dict[str, Any], path: Path, event: str, group: int, handler: int) -> str:
    key = f"{path}:{EVENT_LABELS.get(event, event)}:{group}:{handler}"
    state = states.get(key)
    if not isinstance(state, dict):
        return "untrusted"
    if state.get("enabled") is False:
        return "disabled"
    return "trusted" if state.get("trusted_hash") else "untrusted"


def _project_trust(user_config: dict[str, Any], project_dir: Path) -> str | None:
    projects = user_config.get("projects")
    if not isinstance(projects, dict):
        return None
    for candidate in (str(project_dir), str(project_dir.resolve())):
        entry = projects.get(candidate)
        if isinstance(entry, dict) and isinstance(entry.get("trust_level"), str):
            return entry["trust_level"]
    return None


def hooks_status(project_dir: Path, *, home: Path | None = None, check_shell: bool = True) -> dict[str, Any]:
    """What ``contextos doctor`` reports: where the hooks are installed, whether Codex will run them."""
    project = Path(project_dir).resolve()
    user_config_file = codex_home(home) / "config.toml"
    user_config = _toml(user_config_file)
    hooks_cfg = user_config.get("hooks")
    states = hooks_cfg.get("state", {}) if isinstance(hooks_cfg, dict) else {}
    states = states if isinstance(states, dict) else {}
    scopes: dict[str, Any] = {}
    enforcing: list[str] = []
    broken: list[str] = []
    untrusted: list[str] = []
    for scope in SCOPES:
        path = hooks_path(project, scope, home=home)
        entry: dict[str, Any] = {"path": str(path), "exists": path.exists(), "events": [], "trust": {}}
        try:
            data = _load(path)
            hooks = _hooks_section(data, path) if data else {}
        except ValueError as exc:
            entry["error"] = str(exc)
            scopes[scope] = entry
            continue
        for event, groups in hooks.items():
            for gi, group in enumerate(groups):
                for hi, handler in enumerate((group.get("hooks") or []) if isinstance(group, dict) else []):
                    if is_contextos_hook(handler) != event:
                        continue
                    entry["events"].append(event)
                    entry["trust"][event] = _trust(states, path, event, gi, hi)
                    if event == "PreToolUse":
                        entry["pre_tool_use_command"] = handler.get("command")
                        entry["pre_tool_use_timeout"] = handler.get("timeout")
                        ok = _command_resolvable(str(handler.get("command") or ""))
                        entry["command_resolvable"] = ok
                        if not ok:
                            broken.append(scope)
                        elif entry["trust"][event] == "trusted":
                            enforcing.append(scope)
                        else:
                            untrusted.append(scope)
        entry["events"] = sorted(set(entry["events"]))
        entry["missing"] = [e for e, _, _ in HOOK_EVENTS if e not in entry["events"]] if entry["events"] else []
        scopes[scope] = entry
    disabled = _hooks_feature_off(user_config_file, project / ".codex" / "config.toml")
    project_trust = _project_trust(user_config, project)
    shell_noise = login_shell_prints_to_stdout() if check_shell and (enforcing or untrusted) else None
    installed = bool(enforcing) and not disabled
    notes: list[str] = []
    if disabled:
        detail = f"[features] hooks = false in {', '.join(disabled)}: Codex runs no hooks"
    elif broken and not enforcing:
        detail = (f"the PreToolUse command in the {', '.join(broken)} hooks.json cannot be started; Codex would run "
                  "tools unchecked. Re-run `contextos init --codex`")
    elif enforcing:
        missing = sorted({m for s in enforcing for m in scopes[s]["missing"]})
        not_trusted = sorted({e for s in enforcing for e, t in scopes[s]["trust"].items() if t != "trusted"})
        detail = f"enforcing via PreToolUse ({', '.join(enforcing)} scope; trusted in Codex)"
        if missing:
            detail += f"; not installed: {', '.join(missing)}"
        if not_trusted:
            detail += f"; not yet trusted in /hooks: {', '.join(not_trusted)}"
    elif untrusted:
        detail = (f"installed ({', '.join(untrusted)} scope) but Codex has not recorded trust for the PreToolUse hook: "
                  "Codex skips untrusted hooks. Review and trust them in Codex with /hooks")
    elif any(scopes[s]["events"] for s in SCOPES):
        detail = "observation hooks only: PreToolUse (enforcement) is not installed"
    else:
        detail = "not installed (optional): contextos init --codex"
    if "project" in (enforcing + untrusted) and project_trust not in (None, "trusted"):
        notes.append(f"Codex marks {project} as '{project_trust}': project hooks do not load")
    if shell_noise:
        notes.append("your login shell prints to stdout ($SHELL -lc true): Codex would ignore JSON hook answers, so "
                     "RESTRICT rewrites would not apply (blocking answers still work)")
    if notes:
        detail += "; " + "; ".join(notes)
    error = bool(disabled) or bool(broken and not enforcing) or (
        "project" in (enforcing + untrusted) and project_trust == "untrusted" and "user" not in enforcing)
    warning = not error and (bool(notes) or bool(untrusted and not enforcing) or bool(enforcing and (
        "not yet trusted" in detail or "not installed:" in detail)))
    return {"installed": installed, "ok": not error, "warning": warning, "detail": detail, "scopes": scopes,
            "project_trust": project_trust, "login_shell_stdout": shell_noise}


__all__ = [
    "HOOK_EVENTS",
    "SCOPES",
    "InstallReport",
    "apply_hooks",
    "codex_home",
    "hook_command",
    "hooks_path",
    "hooks_status",
    "install_hooks",
    "is_contextos_hook",
    "login_shell_prints_to_stdout",
    "uninstall_hooks",
]
