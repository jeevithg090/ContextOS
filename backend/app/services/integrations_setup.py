"""Integration setup guides: step-by-step instructions rendered for the caller's organisation.

Steps use the server URL of the caller's request (when it is a plain http(s) address) and the
organisation's configured fail mode. A real API key is never included: steps point to
Settings → API keys and use a placeholder.
"""

from __future__ import annotations

import json
import re

from app.schemas.integrations import (
    SetupCommandOut,
    SetupGuideOut,
    SetupLinkOut,
    SetupScopeOut,
    SetupStepOut,
)
from app.services.integrations_catalog import CATALOG_BY_KIND

__all__ = ["server_url_for", "setup_guide"]

_SAFE_URL = re.compile(r"^https?://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$")
_FALLBACK_URL = "http://localhost:8000"
_KEY_PLACEHOLDER = "ctxk_your_key"
_API_KEYS_LINK = SetupLinkOut(label="Settings → API keys", href="/settings?tab=api-keys")
_SCOPE_PURPOSE = {
    "ingest": "Report events: sessions, prompts, context and tool results.",
    "decide": "Ask for a decision before a tool runs. Without it nothing can be enforced.",
}
_READ_PURPOSE = {
    "claude_code": "Optional: lets the hook re-check masked arguments with POST /scan when a RESTRICT policy "
    "redacts secrets (without it such calls are denied).",
    "mcp_gateway": "Optional: needed for --hide-blocked-tools and for RESTRICT with secret redaction (without it "
    "such calls are blocked).",
    "openai_codex": "Optional: lets the hook re-check masked arguments with POST /scan when a RESTRICT policy "
    "redacts secrets (without it such calls are blocked).",
    "python_sdk": "Optional: needed for RESTRICT with secret redaction and the CLI's read commands.",
}


def server_url_for(base_url: str) -> tuple[str, str]:
    """The request's base URL when it is a plain http(s) address, otherwise a labelled fallback."""
    url = base_url.strip().rstrip("/")
    if _SAFE_URL.match(url):
        return url, (
            "Taken from the address you used to open ContextOS. If your agents reach the server at a "
            "different address (a load balancer or another host name), use that address instead."
        )
    return _FALLBACK_URL, (
        f"This request's address could not be used safely; replace {_FALLBACK_URL} with the "
        "address your agents use to reach ContextOS."
    )


def _cmd(language: str, code: str, title: str | None = None) -> SetupCommandOut:
    return SetupCommandOut(language=language, code=code, title=title)


def _key_step(kind: str) -> SetupStepOut:
    return SetupStepOut(
        title="Create an API key",
        description="Create a key with the ingest and decide scopes. The key is shown once; keep it out of source "
        "control. " + _READ_PURPOSE[kind],
        link=_API_KEYS_LINK,
    )


def _install_step(extra: str = "") -> SetupStepOut:
    target = f"'sdk[{extra}]'" if extra else "sdk"
    note = " The gateway needs the MCP Python SDK 2.x and refuses to start on 1.x." if extra == "mcp" else ""
    return SetupStepOut(
        title="Install the ContextOS SDK and CLI",
        description="From a checkout of the ContextOS repository, into the Python environment your agent uses."
        + note,
        commands=[_cmd("bash", f"pip install -e {target}")],
    )


_FAIL_MODE_MEANING = {
    "closed": "deny the call",
    "open": "let the call run without a decision",
    "ask": "defer to the agent host's own permission prompt",
}


def _init_step(
    url: str, *, claude_code: bool, codex: bool = False, fail_mode: str | None = None, gateway: bool = False
) -> SetupStepOut:
    flags = " --claude-code" if claude_code else " --codex" if codex else ""
    what = (
        (
            " and merges the ContextOS hooks into .claude/settings.json (a backup of the original is kept; "
            "--scope local or --scope user selects another settings file)"
        )
        if claude_code
        else (
            " and merges the ContextOS hooks into .codex/hooks.json (a backup of the original is kept; --scope user "
            "selects ~/.codex/hooks.json)"
        )
        if codex
        else ""
    )
    hooks = claude_code or codex
    mode_note = ""
    if fail_mode in _FAIL_MODE_MEANING and not hooks:
        flags += f" --fail-mode {fail_mode}"
        mode_note = (
            f" --fail-mode {fail_mode} is your organisation's fail mode (Settings → Organisation): when "
            f"ContextOS cannot be reached, the integration will {_FAIL_MODE_MEANING[fail_mode]}."
        )
        if gateway and fail_mode == "ask":
            mode_note += " The MCP gateway has no one to ask, so it treats 'ask' as 'closed' (deny)."
    return SetupStepOut(
        title="Connect the project" + (" and install the hooks" if hooks else ""),
        description="Run in the project directory. It checks the server and the key before writing anything, "
        "writes .contextos/config.json and stores the key in ~/.contextos with mode 600" + what + ". "
        "Leave out --api-key to be prompted for it with hidden input, which keeps the key out of your "
        "shell history." + mode_note,
        commands=[_cmd("bash", f"contextos init --url {url} --api-key {_KEY_PLACEHOLDER}{flags}")],
    )


def _hook_fail_mode_step(fail_mode: str) -> SetupStepOut:
    """The Claude Code hook has its own fail mode setting (default ``ask``), separate from ``guard()``."""
    config = json.dumps({"claude_code": {"fail_mode": fail_mode}}, indent=2)
    return SetupStepOut(
        title="Apply your organisation's fail mode to the hook",
        description=(
            f"Your organisation's fail mode is '{fail_mode}' (Settings → Organisation): when ContextOS "
            f"cannot be reached, the PreToolUse hook will {_FAIL_MODE_MEANING[fail_mode]}. The hook reads "
            "its own setting, not the general one: export CONTEXTOS_HOOK_FAIL_MODE in the shell that starts "
            'Claude Code, or add the "claude_code" object to .contextos/config.json.'
        ),
        commands=[
            _cmd("bash", f"export CONTEXTOS_HOOK_FAIL_MODE={fail_mode}"),
            _cmd("json", config, ".contextos/config.json (claude_code section)"),
        ],
    )


def _doctor_step() -> SetupStepOut:
    return SetupStepOut(
        title="Check the installation",
        description="Confirms the server is reachable, shows which scopes the key has and, for Claude Code, "
        "whether the hooks can start.",
        commands=[_cmd("bash", "contextos doctor")],
    )


def _claude_code_steps(url: str, fail_mode: str | None = None) -> list[SetupStepOut]:
    events = (
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "UserPromptSubmit",
        "SessionStart",
        "SubagentStop",
        "SessionEnd",
    )
    hooks = {
        "hooks": {
            ev: [
                {
                    **({"matcher": "*"} if ev.startswith(("Pre", "Post", "Sub")) else {}),
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"contextos hook {ev}",
                            "timeout": 60 if ev == "PreToolUse" else 15,
                        }
                    ],
                }
            ]
            for ev in events
        }
    }
    return [
        _key_step("claude_code"),
        _install_step(),
        _init_step(url, claude_code=True),
        _doctor_step(),
        SetupStepOut(
            title="Reference: what the installer adds",
            description="The hooks merged into .claude/settings.json. PreToolUse is the enforcement point; the other "
            "hooks only observe. The installer writes the absolute path of the CLI so the hooks do not "
            "depend on PATH, and marks them so `contextos` can remove only its own.",
            commands=[_cmd("json", json.dumps(hooks, indent=2), ".claude/settings.json")],
        ),
        *([_hook_fail_mode_step(fail_mode)] if fail_mode in _FAIL_MODE_MEANING else []),
        SetupStepOut(
            title="Start Claude Code in the project",
            description="The first hook event registers the integration on this page.",
            commands=[_cmd("bash", "claude")],
        ),
    ]


_GATEWAY_ARGS = ["mcp-gateway", "--name", "toolbox", "--", "python", "examples/mcp/benign_server.py"]


def _codex_toml(url: str) -> str:
    return (
        f'[mcp_servers.toolbox]\ncommand = "contextos"\nargs = {json.dumps(_GATEWAY_ARGS)}\n'
        f"env = {{ CONTEXTOS_URL = {json.dumps(url)} }}\n"
    )


def _codex_steps(url: str, fail_mode: str | None = None) -> list[SetupStepOut]:
    events = (
        ("PreToolUse", "*", 60),
        ("PostToolUse", "*", 15),
        ("UserPromptSubmit", None, 15),
        ("SessionStart", None, 15),
        ("SubagentStop", None, 15),
        ("SessionEnd", None, 3),
    )
    hooks = {
        "hooks": {
            ev: [
                {
                    **({"matcher": matcher} if matcher else {}),
                    "hooks": [
                        {"type": "command", "command": f"contextos codex-hook {ev}", "timeout": timeout}
                    ],
                }
            ]
            for ev, matcher, timeout in events
        }
    }
    steps = [
        _key_step("openai_codex"),
        _install_step(),
        _init_step(url, claude_code=False, codex=True),
        _doctor_step(),
        SetupStepOut(
            title="Trust the hooks in Codex",
            description="Codex runs a hook only after you review and trust it: start Codex in the project, open "
            "/hooks and trust the ContextOS hooks. Trust is pinned to each hook's definition, so review "
            "them again after re-running the installer. Project hooks also need Codex to trust the "
            "project (it asks the first time you start it there).",
            commands=[_cmd("bash", "codex"), _cmd("text", "/hooks", "In Codex")],
        ),
        SetupStepOut(
            title="Reference: what the installer adds",
            description="The hooks merged into .codex/hooks.json. PreToolUse is the enforcement point (it blocks with "
            "exit code 2); the other hooks only observe. The installer writes the absolute path of the "
            "CLI so the hooks do not depend on PATH, and recognises its own hooks by their command.",
            commands=[_cmd("json", json.dumps(hooks, indent=2), ".codex/hooks.json")],
        ),
    ]
    if fail_mode in _FAIL_MODE_MEANING:
        meaning = (
            "deny the call (Codex hooks cannot ask, so 'ask' blocks like 'closed')"
            if fail_mode == "ask"
            else _FAIL_MODE_MEANING[fail_mode]
        )
        steps.append(
            SetupStepOut(
                title="Apply your organisation's fail mode to the hook",
                description=(
                    f"Your organisation's fail mode is '{fail_mode}' (Settings → Organisation): when ContextOS "
                    f"cannot be reached, the PreToolUse hook will {meaning}. The hook reads its own setting "
                    "(default 'closed'): export CONTEXTOS_CODEX_FAIL_MODE in the shell that starts Codex, or "
                    'add the "codex" object to .contextos/config.json.'
                ),
                commands=[
                    _cmd("bash", f"export CONTEXTOS_CODEX_FAIL_MODE={fail_mode}"),
                    _cmd(
                        "json",
                        json.dumps({"codex": {"fail_mode": fail_mode}}, indent=2),
                        ".contextos/config.json (codex section)",
                    ),
                ],
            )
        )
    steps.append(
        SetupStepOut(
            title="Optional: also put MCP servers behind the gateway",
            description="The hook already decides every MCP tool call Codex makes. Starting a server through the MCP "
            "gateway adds protocol-level enforcement and scans its tool listings and resources too. Each "
            "call is then decided twice (by the hook and by the gateway).",
            commands=[_cmd("toml", _codex_toml(url), "~/.codex/config.toml")],
        )
    )
    return steps


def _gateway_steps(
    url: str, *, host: str = "claude_code", fail_mode: str | None = None
) -> list[SetupStepOut]:
    args = _GATEWAY_ARGS
    server = json.dumps(
        {"mcpServers": {"toolbox": {"command": "contextos", "args": args, "env": {"CONTEXTOS_URL": url}}}},
        indent=2,
    )
    toml = _codex_toml(url)
    title, path, language, code = {
        "claude_code": ("Wrap a server in .mcp.json", ".mcp.json", "json", server),
        "cursor": ("Wrap a server in .cursor/mcp.json", ".cursor/mcp.json", "json", server),
        "codex": ("Wrap a server in the Codex configuration", "~/.codex/config.toml", "toml", toml),
    }[host]
    return [
        _key_step("mcp_gateway"),
        _install_step("mcp"),
        _init_step(url, claude_code=False, fail_mode=fail_mode, gateway=True),
        SetupStepOut(
            title=title,
            description="The host starts the gateway instead of the server; everything after -- is the real server's "
            "command (replace the example with yours). Use the same value for --name and the server's key "
            "in the configuration so calls are attributed to one server. The gateway reads the API key "
            "stored by `contextos init`; keep it out of the host's configuration file. Hosts often start "
            "servers with a minimal PATH: use the absolute path from `which contextos` if the command "
            "is not found.",
            commands=[_cmd(language, code, path)],
        ),
        _doctor_step(),
    ]


def _sdk_steps(url: str, fail_mode: str | None = None) -> list[SetupStepOut]:
    code = (
        "from contextos import AgentSession, ToolDenied, guard\n\n\n"
        '@guard("send_email", category_hint="email", destination="to")\n'
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    ...  # your implementation; never entered when ContextOS denies the call\n\n\n"
        "with AgentSession() as session:  # reports session.started / session.ended\n"
        "    session.prompt(user_request)\n"
        '    session.ingest_context("web", page_url, page_text)  # classified and scanned server-side\n'
        "    try:\n"
        '        send_email("ops@example.com", "Weekly report", summary)\n'
        "    except ToolDenied as denied:\n"
        '        print("Blocked by ContextOS:", denied)\n'
    )
    return [
        _key_step("python_sdk"),
        _install_step(),
        _init_step(url, claude_code=False, fail_mode=fail_mode),
        SetupStepOut(
            title="Guard your tools and report the session",
            description="Each call to a guard()-wrapped function asks ContextOS for a decision first and enforces "
            "it. Tools you do not wrap are not covered.",
            commands=[_cmd("python", code, "agent.py")],
        ),
        _doctor_step(),
    ]


_VERIFY = {
    "claude_code": "Start a Claude Code session in the project: within seconds Claude Code appears under Connected "
    "integrations as Connected, and its tool calls show up with Enforced decisions.",
    "mcp_gateway": "Use one of the wrapped server's tools from the host: the MCP security gateway appears under "
    "Connected integrations, and each tools/call has an Enforced decision.",
    "openai_codex": "Start Codex in the project and trust the hooks in /hooks: within seconds OpenAI Codex appears "
    "under Connected integrations as Connected, and its tool calls show up with Enforced decisions.",
    "python_sdk": "Run the agent: the Python SDK appears under Connected integrations, and each guarded call has "
    "an Enforced decision.",
}


def setup_guide(kind: str, base_url: str, *, fail_mode: str | None = None) -> SetupGuideOut | None:
    """Step-by-step setup for a catalog kind, or None for an unknown kind. Planned kinds get the
    interim path through an existing adapter, clearly labelled as such. ``fail_mode`` (the
    organisation's setting) is written into the commands when given."""
    fail_mode = fail_mode if fail_mode in _FAIL_MODE_MEANING else None
    spec = CATALOG_BY_KIND.get(kind)
    if spec is None:
        return None
    url, url_note = server_url_for(base_url)
    target = spec.interim_kind if spec.status == "planned" else spec.kind
    assert target is not None
    if target == "claude_code":
        steps = _claude_code_steps(url, fail_mode)
    elif target == "openai_codex":
        steps = _codex_steps(url, fail_mode)
    elif target == "mcp_gateway":
        steps = _gateway_steps(
            url,
            host={"cursor": "cursor", "openai_codex": "codex"}.get(kind, "claude_code"),
            fail_mode=fail_mode,
        )
    else:
        steps = _sdk_steps(url, fail_mode)
    target_spec = CATALOG_BY_KIND[target]
    notes = list(target_spec.limitations)
    if spec.status == "planned":
        notes = [
            f"{spec.name} has no native ContextOS integration yet. {spec.available_today}",
            f"Events from this path are recorded under the {target_spec.name} integration.",
        ] + notes
    scopes = [SetupScopeOut(scope=s, required=True, purpose=_SCOPE_PURPOSE[s]) for s in ("ingest", "decide")]
    scopes.append(SetupScopeOut(scope="read", required=False, purpose=_READ_PURPOSE[target]))
    return SetupGuideOut(
        kind=spec.kind,
        name=spec.name,
        status=spec.status,  # type: ignore[arg-type]
        interim_kind=spec.interim_kind if spec.status == "planned" else None,
        server_url=url,
        server_url_note=url_note,
        api_key_scopes=scopes,
        steps=steps,
        verification=_VERIFY[target],
        notes=notes,
        docs_path=target_spec.docs_path,
        fail_mode=fail_mode,
    )
