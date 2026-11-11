"""Integration registry: health of connected integrations and an honest capability catalog.

``Integration`` rows are created and counted by the ingestion pipeline (``touch_integration``) for
real traffic only — Simulation Lab events never mark an integration as connected. Health is derived
from the last event time; the per-integration evidence counts come from persisted rows
(``IngestedEvent``, ``PolicyDecision``, ``Agent``), never from estimates.

The catalog states what each integration can observe and what it can actually stop, using the
platform's enforcement vocabulary (enforced / advisory / observed). Planned integrations are listed
as planned; nothing is claimed for them. Setup guides (end of this module) are rendered with the
server URL of the caller's request, never with a real API key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.timeutil import ensure_utc, utcnow
from app.models import Agent, IngestedEvent, Integration, PolicyDecision
from app.schemas.integrations import (
    CapabilityOut,
    CatalogEntryOut,
    ConnectedIntegrationOut,
    EnforcementCountsOut,
    IntegrationsOut,
    SetupCommandOut,
    SetupGuideOut,
    SetupLinkOut,
    SetupScopeOut,
    SetupStepOut,
)
from app.services.ingestion_state import DEFAULT_INTEGRATION, ENFORCING_INTEGRATIONS

STALE_AFTER = timedelta(minutes=15)
_ORDER = {"connected": 0, "stale": 1, "never_seen": 2}


@dataclass(frozen=True)
class CatalogSpec:
    kind: str
    name: str
    status: str  # supported | planned
    summary: str
    best_enforcement: str | None
    monitoring: tuple[tuple[str, str, str], ...] = ()  # (name, mode, description)
    enforcement: tuple[tuple[str, str, str], ...] = ()
    limitations: tuple[str, ...] = ()
    integration_surface: str | None = None
    available_today: str | None = None
    interim_kind: str | None = None
    docs_path: str | None = None
    api_key_scopes: tuple[str, ...] = ()


_PLANNED_LIMITATION = (
    "Not supported yet: ContextOS has no native adapter for this framework, so nothing it does is recorded "
    "or enforced unless you use the interim path."
)

CATALOG: tuple[CatalogSpec, ...] = (
    CatalogSpec(
        kind="claude_code", name="Claude Code", status="supported", best_enforcement="enforced",
        summary="Claude Code hooks report each session, prompt and tool result, and ask ContextOS for a "
                "decision before every tool call that passes through the PreToolUse hook.",
        monitoring=(
            ("SessionStart", "observed", "Session start, resume, clear or compact, with the model and working directory."),
            ("UserPromptSubmit", "observed", "Every prompt the user submits, recorded and scanned as context."),
            ("PreToolUse", "observed", "The tool name and full arguments of each call, recorded with its decision."),
            ("PostToolUse / PostToolUseFailure", "observed",
             "Each tool result as the model reads it (file contents, command output, fetched pages, MCP results), "
             "classified for trust and scanned for prompt injection and secrets."),
            ("SessionEnd / SubagentStop", "observed",
             "Session end and subagent completion; delegated subagents get child sessions linked to the parent."),
        ),
        enforcement=(
            ("PreToolUse deny", "enforced",
             "DENY is returned as permissionDecision \"deny\": Claude Code does not run the tool and the reason "
             "reaches the model as the tool error."),
            ("PreToolUse ask", "enforced",
             "REQUIRE_APPROVAL holds the call for a reviewer in the Approval Centre; still pending at the timeout, "
             "Claude Code's own permission prompt (\"ask\") decides. RESTRICT with secret redaction asks with the "
             "masked input."),
        ),
        limitations=(
            "Only tool calls routed through the PreToolUse hook are covered. A disabled hook (disableAllHooks, "
            "--settings, --bare, an untrusted workspace) is not.",
            "Cannot see the model's reasoning, or anything Claude Code does without a tool call.",
            "ALLOW and AUDIT defer to Claude Code's own permissions: the hook never answers \"allow\", so ContextOS "
            "can make Claude Code stricter but never more permissive.",
            "Files a shell command touches are not visible in its arguments; path restrictions on such tools fail "
            "closed (deny).",
            "When ContextOS is unreachable the hook's fail mode applies (default \"ask\": Claude Code's own prompt "
            "decides).",
        ),
        docs_path="docs/integrations/claude-code.md", api_key_scopes=("ingest", "decide"),
    ),
    CatalogSpec(
        kind="mcp_gateway", name="MCP security gateway", status="supported", best_enforcement="enforced",
        summary="A stdio proxy started in place of an MCP server. ContextOS decides every tools/call before the "
                "upstream server is contacted, and scans listings, results, resources and prompts.",
        monitoring=(
            ("tools/list", "observed",
             "Tool names, descriptions, input schemas and server instructions, scanned for tool poisoning and "
             "reported again when the listing changes."),
            ("Tool results", "observed",
             "Each tools/call result, recorded as context from the MCP tool and scanned for prompt injection."),
            ("Resources and prompts", "observed",
             "Text returned by resources/read and prompts/get, passed through unchanged and scanned."),
        ),
        enforcement=(
            ("tools/call deny", "enforced",
             "DENY, a rejected or expired approval, or a restriction the gateway cannot apply returns an error "
             "result; the call never reaches the upstream server."),
            ("Approvals and restrictions", "enforced",
             "REQUIRE_APPROVAL holds the call until a reviewer decides; RESTRICT masks secrets or checks paths and "
             "argument size before forwarding."),
        ),
        limitations=(
            "Covers only MCP servers started through the gateway; servers configured directly in the host are not seen.",
            "Wraps stdio servers that the gateway starts as a child process.",
            "Resource reads and prompts are observed, not blocked.",
            "Sees the arguments of a call, not what the upstream server does with them.",
            "Fails closed by default when ContextOS is unreachable (--fail-mode open forwards without a decision).",
        ),
        docs_path="docs/integrations/mcp.md", api_key_scopes=("ingest", "decide"),
    ),
    CatalogSpec(
        kind="python_sdk", name="Python SDK", status="supported", best_enforcement="enforced",
        summary="guard() enforces decisions on Python tool functions; AgentSession reports sessions, prompts, "
                "context, messages and delegation from any Python agent.",
        monitoring=(
            ("AgentSession", "observed",
             "Session start and end, prompts, ingested context (pages, files, documents), inter-agent messages "
             "and delegation."),
            ("Guarded tool results", "observed", "The result or error of every guard()-wrapped call."),
            ("Reported tool calls", "observed", "Tool calls sent to POST /events after they ran."),
        ),
        enforcement=(
            ("guard()-wrapped tools", "enforced",
             "Before a wrapped function runs, ContextOS decides; DENY raises ToolDenied and the function is never "
             "entered. Approvals are polled; RESTRICT runs with restricted arguments or is denied."),
            ("client.decide() without guard()", "advisory",
             "Code that asks for a decision and applies it itself: ContextOS returns the decision but cannot "
             "verify it is honoured."),
        ),
        limitations=(
            "Enforcement covers only functions called through guard(). Code that calls the underlying API directly, "
            "or tools the agent framework runs itself, is not covered.",
            "Decisions requested through the SDK are recorded as enforced because guard() applies them; code that "
            "calls client.decide() and ignores the answer breaks that claim.",
            "Sees only what the agent reports: not the model's reasoning or unreported context.",
            "When ContextOS is unreachable the fail mode applies: closed (default) denies, open runs with a "
            "warning, ask raises ApprovalRequired.",
        ),
        docs_path="sdk/README.md", api_key_scopes=("ingest", "decide"),
    ),
    CatalogSpec(
        kind="openai_codex", name="OpenAI Codex", status="planned", best_enforcement=None,
        summary="Native support for the Codex CLI and agent is planned.",
        integration_surface="Codex's MCP server configuration and a pre-execution hook for its built-in shell and "
                            "file tools, if Codex exposes one.",
        available_today="Codex starts MCP servers from its configuration: wrap them with the ContextOS MCP gateway "
                        "to enforce decisions on those MCP tool calls. Codex's built-in shell and file tools are "
                        "not covered.",
        interim_kind="mcp_gateway", limitations=(_PLANNED_LIMITATION,),
    ),
    CatalogSpec(
        kind="cursor", name="Cursor", status="planned", best_enforcement=None,
        summary="Native support for Cursor's agent is planned.",
        integration_surface="Cursor's agent hooks (before shell and MCP execution) and its MCP configuration.",
        available_today="Wrap the MCP servers in .cursor/mcp.json with the ContextOS MCP gateway. Cursor's built-in "
                        "edit and terminal tools are not covered.",
        interim_kind="mcp_gateway", limitations=(_PLANNED_LIMITATION,),
    ),
    CatalogSpec(
        kind="langgraph", name="LangGraph", status="planned", best_enforcement=None,
        summary="A native LangGraph adapter is planned.",
        integration_surface="Callback handlers for observation and a tool-node wrapper for decisions before tools run.",
        available_today="Wrap the Python functions behind your LangGraph tools with guard(): those calls are "
                        "enforced and reported under the Python SDK integration.",
        interim_kind="python_sdk", limitations=(_PLANNED_LIMITATION,),
    ),
    CatalogSpec(
        kind="crewai", name="CrewAI", status="planned", best_enforcement=None,
        summary="A native CrewAI adapter is planned.",
        integration_surface="CrewAI event listeners for observation and tool wrappers for decisions.",
        available_today="Wrap the Python functions behind your CrewAI tools with guard(): those calls are enforced "
                        "and reported under the Python SDK integration.",
        interim_kind="python_sdk", limitations=(_PLANNED_LIMITATION,),
    ),
    CatalogSpec(
        kind="openai_agents_sdk", name="OpenAI Agents SDK", status="planned", best_enforcement=None,
        summary="A native OpenAI Agents SDK adapter is planned.",
        integration_surface="Tracing processors for observation and function-tool wrappers or tool guardrails for "
                            "decisions.",
        available_today="Wrap your function tools' Python implementations with guard(): those calls are enforced "
                        "and reported under the Python SDK integration.",
        interim_kind="python_sdk", limitations=(_PLANNED_LIMITATION,),
    ),
    CatalogSpec(
        kind="anthropic_agent_sdk", name="Claude Agent SDK", status="planned", best_enforcement=None,
        summary="A native adapter for Anthropic's Claude Agent SDK is planned.",
        integration_surface="The SDK's in-process hooks (PreToolUse / PostToolUse), which mirror Claude Code's.",
        available_today="Wrap your custom Python tools with guard(); stdio MCP servers the SDK starts can be "
                        "wrapped with the ContextOS MCP gateway.",
        interim_kind="python_sdk", limitations=(_PLANNED_LIMITATION,),
    ),
)

CATALOG_BY_KIND: dict[str, CatalogSpec] = {spec.kind: spec for spec in CATALOG}


def catalog_spec(kind: str) -> CatalogSpec | None:
    return CATALOG_BY_KIND.get(kind)


def normalise_kind(raw: str | None) -> str:
    """Same normalisation as the ingestion pipeline (``ingestion_state.integration_kind``)."""
    kind = (raw or "").strip().lower()
    return kind[:48] if kind else DEFAULT_INTEGRATION


def display_name(kind: str) -> str:
    spec = CATALOG_BY_KIND.get(kind)
    if spec is not None:
        return spec.name
    if kind == DEFAULT_INTEGRATION:
        return "Custom (no integration name)"
    return kind.replace("_", " ").strip().capitalize() or kind


def health_of(last_event_at: datetime | None, now: datetime) -> tuple[str, str]:
    """``connected`` (event within 15 minutes) | ``stale`` | ``never_seen``, with a plain explanation."""
    last = ensure_utc(last_event_at)
    if last is None:
        return "never_seen", "Registered, but no event has been received yet."
    minutes = int(STALE_AFTER.total_seconds() // 60)
    if now - last <= STALE_AFTER:
        return "connected", f"Received an event in the last {minutes} minutes."
    return "stale", (f"No event in the last {minutes} minutes. The agent may simply be idle; if it is running, "
                     "check its configuration with `contextos doctor`.")


def _best_enforcement(kind: str) -> str:
    """What a decision for this kind is recorded as when it is requested before the tool runs."""
    return "enforced" if kind in ENFORCING_INTEGRATIONS else "advisory"


# ----------------------------------------------------------------------------- evidence counts


def _events_24h(db: Session, org_id: str, since: datetime) -> dict[str, int]:
    rows = db.execute(
        select(IngestedEvent.integration, func.count())
        .where(IngestedEvent.organization_id == org_id, IngestedEvent.is_simulation.is_(False),
               IngestedEvent.received_at >= since)
        .group_by(IngestedEvent.integration)
    ).all()
    counts: dict[str, int] = {}
    for raw, n in rows:
        key = normalise_kind(raw)
        counts[key] = counts.get(key, 0) + int(n)
    return counts


def _decisions_by_kind(db: Session, org_id: str) -> dict[str, EnforcementCountsOut]:
    rows = db.execute(
        select(IngestedEvent.integration, PolicyDecision.enforcement, func.count())
        .join(IngestedEvent, (IngestedEvent.id == PolicyDecision.event_id)
              & (IngestedEvent.organization_id == PolicyDecision.organization_id))
        .where(PolicyDecision.organization_id == org_id, PolicyDecision.is_simulation.is_(False))
        .group_by(IngestedEvent.integration, PolicyDecision.enforcement)
    ).all()
    out: dict[str, EnforcementCountsOut] = {}
    for raw, mode, n in rows:
        counts = out.setdefault(normalise_kind(raw), EnforcementCountsOut())
        if mode in ("enforced", "advisory", "observed"):
            setattr(counts, mode, getattr(counts, mode) + int(n))
    return out


def _agents_by_integration(db: Session, org_id: str, ids: list[str]) -> dict[str, int]:
    if not ids:
        return {}
    rows = db.execute(
        select(Agent.integration_id, func.count())
        .where(Agent.organization_id == org_id, Agent.is_simulation.is_(False), Agent.integration_id.in_(ids))
        .group_by(Agent.integration_id)
    ).all()
    return {str(i): int(n) for i, n in rows}


# ----------------------------------------------------------------------------- registry


def connected_integrations(db: Session, org_id: str, now: datetime) -> list[ConnectedIntegrationOut]:
    rows = list(db.scalars(select(Integration).where(Integration.organization_id == org_id)))
    events = _events_24h(db, org_id, now - timedelta(hours=24))
    decisions = _decisions_by_kind(db, org_id)
    agents = _agents_by_integration(db, org_id, [r.id for r in rows])
    out: list[ConnectedIntegrationOut] = []
    for row in rows:
        health, detail = health_of(row.last_event_at, now)
        out.append(ConnectedIntegrationOut(
            id=row.id, kind=row.kind, name=row.name, display_name=display_name(row.kind),
            supported=getattr(CATALOG_BY_KIND.get(row.kind), "status", None) == "supported",
            best_enforcement=_best_enforcement(row.kind), health=health, health_detail=detail,
            first_seen_at=row.created_at, last_event_at=row.last_event_at,
            event_count=row.event_count or 0, decision_count=row.decision_count or 0,
            events_24h=events.get(row.kind, 0), decisions=decisions.get(row.kind, EnforcementCountsOut()),
            agent_count=agents.get(row.id, 0), last_error=row.last_error,
        ))
    epoch = datetime.min.replace(tzinfo=now.tzinfo)
    out.sort(key=lambda i: (_ORDER[i.health], -(ensure_utc(i.last_event_at) or epoch).timestamp(), i.kind))
    return out


def _catalog_entry(spec: CatalogSpec, connected: list[ConnectedIntegrationOut]) -> CatalogEntryOut:
    mine = [c for c in connected if c.kind == spec.kind]
    health = min((c.health for c in mine), key=_ORDER.__getitem__, default="never_seen")
    last = max((c.last_event_at for c in mine if c.last_event_at is not None), default=None)

    def caps(items: tuple[tuple[str, str, str], ...]) -> list[CapabilityOut]:
        return [CapabilityOut(name=n, mode=m, description=d) for n, m, d in items]  # type: ignore[arg-type]

    return CatalogEntryOut(
        kind=spec.kind, name=spec.name, status=spec.status, summary=spec.summary,  # type: ignore[arg-type]
        best_enforcement=spec.best_enforcement, monitoring=caps(spec.monitoring),  # type: ignore[arg-type]
        enforcement=caps(spec.enforcement), limitations=list(spec.limitations),
        integration_surface=spec.integration_surface, available_today=spec.available_today,
        interim_kind=spec.interim_kind, docs_path=spec.docs_path, api_key_scopes=list(spec.api_key_scopes),
        health=health, last_event_at=last,  # type: ignore[arg-type]
    )


def integrations_overview(db: Session, org_id: str, *, now: datetime | None = None) -> IntegrationsOut:
    now = now or utcnow()
    connected = connected_integrations(db, org_id, now)
    return IntegrationsOut(
        connected=connected,
        catalog=[_catalog_entry(spec, connected) for spec in CATALOG],
        stale_after_minutes=int(STALE_AFTER.total_seconds() // 60),
        generated_at=now,
    )


# ----------------------------------------------------------------------------- setup guides

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
    "python_sdk": "Optional: needed for RESTRICT with secret redaction and the CLI's read commands.",
}


def server_url_for(base_url: str) -> tuple[str, str]:
    """The request's base URL when it is a plain http(s) address, otherwise a labelled fallback."""
    url = base_url.strip().rstrip("/")
    if _SAFE_URL.match(url):
        return url, ("Taken from the address you used to open ContextOS. If your agents reach the server at a "
                     "different address (a load balancer or another host name), use that address instead.")
    return _FALLBACK_URL, (f"This request's address could not be used safely; replace {_FALLBACK_URL} with the "
                           "address your agents use to reach ContextOS.")


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
        description="From a checkout of the ContextOS repository, into the Python environment your agent uses." + note,
        commands=[_cmd("bash", f"pip install -e {target}")],
    )


def _init_step(url: str, *, claude_code: bool) -> SetupStepOut:
    flags = " --claude-code" if claude_code else ""
    what = (" and merges the ContextOS hooks into .claude/settings.json (a backup of the original is kept; "
            "--scope local or --scope user selects another settings file)") if claude_code else ""
    return SetupStepOut(
        title="Connect the project" + (" and install the hooks" if claude_code else ""),
        description="Run in the project directory. It checks the server and the key before writing anything, "
                    "writes .contextos/config.json and stores the key in ~/.contextos with mode 600" + what + ". "
                    "Leave out --api-key to be prompted for it with hidden input, which keeps the key out of your "
                    "shell history.",
        commands=[_cmd("bash", f"contextos init --url {url} --api-key {_KEY_PLACEHOLDER}{flags}")],
    )


def _doctor_step() -> SetupStepOut:
    return SetupStepOut(
        title="Check the installation",
        description="Confirms the server is reachable, shows which scopes the key has and, for Claude Code, "
                    "whether the hooks can start.",
        commands=[_cmd("bash", "contextos doctor")],
    )


def _claude_code_steps(url: str) -> list[SetupStepOut]:
    events = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "SubagentStop",
              "SessionEnd")
    hooks = {"hooks": {ev: [{**({"matcher": "*"} if ev.startswith(("Pre", "Post", "Sub")) else {}), "hooks": [
        {"type": "command", "command": f"contextos hook {ev}", "timeout": 60 if ev == "PreToolUse" else 15}]}]
        for ev in events}}
    return [
        _key_step("claude_code"), _install_step(), _init_step(url, claude_code=True), _doctor_step(),
        SetupStepOut(
            title="Reference: what the installer adds",
            description="The hooks merged into .claude/settings.json. PreToolUse is the enforcement point; the other "
                        "hooks only observe. The installer writes the absolute path of the CLI so the hooks do not "
                        "depend on PATH, and marks them so `contextos` can remove only its own.",
            commands=[_cmd("json", json.dumps(hooks, indent=2), ".claude/settings.json")],
        ),
        SetupStepOut(title="Start Claude Code in the project",
                     description="The first hook event registers the integration on this page.",
                     commands=[_cmd("bash", "claude")]),
    ]


def _gateway_steps(url: str, *, host: str = "claude_code") -> list[SetupStepOut]:
    args = ["mcp-gateway", "--name", "toolbox", "--", "python", "examples/mcp/benign_server.py"]
    server = json.dumps({"mcpServers": {"toolbox": {"command": "contextos", "args": args,
                                                    "env": {"CONTEXTOS_URL": url}}}}, indent=2)
    toml = (f"[mcp_servers.toolbox]\ncommand = \"contextos\"\nargs = {json.dumps(args)}\n"
            f"env = {{ CONTEXTOS_URL = {json.dumps(url)} }}\n")
    title, path, language, code = {
        "claude_code": ("Wrap a server in .mcp.json", ".mcp.json", "json", server),
        "cursor": ("Wrap a server in .cursor/mcp.json", ".cursor/mcp.json", "json", server),
        "codex": ("Wrap a server in the Codex configuration", "~/.codex/config.toml", "toml", toml),
    }[host]
    return [
        _key_step("mcp_gateway"), _install_step("mcp"), _init_step(url, claude_code=False),
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


def _sdk_steps(url: str) -> list[SetupStepOut]:
    code = (
        "from contextos import AgentSession, ToolDenied, guard\n\n\n"
        "@guard(\"send_email\", category_hint=\"email\", destination=\"to\")\n"
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    ...  # your implementation; never entered when ContextOS denies the call\n\n\n"
        "with AgentSession() as session:  # reports session.started / session.ended\n"
        "    session.prompt(user_request)\n"
        "    session.ingest_context(\"web\", page_url, page_text)  # classified and scanned server-side\n"
        "    try:\n"
        "        send_email(\"ops@example.com\", \"Weekly report\", summary)\n"
        "    except ToolDenied as denied:\n"
        "        print(\"Blocked by ContextOS:\", denied)\n"
    )
    return [
        _key_step("python_sdk"), _install_step(), _init_step(url, claude_code=False),
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
    "python_sdk": "Run the agent: the Python SDK appears under Connected integrations, and each guarded call has "
                  "an Enforced decision.",
}


def setup_guide(kind: str, base_url: str) -> SetupGuideOut | None:
    """Step-by-step setup for a catalog kind, or None for an unknown kind. Planned kinds get the
    interim path through an existing adapter, clearly labelled as such."""
    spec = CATALOG_BY_KIND.get(kind)
    if spec is None:
        return None
    url, url_note = server_url_for(base_url)
    target = spec.interim_kind if spec.status == "planned" else spec.kind
    assert target is not None
    if target == "claude_code":
        steps = _claude_code_steps(url)
    elif target == "mcp_gateway":
        steps = _gateway_steps(url, host={"cursor": "cursor", "openai_codex": "codex"}.get(kind, "claude_code"))
    else:
        steps = _sdk_steps(url)
    target_spec = CATALOG_BY_KIND[target]
    notes = list(target_spec.limitations)
    if spec.status == "planned":
        notes = [f"{spec.name} has no native ContextOS integration yet. {spec.available_today}",
                 f"Events from this path are recorded under the {target_spec.name} integration."] + notes
    scopes = [SetupScopeOut(scope=s, required=True, purpose=_SCOPE_PURPOSE[s]) for s in ("ingest", "decide")]
    scopes.append(SetupScopeOut(scope="read", required=False, purpose=_READ_PURPOSE[target]))
    return SetupGuideOut(
        kind=spec.kind, name=spec.name, status=spec.status,  # type: ignore[arg-type]
        interim_kind=spec.interim_kind if spec.status == "planned" else None,
        server_url=url, server_url_note=url_note, api_key_scopes=scopes, steps=steps,
        verification=_VERIFY[target], notes=notes, docs_path=target_spec.docs_path,
    )
