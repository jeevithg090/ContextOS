"""The integration capability catalog: what each integration can observe and what it can stop.

Stated in the platform's enforcement vocabulary (enforced / advisory / observed). Planned
integrations are listed as planned with the interim path through an existing adapter; nothing is
claimed for them. A supported kind's ``best_enforcement`` must match ``ENFORCING_INTEGRATIONS``.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.ingestion_state import DEFAULT_INTEGRATION, ENFORCING_INTEGRATIONS

__all__ = ["CATALOG", "CATALOG_BY_KIND", "CatalogSpec", "best_enforcement", "catalog_spec", "display_name",
           "normalise_kind"]


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
        kind="openai_codex", name="OpenAI Codex", status="supported", best_enforcement="enforced",
        summary="Codex hooks report each session, prompt and successful tool result, and ask ContextOS for a "
                "decision before every tool call that reaches Codex's PreToolUse hook: shell commands, apply_patch "
                "edits, MCP tools and sub-agent launches.",
        monitoring=(
            ("SessionStart / SessionEnd", "observed", "Session start, resume and end, with the model, working "
             "directory and approval mode."),
            ("UserPromptSubmit", "observed", "Every prompt the user submits; inside a sub-agent, the task its parent "
             "sent (recorded as a message between agents, not as a person's prompt)."),
            ("PreToolUse", "observed", "The tool name and full input of each call, recorded with its decision."),
            ("PostToolUse", "observed",
             "Each successful tool result as the model reads it (command output, patch results, MCP results), "
             "classified for trust and scanned for prompt injection and secrets."),
            ("spawn_agent / SubagentStop", "observed",
             "Sub-agent delegation with its task; the sub-agent gets a child session linked to the parent."),
        ),
        enforcement=(
            ("PreToolUse block", "enforced",
             "DENY is returned as exit code 2 with the reason on stderr: Codex does not run the tool and the reason "
             "reaches the model as the tool output."),
            ("Approvals and restrictions", "enforced",
             "REQUIRE_APPROVAL holds the call for a reviewer in the Approval Centre; still pending at the timeout, "
             "the call is blocked (Codex hooks cannot ask). RESTRICT with secret redaction runs the call with the "
             "masked input; a restriction the hook cannot apply blocks."),
        ),
        limitations=(
            "Only tool calls that reach Codex's PreToolUse hook are covered. Hosted tools (web search), input "
            "typed into an already running command (write_stdin) and hooks that are disabled ([features] hooks = "
            "false), untrusted or modified (not re-trusted in /hooks) are not.",
            "Codex runs PostToolUse only for calls that produced output: failed calls (an MCP error result, a "
            "rejected approval, a sandbox or tool error) and apply_patch run inside a shell command report no result.",
            "ALLOW and AUDIT defer to Codex's own approval policy and sandbox: the hook never grants approval, so "
            "ContextOS can make Codex stricter but never more permissive.",
            "Files a shell command touches are not visible in its arguments; path restrictions on such tools fail "
            "closed (block). Another PreToolUse hook that rewrites a call's input runs after ContextOS decided.",
            "When ContextOS is unreachable the hook's fail mode applies (default \"closed\": the call is blocked).",
        ),
        docs_path="docs/integrations/codex.md", api_key_scopes=("ingest", "decide"),
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


def best_enforcement(kind: str) -> str:
    """What a decision for this kind is recorded as when it is requested before the tool runs."""
    return "enforced" if kind in ENFORCING_INTEGRATIONS else "advisory"
