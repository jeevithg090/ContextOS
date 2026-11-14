"""Tool-name parsing and keyword inference (pure data + small helpers).

Knows the Claude Code and OpenAI Codex built-in tools, the ``mcp__<server>__<tool>`` naming
convention and common MCP / framework verbs. Inference is ordered from most to least specific so that, for example,
``execute_sql`` is a database tool (not code execution) and ``gmail_fetch`` is email (not HTTP).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain.enums import RiskLevel, ToolCategory

C = ToolCategory

# name -> (category, what it does, risk override or None)
BUILTINS: dict[str, tuple[str, str, str | None]] = {
    "Bash": (C.SHELL, "runs shell commands", None),
    "BashOutput": (C.SHELL, "reads the output of a background shell (the command itself was classified when "
                   "it started)", RiskLevel.MEDIUM),
    "KillShell": (C.OTHER, "stops a background shell and runs nothing new", None),
    "KillBash": (C.OTHER, "stops a background shell and runs nothing new", None),
    "Read": (C.FILE_READ, "reads local files", None),
    "Glob": (C.FILE_READ, "lists files matching a pattern", None),
    "Grep": (C.FILE_READ, "searches file contents", None),
    "LS": (C.FILE_READ, "lists a directory", None),
    "NotebookRead": (C.FILE_READ, "reads a notebook", None),
    "ListMcpResourcesTool": (C.FILE_READ, "lists resources exposed by connected MCP servers", None),
    "ReadMcpResourceTool": (C.FILE_READ, "reads a resource exposed by a connected MCP server", None),
    "Write": (C.FILE_WRITE, "writes files", None),
    "Edit": (C.FILE_WRITE, "edits files", None),
    "MultiEdit": (C.FILE_WRITE, "edits files", None),
    "NotebookEdit": (C.FILE_WRITE, "edits notebooks", None),
    "WebFetch": (C.HTTP, "fetches a URL", None),
    "WebSearch": (C.SEARCH, "runs a web search", None),
    "Task": (C.AGENT_DELEGATION, "delegates work to a sub-agent", None),
    "Agent": (C.AGENT_DELEGATION, "delegates work to a sub-agent", None),
    "TodoWrite": (C.OTHER, "updates the agent's own task list", None),
    "ExitPlanMode": (C.OTHER, "leaves planning mode", None),
    "SlashCommand": (C.OTHER, "runs a user-defined slash command prompt", None),
    "ToolSearch": (C.OTHER, "loads the definitions of the agent's own deferred tools (no outside access)", None),
}

# OpenAI Codex built-ins, as Codex names them in its hook payloads (provider ``openai_codex``).
# ``apply_patch`` carries ``{"command": <patch text>}``: without this entry the ``command`` argument
# would make it look like a shell call.
CODEX_PROVIDER = "openai_codex"
CODEX_BUILTINS: dict[str, tuple[str, str, str | None]] = {
    "Bash": (C.SHELL, "runs shell commands (exec_command)", None),
    "apply_patch": (C.FILE_WRITE, "edits files by applying a patch", None),
    "view_image": (C.FILE_READ, "reads a local image", None),
    "spawn_agent": (C.AGENT_DELEGATION, "starts a sub-agent with a task", None),
    "send_input": (C.AGENT_DELEGATION, "sends more work to a running sub-agent", None),
    "send_message": (C.AGENT_DELEGATION, "sends more work to a running sub-agent", None),
    "followup_task": (C.AGENT_DELEGATION, "sends more work to a running sub-agent", None),
    "resume_agent": (C.AGENT_DELEGATION, "resumes a sub-agent", None),
    "wait_agent": (C.OTHER, "waits for sub-agents to finish", None),
    "list_agents": (C.OTHER, "lists the session's sub-agents", None),
    "close_agent": (C.OTHER, "stops a sub-agent and runs nothing new", None),
    "interrupt_agent": (C.OTHER, "interrupts a sub-agent and runs nothing new", None),
    "update_plan": (C.OTHER, "updates the agent's own plan", None),
    "request_user_input": (C.OTHER, "asks the user a question", None),
    "list_mcp_resources": (C.FILE_READ, "lists resources exposed by connected MCP servers", None),
    "list_mcp_resource_templates": (C.FILE_READ, "lists resource templates exposed by connected MCP servers", None),
    "read_mcp_resource": (C.FILE_READ, "reads a resource exposed by a connected MCP server", None),
}
# Codex names a namespaced tool "<namespace><name>" in hook payloads (``flat_tool_name``), so the
# multi-agent v1 tools arrive as e.g. "multi_agent_v1wait_agent" (spawn_agent alone is special-cased).
CODEX_MULTI_AGENT_NAMESPACE = "multi_agent_v1"
CODEX_BUILTINS.update({
    CODEX_MULTI_AGENT_NAMESPACE + name: entry for name, entry in list(CODEX_BUILTINS.items())
    if entry[0] == C.AGENT_DELEGATION or name.endswith("_agent") or name == "list_agents"
})
_HOST_LABELS = {CODEX_PROVIDER: "Codex"}


def builtin_for(tool: str, provider: str | None) -> tuple[tuple[str, str, str | None] | None, str]:
    """``(entry, host label)`` for a host built-in; Codex names resolve only for its own provider."""
    if (provider or "").strip().lower() == CODEX_PROVIDER:
        return CODEX_BUILTINS.get(tool), _HOST_LABELS[CODEX_PROVIDER]
    return BUILTINS.get(tool), "Claude Code"


FILE_OBJECTS = {"file", "files", "directory", "directories", "dir", "folder", "path", "paths", "contents",
                "content", "notebook", "document", "documents", "tree"}
SEND_VERBS = {"send", "post", "reply", "forward", "draft", "compose", "publish", "share", "upload", "notify",
              "broadcast", "dm", "sendmessage", "postmessage", "sendemail", "write", "create", "update"}
READ_VERBS = {"read", "get", "list", "search", "fetch", "find", "view", "history", "unread", "query", "lookup",
              "retrieve", "download", "show", "inbox"}
WEB_SEARCH_TOKENS = {"web", "google", "bing", "brave", "tavily", "exa", "serp", "serpapi", "duckduckgo",
                     "perplexity", "internet", "websearch", "kagi", "searxng"}

# (category, exact tokens, substrings, [(verb set, object set) pairs that must both appear])
_Rule = tuple[str, set[str], tuple[str, ...], list[tuple[set[str], set[str]]]]
RULES: list[_Rule] = [
    (C.AGENT_DELEGATION, {"delegate", "delegation", "subagent", "handoff"}, (),
     [({"spawn", "invoke", "call", "run", "launch", "start", "create"}, {"agent", "agents", "subagent", "assistant"})]),
    (C.EMAIL, {"email", "emails", "mail", "mails", "gmail", "smtp", "outlook", "inbox", "sendgrid", "mailgun",
               "postmark", "imap"}, ("gmail", "email", "smtp"), []),
    (C.MESSAGING, {"slack", "discord", "teams", "telegram", "whatsapp", "sms", "twilio", "mattermost", "chat", "dm",
                   "postmessage", "sendmessage"}, ("slack", "discord", "telegram", "whatsapp", "twilio"),
     [({"post", "send"}, {"message", "messages", "msg"})]),
    (C.INFRASTRUCTURE, {"terraform", "kubectl", "kubernetes", "k8s", "aws", "gcloud", "gcp", "azure", "deploy",
                        "deployment", "deployments", "helm", "pulumi", "cloudformation", "ec2", "ecs", "eks", "gke",
                        "aks", "s3", "docker", "container", "containers", "vercel", "netlify", "heroku",
                        "ansible"}, ("terraform", "kubectl", "kubernetes", "gcloud", "cloudformation", "pulumi",
                                     "deploy"), []),
    (C.SHELL, {"shell", "bash", "zsh", "sh", "ssh", "terminal", "powershell", "cmd", "command", "commands"},
     ("shell", "bash", "powershell"), []),
    (C.DATABASE, {"sql", "database", "databases", "db", "postgres", "postgresql", "mysql", "sqlite", "mongo",
                  "mongodb", "redis", "bigquery", "snowflake", "dynamodb", "supabase", "firestore", "cassandra",
                  "clickhouse", "duckdb", "table", "tables"}, ("sql", "postgres", "mongo"),
     [({"execute", "exec", "run"}, {"query", "queries", "statement"})]),
    (C.BROWSER, {"browser", "browse", "navigate", "click", "screenshot", "playwright", "puppeteer", "selenium",
                 "webdriver"}, ("playwright", "puppeteer", "selenium", "browser"), []),
    (C.CODE_EXECUTION, {"exec", "execute", "eval", "python", "jupyter", "interpreter", "sandbox", "repl",
                        "javascript", "ipython", "executecode"}, (),
     [({"run"}, {"code", "script", "python", "notebook", "cell", "js"})]),
    (C.HTTP, {"http", "https", "fetch", "request", "requests", "url", "urls", "webhook", "webhooks", "curl", "wget",
              "download", "upload", "publish", "push", "graphql", "webfetch"}, ("webhook",), []),
    (C.FILE_WRITE, {"write", "edit", "edits", "save", "append", "overwrite", "mkdir", "rmdir", "touch"}, (),
     [({"create", "delete", "remove", "move", "rename", "copy", "update", "replace"}, FILE_OBJECTS)]),
    (C.FILE_READ, {"read", "cat", "open", "ls", "glob", "grep", "head", "tail", "stat"}, (),
     [({"get", "list", "find", "tree", "show", "load", "view"}, FILE_OBJECTS)]),
    (C.SEARCH, {"search", "lookup", "find", "retrieve", "retrieval", "websearch"}, ("search",), []),
    (C.DATABASE, {"query", "queries"}, (), []),
]

_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


@dataclass(frozen=True)
class ParsedName:
    raw: str
    tool: str
    server: str | None
    is_mcp: bool


def parse_tool_name(name: str, provider: str | None, server: str | None) -> ParsedName:
    """Split ``mcp__<server>__<tool>`` and recognise MCP providers (``mcp:<server>``)."""
    name = (name or "").strip()
    if name.startswith("mcp__"):
        srv, sep, tool = name[5:].partition("__")
        if sep and tool:
            return ParsedName(name, tool, srv or server, True)
        return ParsedName(name, name[5:] or name, server, True)
    prov = (provider or "").strip()
    if prov.lower().startswith("mcp"):
        mcp_server = server or (prov.split(":", 1)[1] if ":" in prov else None)
        return ParsedName(name, name, mcp_server or None, True)
    if server:
        return ParsedName(name, name, server, True)
    return ParsedName(name, name, None, False)


def name_tokens(value: str | None) -> set[str]:
    """Lower-cased tokens from snake/kebab/dotted/camelCase names (whole parts are kept too)."""
    if not value:
        return set()
    tokens: set[str] = set()
    for part in re.split(r"[^A-Za-z0-9]+", value):
        if not part:
            continue
        tokens.add(part.lower())
        tokens.update(piece.lower() for piece in _CAMEL.findall(part))
    return tokens


def infer_category(tokens: set[str]) -> tuple[str, str] | None:
    """(category, matched keyword) for the first rule that matches, else None."""
    joined = " ".join(sorted(tokens))
    for category, exact, substrings, pairs in RULES:
        hit = next(iter(sorted(tokens & exact)), None)
        if hit:
            return category, hit
        sub = next((s for s in substrings if s in joined), None)
        if sub:
            return category, sub
        for verbs, objects in pairs:
            v, o = tokens & verbs, tokens & objects
            if v and o:
                return category, f"{sorted(v)[0]} {sorted(o)[0]}"
    return None
