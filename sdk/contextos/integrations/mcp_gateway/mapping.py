"""MCP protocol objects -> ContextOS events (pure: no network, no MCP session).

Everything here is deterministic given its inputs, so the translation can be tested exhaustively
without an MCP server or a ContextOS server.

Identity: tools are reported with ``provider="mcp:<server>"`` and ``server=<server>``, the key the
ContextOS server uses for MCP tools whether they arrive through this gateway or as
``mcp__<server>__<tool>`` from Claude Code hooks. Resources and prompts are reported as context from
an ``mcp_server`` source whose identifier is ``<server>/resource:<uri>`` or ``<server>/prompt:<name>``.

Size: the server rejects events whose JSON exceeds 512 000 bytes. Long texts are truncated with an
explicit marker (and the number of omitted characters is recorded in ``metadata``), and very large
tool listings are split over several ``mcp.server_connected`` events, so every tool description
is still delivered for scanning.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import mcp.types as types

from contextos.models import AgentRef, EventEnvelope, EventType, SourceRef, SourceType, ToolRef

INTEGRATION = "mcp_gateway"
COLLECTED_VIA = "mcp_gateway"
EVENT_BUDGET_BYTES = 400_000  # below the server's 512 000-byte limit, leaving room for the envelope
MAX_TEXT_CHARS = 100_000  # tool results, resource and prompt texts
MAX_DESCRIPTION_CHARS = 50_000  # one tool description inside a listing (scanned for poisoning)
TOOLREF_DESCRIPTION_CHARS = 4_000  # ToolRef.description limit of the event contract
MAX_TOOLS_PER_EVENT = 500  # the server reads at most 500 tools from one listing event
MAX_SCHEMA_STRINGS = 500
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.\-]{0,98}[A-Za-z0-9])?$")
_TRUNCATION = "\n[TRUNCATED by the ContextOS MCP gateway: {n} more characters were not reported]"
_NOT_INSPECTED = "not inspected by ContextOS"


# -- helpers ---------------------------------------------------------------------------------------


def server_name_problem(name: str) -> str | None:
    """Why ``name`` cannot identify an MCP server in ContextOS, or ``None`` when it is valid.

    ``/``, ``:`` and ``__`` are refused because ContextOS (and Claude Code's ``mcp__server__tool``
    naming) use them as separators; a name containing them would be attributed to another server.
    """
    if not SERVER_NAME_RE.match(name or ""):
        return (
            "the server name must be 1-100 characters of letters, digits, '.', '_' or '-', "
            "starting and ending with a letter or digit"
        )
    if "__" in name:
        return (
            "the server name must not contain '__' (it separates server and tool in mcp__server__tool names)"
        )
    return None


def provider_for(server_name: str) -> str:
    return f"mcp:{server_name}"


def json_size(value: Any) -> int:
    """Bytes of ``value`` as the server measures it (compact, ASCII-escaped JSON)."""
    return len(json.dumps(value, separators=(",", ":"), default=str))


def fit_text(
    text: str, max_chars: int = MAX_TEXT_CHARS, max_bytes: int = EVENT_BUDGET_BYTES
) -> tuple[str, int]:
    """``(text, omitted_chars)``: ``text`` cut to ``max_chars`` and ``max_bytes`` with a visible marker."""
    limit = min(len(text), max(max_chars, 0))
    while True:
        omitted = len(text) - limit
        candidate = text[:limit] + (_TRUNCATION.format(n=omitted) if omitted else "")
        size = json_size(candidate)
        if limit == 0 or size <= max_bytes:
            return candidate, omitted
        limit = max(0, min(limit - 1, int(limit * max_bytes / size * 0.95)))


def _string_leaves(value: Any, out: list[str], depth: int = 0) -> list[str]:
    if depth > 20:
        return out
    if isinstance(value, str):
        if value.strip():
            out.append(value)
    elif isinstance(value, Mapping):
        for item in value.values():
            _string_leaves(item, out, depth + 1)
    elif isinstance(value, list | tuple):
        for item in value:
            _string_leaves(item, out, depth + 1)
    return out


# -- what the agent sees ---------------------------------------------------------------------------


def _resource_contents_text(contents: types.TextResourceContents | types.BlobResourceContents) -> str:
    if isinstance(contents, types.TextResourceContents):
        return contents.text
    approx_bytes = len(contents.blob) * 3 // 4
    return f"[binary resource {contents.uri} ({contents.mime_type or 'unknown type'}, ~{approx_bytes} bytes), {_NOT_INSPECTED}]"


def content_text(blocks: Iterable[Any]) -> str:
    """The text an agent receives from MCP content blocks. Binary blocks become labelled placeholders."""
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, types.TextContent):
            parts.append(block.text)
        elif isinstance(block, types.EmbeddedResource):
            parts.append(
                f"[embedded resource {block.resource.uri}]\n{_resource_contents_text(block.resource)}"
            )
        elif isinstance(block, types.ResourceLink):
            label = " ".join(p for p in (block.name, block.title) if p)
            detail = f": {block.description}" if block.description else ""
            parts.append(f"[resource link {block.uri} {label}{detail}]".replace("  ", " "))
        elif isinstance(block, types.ImageContent):
            parts.append(f"[image ({block.mime_type}), {_NOT_INSPECTED}]")
        elif isinstance(block, types.AudioContent):
            parts.append(f"[audio ({block.mime_type}), {_NOT_INSPECTED}]")
        else:
            parts.append(f"[{getattr(block, 'type', type(block).__name__)} content, {_NOT_INSPECTED}]")
    return "\n".join(p for p in parts if p)


def call_result_text(result: types.CallToolResult) -> str:
    """Text of a tool result: its content blocks, plus structured content not already shown as text."""
    text = content_text(result.content)
    structured = result.structured_content
    if structured is not None:
        leaves = _string_leaves(structured, [])
        if not leaves or not all(leaf in text for leaf in leaves):
            dumped = json.dumps(structured, ensure_ascii=False, sort_keys=True, default=str)
            text = f"{text}\n[structured content]\n{dumped}" if text else dumped
    return text


def resource_text(result: types.ReadResourceResult) -> str:
    return "\n\n".join(_resource_contents_text(c) for c in result.contents)


def prompt_text(result: types.GetPromptResult) -> str:
    lines = [result.description] if result.description else []
    lines.extend(f"{message.role}: {content_text([message.content])}" for message in result.messages)
    return "\n\n".join(lines)


def blocked_result(message: str) -> types.CallToolResult:
    """The error result returned to the host when the gateway does not run a call."""
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


# -- tool listings ---------------------------------------------------------------------------------


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def schema_strings(schema: Any, tool_name: str = "") -> list[str]:
    """Human-readable strings inside a JSON schema (descriptions, defaults, enums...) with their path.

    Tool poisoning is not limited to the tool description: parameter descriptions and defaults reach
    the model too. Titles that only restate a property name (as SDKs generate) are skipped.
    """
    out: list[str] = []

    def add(path: str, key: str, value: Any) -> None:
        if len(out) < MAX_SCHEMA_STRINGS and isinstance(value, str) and value.strip():
            out.append(f"{path or '(arguments)'} {key}: {value}")

    def visit(node: Any, path: str, name: str, depth: int) -> None:
        if depth > 12 or len(out) >= MAX_SCHEMA_STRINGS or not isinstance(node, Mapping):
            return
        title = node.get("title")
        generated = isinstance(title, str) and (_norm(title) in (_norm(name), _norm(f"{tool_name}arguments")))
        if not generated:
            add(path, "title", title)
        for key in ("description", "default", "const"):
            add(path, key, node.get(key))
        for key in ("enum", "examples"):
            values = node.get(key)
            if isinstance(values, list):
                for value in values[:50]:
                    add(path, key, value)
        props = node.get("properties")
        if isinstance(props, Mapping):
            for prop, sub in props.items():
                visit(sub, f"{path}.{prop}" if path else str(prop), str(prop), depth + 1)
        for key in ("items", "additionalProperties", "not"):
            visit(node.get(key), f"{path}[]" if key == "items" else path, name, depth + 1)
        for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
            branches = node.get(key)
            if isinstance(branches, list):
                for branch in branches[:50]:
                    visit(branch, path, name, depth + 1)
        for key in ("$defs", "definitions"):
            defs = node.get(key)
            if isinstance(defs, Mapping):
                for def_name, sub in defs.items():
                    visit(sub, f"#{def_name}", str(def_name), depth + 1)

    visit(schema, "", "", 0)
    return out


def listing_content(server_name: str, *, instructions: str | None, tools: Sequence[types.Tool]) -> str | None:
    """Server instructions and schema text: listing content the server scans besides the descriptions."""
    sections: list[str] = []
    if instructions and instructions.strip():
        sections.append(f"Instructions from MCP server {server_name}:\n{instructions}")
    for tool in tools:
        lines: list[str] = []
        if tool.title and _norm(tool.title) != _norm(tool.name):
            lines.append(f"title: {tool.title}")
        if (
            tool.annotations is not None
            and tool.annotations.title
            and _norm(tool.annotations.title) != _norm(tool.name)
        ):
            lines.append(f"annotation title: {tool.annotations.title}")
        lines.extend(schema_strings(tool.input_schema, tool.name))
        if lines:
            sections.append(f"Input schema text of tool {tool.name}:\n" + "\n".join(lines))
    return "\n\n".join(sections) or None


def tool_entry(tool: types.Tool) -> dict[str, Any]:
    description, omitted = fit_text(tool.description or "", MAX_DESCRIPTION_CHARS)
    entry: dict[str, Any] = {"name": tool.name, "description": description, "input_schema": tool.input_schema}
    if omitted:
        entry["description_truncated_chars"] = omitted
    if tool.title:
        entry["title"] = tool.title
    if tool.annotations is not None:
        entry["annotations"] = tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True)
    return entry


def listing_fingerprint(tools: Sequence[types.Tool], instructions: str | None = None) -> str:
    """Changes whenever a tool is added, removed or redescribed (e.g. a description swapped after approval)."""
    canonical = [
        {"name": t.name, "title": t.title, "description": t.description, "input_schema": t.input_schema}
        for t in sorted(tools, key=lambda t: t.name)
    ]
    payload = json.dumps({"tools": canonical, "instructions": instructions}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _chunks(entries: list[dict[str, Any]], budget: int) -> tuple[list[list[dict[str, Any]]], bool]:
    """Split entries so each chunk fits ``budget`` bytes; input schemas are dropped first if needed."""
    schemas_omitted = json_size(entries) > budget
    if schemas_omitted:
        entries = [{k: v for k, v in e.items() if k != "input_schema"} for e in entries]
    chunks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 2
    for entry in entries:
        entry_size = json_size(entry) + 1
        if current and (size + entry_size > budget or len(current) >= MAX_TOOLS_PER_EVENT):
            chunks.append(current)
            current, size = [], 2
        current.append(entry)
        size += entry_size
    chunks.append(current)
    return chunks, schemas_omitted


def server_connected_events(
    *,
    agent: AgentRef,
    session_id: str,
    server_name: str,
    tools: Sequence[types.Tool],
    instructions: str | None = None,
    server_info: Mapping[str, Any] | None = None,
    host: Mapping[str, Any] | None = None,
    budget: int = EVENT_BUDGET_BYTES,
) -> list[EventEnvelope]:
    """``mcp.server_connected`` event(s) carrying the full listing (split only when it is very large)."""
    content, content_omitted = (None, 0)
    raw_content = listing_content(server_name, instructions=instructions, tools=tools)
    if raw_content:
        content, content_omitted = fit_text(raw_content, MAX_TEXT_CHARS, budget // 4)
    chunk_budget = max(budget - json_size(content or "") - 8_000, 50_000)
    chunks, schemas_omitted = _chunks([tool_entry(t) for t in tools], chunk_budget)
    source = SourceRef(
        type=SourceType.MCP_SERVER,
        identifier=server_name,
        display_name=f"MCP server {server_name}"[:400],
        metadata={
            "transport": "stdio",
            **{k: v for k, v in (server_info or {}).items() if v not in (None, "")},
        },
    )
    base: dict[str, Any] = {
        "tool_count": len(tools),
        "listing_fingerprint": listing_fingerprint(tools, instructions),
    }
    if host:
        base["mcp_host"] = dict(host)
    if schemas_omitted:
        base["input_schemas_omitted"] = True
    if content_omitted:
        base["content_truncated_chars"] = content_omitted
    events: list[EventEnvelope] = []
    for index, chunk in enumerate(chunks):
        metadata = {**base, "tools": chunk}
        if len(chunks) > 1:
            metadata.update(listing_part=index + 1, listing_parts=len(chunks))
        events.append(
            EventEnvelope(
                event_type=EventType.MCP_SERVER_CONNECTED,
                agent=agent,
                session_id=session_id,
                integration=INTEGRATION,
                collected_via=COLLECTED_VIA,
                source=source,
                content=content if index == 0 else None,
                metadata=metadata,
            )
        )
    return events


# -- tool calls ------------------------------------------------------------------------------------


def tool_request_event(
    *,
    agent: AgentRef,
    session_id: str,
    server_name: str,
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    correlation_id: str,
    description: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """``tool.requested`` for ``POST /decide``. Raises ``ValueError`` when it cannot be built."""
    short = description[:TOOLREF_DESCRIPTION_CHARS] if description else None
    return EventEnvelope(
        event_type=EventType.TOOL_REQUESTED,
        agent=agent,
        session_id=session_id,
        correlation_id=correlation_id,
        integration=INTEGRATION,
        collected_via=COLLECTED_VIA,
        tool=ToolRef(
            name=tool_name, provider=provider_for(server_name), server=server_name, description=short
        ),
        arguments=dict(arguments or {}),
        metadata=dict(metadata or {}),
    )


def tool_result_event(
    request: EventEnvelope,
    *,
    text: str,
    is_error: bool,
    metadata: Mapping[str, Any] | None = None,
    max_chars: int = MAX_TEXT_CHARS,
) -> EventEnvelope:
    """``tool.completed`` (or ``tool.failed``) paired with ``request`` by correlation id."""
    fitted, omitted = fit_text(text, max_chars)
    meta = dict(metadata or {})
    if omitted:
        meta["result_truncated_chars"] = omitted
    return EventEnvelope(
        event_type=EventType.TOOL_FAILED if is_error else EventType.TOOL_COMPLETED,
        agent=request.agent,
        session_id=request.session_id,
        correlation_id=request.correlation_id,
        integration=INTEGRATION,
        collected_via=COLLECTED_VIA,
        tool=request.tool,
        result=fitted or None,
        is_error=is_error,
        metadata=meta,
    )


def context_event(
    *,
    agent: AgentRef,
    session_id: str,
    server_name: str,
    kind: str,
    name: str,
    text: str,
    content_type: str = "text/plain",
    metadata: Mapping[str, Any] | None = None,
    max_chars: int = MAX_TEXT_CHARS,
) -> EventEnvelope:
    """``context.ingested`` for what a resource read or prompt returned (observed, never blocked)."""
    fitted, omitted = fit_text(text, max_chars)
    meta: dict[str, Any] = {"kind": f"mcp_{kind}", **dict(metadata or {})}
    if omitted:
        meta["content_truncated_chars"] = omitted
    source = SourceRef(
        type=SourceType.MCP_SERVER,
        identifier=f"{server_name}/{kind}:{name}"[:2048],
        display_name=f"MCP {kind} {name} from {server_name}"[:400],
        metadata={"mcp_server": server_name, kind: name[:1000]},
    )
    return EventEnvelope(
        event_type=EventType.CONTEXT_INGESTED,
        agent=agent,
        session_id=session_id,
        integration=INTEGRATION,
        collected_via=COLLECTED_VIA,
        source=source,
        content=fitted,
        content_type=content_type[:64] or "text/plain",
        metadata=meta,
    )


__all__ = [
    "COLLECTED_VIA",
    "EVENT_BUDGET_BYTES",
    "INTEGRATION",
    "MAX_TEXT_CHARS",
    "blocked_result",
    "call_result_text",
    "content_text",
    "context_event",
    "fit_text",
    "json_size",
    "listing_content",
    "listing_fingerprint",
    "prompt_text",
    "provider_for",
    "resource_text",
    "schema_strings",
    "server_connected_events",
    "server_name_problem",
    "tool_entry",
    "tool_request_event",
    "tool_result_event",
]
