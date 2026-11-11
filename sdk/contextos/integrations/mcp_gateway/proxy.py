"""MCP wiring: the downstream server the host connects to, backed by an upstream client session.

    host (Claude Code, ...) ──stdio──▶ Gateway (mcp Server) ──stdio──▶ upstream MCP server
                                          │
                                          └── ContextOS: /decide before every tools/call,
                                              /events for listings, results, resources, prompts

Every ``tools/call`` is decided by ContextOS BEFORE the upstream server is contacted (see
:mod:`.enforcement`). Reports of what came back are sent before the result is returned to the
host, so the decision on the agent's NEXT call already accounts for (for example) an injection in
this result. Reporting problems are logged and never change what the host receives.

Agent identity: ``--agent``, else ``CONTEXTOS_AGENT_NAME`` / config, else the host's MCP client name
(``clientInfo.name``, e.g. ``claude-code``), else ``mcp-client``. One gateway process is one session.

Not proxied (documented in docs/integrations/mcp.md): server-to-client requests from the upstream
server (sampling, elicitation, roots), resource subscriptions, logging levels, and the
2026-07-28 ``subscriptions/listen`` stream. Upstream ``list_changed`` notifications are relayed on
handshake-era connections.
"""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import anyio
import anyio.to_thread
import mcp.types as types
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from contextos._version import __version__
from contextos.client import ContextOSClient, SendResult
from contextos.errors import ContextOSError
from contextos.integrations.mcp_gateway.enforcement import (
    Enforcer,
    Verdict,
    WaitCallback,
    gateway_block_message,
)
from contextos.integrations.mcp_gateway.mapping import (
    COLLECTED_VIA,
    INTEGRATION,
    MAX_TEXT_CHARS,
    blocked_result,
    call_result_text,
    context_event,
    listing_fingerprint,
    prompt_text,
    resource_text,
    server_connected_events,
    tool_request_event,
    tool_result_event,
)
from contextos.models import AgentRef, EventEnvelope, EventType, new_correlation_id, new_session_id

log = logging.getLogger("contextos.mcp_gateway")

DEFAULT_AGENT_NAME = "mcp-client"
MAX_LISTING_PAGES = 100


@dataclass
class GatewaySettings:
    server_name: str
    agent_name: str | None = None
    session_id: str = field(default_factory=new_session_id)
    fail_mode: str = "closed"
    approval_timeout_s: float = 300.0
    poll_s: float = 2.0
    hide_blocked_tools: bool = False
    report_context: bool = True  # resources/read and prompts/get results as context.ingested
    max_result_chars: int = MAX_TEXT_CHARS


def host_info(ctx: Any) -> dict[str, str] | None:
    """The connecting host's MCP client name/version (handshake params or the 2026 request envelope)."""
    params = getattr(getattr(ctx, "session", None), "client_params", None)
    info = getattr(params, "client_info", None)
    name, version = (getattr(info, "name", None), getattr(info, "version", None)) if info else (None, None)
    if not name:
        raw = (getattr(ctx, "meta", None) or {}).get(types.CLIENT_INFO_META_KEY)
        if isinstance(raw, Mapping):
            name, version = raw.get("name"), raw.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    return {"name": name.strip()[:200], "version": str(version or "")[:64]}


def _page(params: types.PaginatedRequestParams | None) -> types.PaginatedRequestParams | None:
    """Forward the cursor only; the host's ``_meta`` belongs to the downstream connection."""
    return types.PaginatedRequestParams(cursor=params.cursor) if params is not None and params.cursor else None


class Gateway:
    """Handlers for the downstream MCP server; ``upstream`` is an initialized ``ClientSession``."""

    def __init__(
        self,
        upstream: Any,
        client: ContextOSClient,
        settings: GatewaySettings,
        *,
        upstream_info: types.InitializeResult | None = None,
        enforcer: Enforcer | None = None,
    ) -> None:
        self.upstream = upstream
        self.client = client
        self.settings = settings
        self.info = upstream_info
        self.enforcer = enforcer or Enforcer(client, fail_mode=settings.fail_mode,
                                             approval_timeout_s=settings.approval_timeout_s, poll_s=settings.poll_s)
        self._agent = AgentRef(name=settings.agent_name, framework="mcp") if settings.agent_name else None
        self._host: dict[str, str] | None = None
        self._downstream: Any = None  # a ServerSession: its standalone channel relays list_changed
        self._descriptions: dict[str, str | None] = {}
        self._reported_fingerprint: str | None = None
        self._server_blocked = False
        self._listing_lock = anyio.Lock()
        self._events_sent = 0

    # -- identity -------------------------------------------------------------------------------

    @property
    def capabilities(self) -> types.ServerCapabilities | None:
        return self.info.capabilities if self.info is not None else None

    @property
    def agent(self) -> AgentRef:
        return self._agent or AgentRef(name=DEFAULT_AGENT_NAME, framework="mcp")

    def _observe(self, ctx: Any) -> AgentRef:
        session = getattr(ctx, "session", None)
        if session is not None:
            self._downstream = session
        if self._host is None:
            self._host = host_info(ctx)
        if self._agent is None:
            host = self._host or {}
            self._agent = AgentRef(name=host.get("name") or DEFAULT_AGENT_NAME, framework="mcp",
                                   version=host.get("version") or None)
            self.client.agent = self._agent
        return self._agent

    def _server_info(self) -> dict[str, Any]:
        info = self.info.server_info if self.info is not None else None
        return {
            "server_name": info.name if info else None,
            "server_version": info.version if info else None,
            "protocol_version": self.info.protocol_version if self.info is not None else None,
        }

    # -- reporting ------------------------------------------------------------------------------

    async def _send(self, events: list[EventEnvelope]) -> SendResult | None:
        """Send events (spooled automatically while ContextOS is unreachable). Never raises."""
        try:
            result = await anyio.to_thread.run_sync(self.client.send_events, events)
        except (ContextOSError, OSError, ValueError) as exc:
            log.warning("Could not report %s to ContextOS: %s", events[0].event_type if events else "events", exc)
            return None
        self._events_sent += len(events)
        return result

    async def _spool(self, events: list[EventEnvelope]) -> None:
        try:
            await anyio.to_thread.run_sync(self.client.spool_events, events)
            self._events_sent += len(events)
        except OSError as exc:
            log.warning("Could not spool %d event(s): %s", len(events), exc)

    # -- tools ----------------------------------------------------------------------------------

    async def _fetch_tools(self) -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor: str | None = None
        for _ in range(MAX_LISTING_PAGES):
            page = await self.upstream.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
            tools.extend(page.tools)
            cursor = page.next_cursor
            if not cursor:
                break
        else:
            log.warning("Upstream MCP server '%s' returned more than %d pages of tools; the rest are not listed",
                        self.settings.server_name, MAX_LISTING_PAGES)
        self._descriptions = {t.name: t.description for t in tools}
        return tools

    async def _report_listing(self, tools: list[types.Tool]) -> None:
        instructions = self.info.instructions if self.info is not None else None
        fingerprint = listing_fingerprint(tools, instructions)
        async with self._listing_lock:
            if fingerprint == self._reported_fingerprint:
                return
            events = server_connected_events(
                agent=self.agent, session_id=self.settings.session_id, server_name=self.settings.server_name,
                tools=tools, instructions=instructions, server_info=self._server_info(), host=self._host,
            )
            result = await self._send(events)
            if result is None:
                return  # not recorded: try again on the next listing
            if self._reported_fingerprint is not None:
                log.warning("Upstream MCP server '%s' changed its tool listing; the new listing was reported to "
                            "ContextOS for scanning", self.settings.server_name)
            self._reported_fingerprint = fingerprint
            poisoned = sum(len(r.refs.get("poisoned_tool_ids") or []) for r in result.results)
            if poisoned:
                log.warning("ContextOS detected possible tool poisoning in %d tool description(s) of MCP server '%s'",
                            poisoned, self.settings.server_name)
            if self.settings.hide_blocked_tools and result.results:
                self._server_blocked = await self._is_server_blocked(result)

    async def _is_server_blocked(self, result: SendResult) -> bool:
        """The server's trust classification of this MCP server after the listing, from the
        ``mcp.server_connected`` result (``refs.source_trust_level``): no extra request, no read scope."""
        level = next((r.refs.get("source_trust_level") for r in result.results if r.refs.get("source_trust_level")),
                     None)
        if not level:
            log.debug("ContextOS returned no trust level for MCP server '%s'; its tools stay listed",
                      self.settings.server_name)
            return self._server_blocked
        blocked = str(level).upper() == "BLOCKED"
        if blocked:
            log.warning("ContextOS classifies MCP server '%s' as BLOCKED; its tools are hidden from the host",
                        self.settings.server_name)
        return blocked

    async def _ensure_listing(self) -> None:
        """Report the tool listing even if the host never asks for it (instructions are scanned too)."""
        caps = self.capabilities
        if self._reported_fingerprint is None and (caps is None or caps.tools is not None):
            try:
                await self._report_listing(await self._fetch_tools())
            except MCPError as exc:
                log.warning("Could not list the upstream tools for ContextOS: %s", exc.message)

    async def list_tools(self, ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        self._observe(ctx)
        tools = await self._fetch_tools()
        await self._report_listing(tools)
        return types.ListToolsResult(tools=[] if self._server_blocked else tools)

    async def call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        agent = self._observe(ctx)
        # A host may call a tool it listed on an earlier connection: report this server's listing
        # first, so its descriptions are scanned and the server's trust applies to this decision.
        await self._ensure_listing()
        name = params.name
        try:
            request = tool_request_event(
                agent=agent, session_id=self.settings.session_id, server_name=self.settings.server_name,
                tool_name=name, arguments=params.arguments, correlation_id=new_correlation_id(),
                description=self._descriptions.get(name),
                metadata={"mcp_host": self._host} if self._host else None,
            )
        except ValueError as exc:  # first line only: validation details can echo argument values
            log.warning("tools/call %s blocked: the decision request could not be built", name)
            return blocked_result(gateway_block_message(
                f"the decision request could not be built ({str(exc).splitlines()[0]}); failing closed"))
        verdict = await self.enforcer.authorize(request, on_wait=self._wait_reporter(ctx))
        log.info("tools/call %s: %s", name, verdict.outcome)
        if not verdict.allowed:
            return blocked_result(verdict.message)
        return await self._forward(ctx, request, verdict)

    async def _forward(self, ctx: Any, request: EventEnvelope, verdict: Verdict) -> types.CallToolResult:
        assert request.tool is not None
        started = time.perf_counter()
        try:
            result = await self.upstream.call_tool(request.tool.name, verdict.arguments,
                                                   progress_callback=self._progress_relay(ctx))
        except MCPError as exc:
            await self._report_result(request, verdict, f"MCP error {exc.code}: {exc.message}", True, started)
            raise
        except anyio.get_cancelled_exc_class():
            raise
        except Exception as exc:
            await self._report_result(request, verdict, f"{type(exc).__name__}: {exc}", True, started)
            raise MCPError(types.INTERNAL_ERROR, f"The upstream MCP server '{self.settings.server_name}' failed "
                                                 f"to run the tool ({type(exc).__name__})") from None
        await self._report_result(request, verdict, call_result_text(result), result.is_error, started)
        return result

    async def _report_result(self, request: EventEnvelope, verdict: Verdict, text: str, is_error: bool,
                             started: float) -> None:
        metadata: dict[str, Any] = {"duration_ms": round((time.perf_counter() - started) * 1000, 1)}
        if verdict.decision is not None:
            metadata["decision"] = verdict.decision.decision
            metadata["policy_decision_id"] = verdict.decision.policy_decision_id
        if verdict.fail_open:
            metadata["ran_without_decision"] = True
        if verdict.restrictions_applied:
            metadata["restrictions_applied"] = verdict.restrictions_applied
        event = tool_result_event(request, text=text, is_error=is_error, metadata=metadata,
                                  max_chars=self.settings.max_result_chars)
        if verdict.fail_open:  # ContextOS was just unreachable: go straight to the spool
            await self._spool([event])
        else:
            await self._send([event])

    @staticmethod
    def _progress_relay(ctx: Any) -> Any:
        session = getattr(ctx, "session", None)
        if session is None:
            return None

        async def relay(progress: float, total: float | None, message: str | None) -> None:
            try:
                await session.report_progress(progress, total, message)
            except Exception as exc:  # noqa: BLE001 - progress is a courtesy
                log.debug("Could not relay progress to the MCP host: %s", exc)

        return relay

    @staticmethod
    def _wait_reporter(ctx: Any) -> WaitCallback | None:
        session = getattr(ctx, "session", None)
        if session is None:
            return None

        async def report(elapsed: float, total: float, message: str) -> None:
            await session.report_progress(elapsed, total, message)

        return report

    # -- resources and prompts (pass-through, reported as context) -------------------------------

    async def _report_context(self, kind: str, name: str, text: str, content_type: str,
                              metadata: dict[str, Any]) -> None:
        if not self.settings.report_context or not text.strip():
            return
        await self._send([context_event(
            agent=self.agent, session_id=self.settings.session_id, server_name=self.settings.server_name,
            kind=kind, name=name, text=text, content_type=content_type, metadata=metadata,
            max_chars=self.settings.max_result_chars,
        )])

    async def list_resources(self, ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListResourcesResult:
        self._observe(ctx)
        await self._ensure_listing()
        return await self.upstream.list_resources(params=_page(params))

    async def list_resource_templates(self, ctx: Any,
                                      params: types.PaginatedRequestParams | None) -> types.ListResourceTemplatesResult:
        self._observe(ctx)
        return await self.upstream.list_resource_templates(params=_page(params))

    async def read_resource(self, ctx: Any, params: types.ReadResourceRequestParams) -> types.ReadResourceResult:
        self._observe(ctx)
        result = await self.upstream.read_resource(params.uri)
        mime = next((c.mime_type for c in result.contents if c.mime_type), None) or "text/plain"
        await self._report_context("resource", params.uri, resource_text(result), mime,
                                   {"content_blocks": len(result.contents)})
        return result

    async def list_prompts(self, ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListPromptsResult:
        self._observe(ctx)
        await self._ensure_listing()
        return await self.upstream.list_prompts(params=_page(params))

    async def get_prompt(self, ctx: Any, params: types.GetPromptRequestParams) -> types.GetPromptResult:
        self._observe(ctx)
        result = await self.upstream.get_prompt(params.name, params.arguments)
        # Argument names only: their values are the user's input and are not needed to scan the prompt.
        await self._report_context("prompt", params.name, prompt_text(result), "text/plain",
                                   {"argument_names": sorted(params.arguments or {})})
        return result

    async def complete(self, ctx: Any, params: types.CompleteRequestParams) -> types.CompleteResult:
        self._observe(ctx)
        context = params.context.arguments if params.context is not None else None
        return await self.upstream.complete(params.ref, params.argument.model_dump(), context_arguments=context)

    # -- upstream notifications -----------------------------------------------------------------

    async def on_upstream_message(self, message: Any) -> None:
        if isinstance(message, Exception):
            log.warning("The upstream MCP server sent a message the gateway could not read (%s)", type(message).__name__)
            return
        downstream = self._downstream
        if downstream is None:
            return
        try:
            if isinstance(message, types.ToolListChangedNotification):
                await downstream.send_tool_list_changed()
            elif isinstance(message, types.ResourceListChangedNotification):
                await downstream.send_resource_list_changed()
            elif isinstance(message, types.PromptListChangedNotification):
                await downstream.send_prompt_list_changed()
        except Exception as exc:  # noqa: BLE001 - a relay failure must not break the upstream session
            log.debug("Could not relay %s to the MCP host: %s", type(message).__name__, exc)

    # -- server ---------------------------------------------------------------------------------

    def build_server(self) -> Server[Any]:
        """The downstream server: the same name, tools, resources and prompts as the upstream."""
        caps = self.capabilities
        handlers: dict[str, Any] = {}
        if caps is None or caps.tools is not None:
            handlers.update(on_list_tools=self.list_tools, on_call_tool=self.call_tool)
        if caps is not None and caps.resources is not None:
            handlers.update(on_list_resources=self.list_resources, on_read_resource=self.read_resource,
                            on_list_resource_templates=self.list_resource_templates)
        if caps is not None and caps.prompts is not None:
            handlers.update(on_list_prompts=self.list_prompts, on_get_prompt=self.get_prompt)
        if caps is not None and caps.completions is not None:
            handlers["on_completion"] = self.complete
        info = self.info.server_info if self.info is not None else None
        return Server(
            self.settings.server_name, version=info.version if info else "", title=info.title if info else None,
            description=info.description if info else None,
            instructions=self.info.instructions if self.info is not None else None, **handlers,
        )

    def initialization_options(self, server: Server[Any]) -> InitializationOptions:
        caps = self.capabilities
        return server.create_initialization_options(NotificationOptions(
            tools_changed=bool(caps and caps.tools and caps.tools.list_changed),
            resources_changed=bool(caps and caps.resources and caps.resources.list_changed),
            prompts_changed=bool(caps and caps.prompts and caps.prompts.list_changed),
        ))

    async def close(self) -> None:
        """Report the end of the session (best effort, bounded) if anything was reported."""
        if not self._events_sent:
            return
        event = EventEnvelope(
            event_type=EventType.SESSION_ENDED, agent=self.agent, session_id=self.settings.session_id,
            integration=INTEGRATION, collected_via=COLLECTED_VIA,
            metadata={"outcome": "completed", "reason": "mcp_host_disconnected"},
        )
        with anyio.move_on_after(5, shield=True):
            await self._send([event])


class _Relay:
    """Upstream notification handler bound to the gateway once it exists."""

    def __init__(self) -> None:
        self.target: Gateway | None = None

    async def __call__(self, message: Any) -> None:
        if self.target is not None:
            await self.target.on_upstream_message(message)


async def serve_stdio(settings: GatewaySettings, upstream: StdioServerParameters, client: ContextOSClient, *,
                      startup_timeout_s: float = 60.0) -> None:
    """Start the upstream server, then serve the host on this process's stdin/stdout until it disconnects."""
    relay = _Relay()
    async with stdio_client(upstream, errlog=sys.stderr) as (read, write):
        async with ClientSession(read, write, message_handler=relay,
                                 client_info=types.Implementation(name="contextos-mcp-gateway",
                                                                  version=__version__)) as session:
            with anyio.fail_after(startup_timeout_s):
                info = await session.initialize()
            gateway = Gateway(session, client, settings, upstream_info=info)
            relay.target = gateway
            server = gateway.build_server()
            upstream_label = " ".join(p for p in (info.server_info.name, info.server_info.version) if p)
            log.info("Serving MCP server '%s' (upstream %s) for session %s; tools/call decided by ContextOS at %s "
                     "(fail mode %s)", settings.server_name, upstream_label or "unnamed", settings.session_id,
                     client.base_url, settings.fail_mode)
            try:
                async with stdio_server() as (server_read, server_write):
                    await server.run(server_read, server_write, gateway.initialization_options(server))
            finally:
                await gateway.close()


__all__ = ["DEFAULT_AGENT_NAME", "Gateway", "GatewaySettings", "host_info", "serve_stdio"]
