"""Agent sessions: report what an agent run consumed and did.

    with AgentSession(client) as session:
        session.prompt(user_request)
        session.ingest_context("web", url, page_text)
        send_email(...)            # a @guard-ed tool picks up this session automatically

``session.started`` / ``session.ended`` are emitted on enter/exit. Every event here is
*observed* (reported, not enforced); enforcement happens only in :mod:`contextos.guard`. Events are
non-blocking: if the server is unreachable they go to the offline spool, and other reporting
errors are logged as warnings instead of interrupting the agent.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from contextvars import ContextVar, Token
from typing import Any

from contextos.client import ContextOSClient, SendResult
from contextos.errors import ContextOSError
from contextos.models import (
    MAX_CONTENT_CHARS,
    AgentRef,
    DelegationRef,
    EventType,
    MessageRef,
    SourceRef,
    SourceType,
    new_session_id,
)

log = logging.getLogger("contextos.session")

_CURRENT: ContextVar[AgentSession | None] = ContextVar("contextos_current_session", default=None)
_TRUNCATION_MARKER = "\n[TRUNCATED by ContextOS SDK: {n} characters beyond the {limit}-character event limit]"


def current_session() -> AgentSession | None:
    """The innermost active :class:`AgentSession` in this thread / async task, if any."""
    return _CURRENT.get()


def _fit(content: str, metadata: dict[str, Any]) -> str:
    if len(content) <= MAX_CONTENT_CHARS:
        return content
    marker = _TRUNCATION_MARKER.format(n=len(content) - MAX_CONTENT_CHARS, limit=MAX_CONTENT_CHARS)
    metadata["content_truncated"] = True
    metadata["original_chars"] = len(content)
    return content[: MAX_CONTENT_CHARS - len(marker)] + marker


class AgentSession:
    """Context manager for one agent run (sync ``with`` or ``async with``)."""

    def __init__(
        self,
        client: ContextOSClient | None = None,
        *,
        session_id: str | None = None,
        parent_session_id: str | None = None,
        agent: AgentRef | None = None,
        metadata: dict[str, Any] | None = None,
        collected_via: str = "python_sdk.AgentSession",
    ) -> None:
        self.client = client or _default_client()
        self.session_id = session_id or new_session_id()
        self.parent_session_id = parent_session_id
        self.agent = agent or self.client.agent
        self.metadata = dict(metadata or {})
        self.collected_via = collected_via
        self._token: Token[AgentSession | None] | None = None
        self._started = False

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> SendResult | None:
        if self._started:
            return None
        self._started = True
        return self._emit(EventType.SESSION_STARTED, metadata=dict(self.metadata))

    def end(self, *, error: BaseException | None = None) -> SendResult | None:
        if not self._started:
            return None
        self._started = False
        meta: dict[str, Any] = {"outcome": "error" if error else "completed"}
        if error is not None:
            meta["error_type"] = type(error).__name__
        return self._emit(EventType.SESSION_ENDED, metadata=meta)

    def __enter__(self) -> AgentSession:
        self._token = _CURRENT.set(self)
        self.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object) -> None:
        try:
            self.end(error=exc)
        finally:
            if self._token is not None:
                _CURRENT.reset(self._token)
                self._token = None

    async def __aenter__(self) -> AgentSession:
        self._token = _CURRENT.set(self)
        await asyncio.to_thread(self.start)
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object
    ) -> None:
        try:
            await asyncio.to_thread(self.end, error=exc)
        finally:
            if self._token is not None:
                _CURRENT.reset(self._token)
                self._token = None

    # -- reporting ------------------------------------------------------------------------------

    def ingest_context(
        self,
        source_type: SourceType | str,
        identifier: str,
        content: str,
        *,
        display_name: str | None = None,
        content_type: str = "text/plain",
        metadata: dict[str, Any] | None = None,
    ) -> SendResult | None:
        """Report context entering the agent (web page, file, email, tool output, ...).

        ContextOS classifies the source's trust and scans the content for prompt injection and
        secrets server-side; nothing is decided here.
        """
        meta = dict(metadata or {})
        source = SourceRef(type=SourceType(source_type), identifier=identifier, display_name=display_name)
        return self._emit(
            EventType.CONTEXT_INGESTED,
            source=source,
            content=_fit(content, meta),
            content_type=content_type,
            metadata=meta,
        )

    def prompt(self, content: str, *, metadata: dict[str, Any] | None = None) -> SendResult | None:
        """Report a user/system prompt submitted to the agent."""
        meta = dict(metadata or {})
        return self._emit(EventType.PROMPT_SUBMITTED, content=_fit(content, meta), metadata=meta)

    def message(
        self,
        content: str,
        *,
        from_agent: str,
        from_session_id: str | None = None,
        to_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SendResult | None:
        """Report a message this agent received from another agent (cross-agent context)."""
        meta = dict(metadata or {})
        ref = MessageRef(
            from_agent=from_agent,
            from_session_id=from_session_id,
            to_agent=to_agent or self.agent.name,
            content=_fit(content, meta),
        )
        return self._emit(EventType.AGENT_MESSAGE, message=ref, metadata=meta)

    def delegate(
        self,
        child_agent: AgentRef | str,
        child_session_id: str | None = None,
        task: str | None = None,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Report that this session handed work to another agent. Returns the child session id."""
        child = (
            child_agent
            if isinstance(child_agent, AgentRef)
            else AgentRef(name=child_agent, framework=self.agent.framework)
        )
        child_id = child_session_id or new_session_id()
        task_text = task[:20_000] if task else None
        self._emit(
            EventType.AGENT_DELEGATED,
            delegation=DelegationRef(child_agent=child, child_session_id=child_id, task=task_text),
            metadata=dict(metadata or {}),
        )
        return child_id

    def child_session(self, child_agent: AgentRef | str, task: str | None = None) -> AgentSession:
        """Report a delegation and return the (not yet started) child :class:`AgentSession`."""
        child = (
            child_agent
            if isinstance(child_agent, AgentRef)
            else AgentRef(name=child_agent, framework=self.agent.framework)
        )
        child_id = self.delegate(child, task=task)
        return AgentSession(
            self.client,
            session_id=child_id,
            parent_session_id=self.session_id,
            agent=child,
            collected_via=self.collected_via,
        )

    def _emit(self, event_type: EventType, **fields: Any) -> SendResult | None:
        try:
            event = self.client.new_event(
                event_type,
                self.session_id,
                agent=self.agent,
                parent_session_id=self.parent_session_id,
                collected_via=self.collected_via,
                **fields,
            )
            return self.client.send_event(event)
        except ContextOSError as exc:
            log.warning("ContextOS could not record %s for session %s: %s", event_type, self.session_id, exc)
            return None


_DEFAULT_CLIENT: ContextOSClient | None = None
_DEFAULT_LOCK = threading.Lock()


def _default_client() -> ContextOSClient:
    """Process-wide client built from configuration (env > project file > user file)."""
    global _DEFAULT_CLIENT
    with _DEFAULT_LOCK:
        if _DEFAULT_CLIENT is None:
            _DEFAULT_CLIENT = ContextOSClient.from_config()
        return _DEFAULT_CLIENT


def set_default_client(client: ContextOSClient | None) -> None:
    """Override (or reset with ``None``) the client used when none is passed explicitly."""
    global _DEFAULT_CLIENT
    _DEFAULT_CLIENT = client


def get_default_client() -> ContextOSClient:
    return _default_client()


__all__ = ["AgentSession", "current_session", "get_default_client", "set_default_client"]
