"""``guard()``: enforce ContextOS policy decisions on Python tool functions.

    @guard("send_email", category_hint="email", destination="to")
    def send_email(to: str, subject: str, body: str) -> str: ...

Before every call the guard sends a ``tool.requested`` event to ``POST /decide`` and acts on the
answer. This is genuine enforcement — the wrapped function is never entered unless the decision
allows it — but it only covers tools invoked THROUGH the guard. Code that calls the underlying
API directly, or tools the agent framework runs itself, are not covered.

    ALLOW / AUDIT       run the function
    DENY                raise ToolDenied (function not run)
    REQUIRE_APPROVAL    poll the approval until decided or ``approval_timeout_s``; run only if
                        approved, else raise ToolDenied. ``approval_timeout_s=0`` raises
                        ApprovalRequired immediately so the host can wait asynchronously.
    RESTRICT            apply every restriction (see ``contextos.restrictions``) and run with the
                        restricted arguments; any restriction the SDK cannot apply → ToolDenied
                        (fail closed)
    anything else       ToolDenied (fail closed)

When the server cannot be reached (network error, timeout, 5xx) the fail mode decides:
``closed`` (default) → ToolDenied; ``open`` → run with a warning; ``ask`` → ApprovalRequired (the
host should ask its user). An invalid or under-scoped API key always fails closed. In every
fail-mode case the attempt is spooled so the server sees it later (as observed, not enforced).

After the call a ``tool.completed`` or ``tool.failed`` event reports the (truncated) result.
Reporting problems are logged and never change the tool's outcome.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import threading
import time
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from contextos._args import BoundCall, bind_call, destination_from, to_jsonable, truncate_result
from contextos.client import ContextOSClient, approval_status_of
from contextos.errors import (
    APIError,
    ApprovalRequired,
    ApprovalTimeout,
    AuthError,
    ContextOSError,
    ServerError,
    ToolDenied,
    Unreachable,
)
from contextos.models import (
    ApprovalStatus,
    Decision,
    DecisionResponse,
    DestinationRef,
    EventEnvelope,
    EventType,
    ToolCategory,
    ToolRef,
    new_correlation_id,
    new_session_id,
)
from contextos.restrictions import apply_restrictions, scan_reports_secrets
from contextos.session import current_session, get_default_client

log = logging.getLogger("contextos.guard")

F = TypeVar("F", bound=Callable[..., Any])
DestinationSpec = str | Callable[[dict[str, Any]], DestinationRef | str | None] | None

_IMPLICIT_SESSIONS: dict[int, str] = {}
_IMPLICIT_LOCK = threading.Lock()


def _implicit_session_id(client: ContextOSClient) -> str:
    """One session id per client for guarded calls made outside any AgentSession."""
    with _IMPLICIT_LOCK:
        return _IMPLICIT_SESSIONS.setdefault(id(client), new_session_id())


@dataclass
class Permit:
    """Permission to run one call, possibly with restricted arguments."""

    call: BoundCall
    envelope: EventEnvelope
    client: ContextOSClient
    decision: DecisionResponse | None
    fail_open: bool = False
    restrictions_applied: list[str] = field(default_factory=list)


class ToolGuard:
    """Policy enforcement for one tool. Use as a decorator, or call :meth:`run` / :meth:`arun`."""

    def __init__(
        self,
        tool_name: str | None = None,
        category_hint: ToolCategory | str | None = None,
        provider: str = "python_sdk",
        *,
        client: ContextOSClient | None = None,
        server: str | None = None,
        description: str | None = None,
        fail_mode: str | None = None,
        approval_timeout_s: float | None = None,
        poll_s: float = 2.0,
        path_args: Sequence[str] | None = None,
        destination: DestinationSpec = None,
        max_result_chars: int = 16_000,
    ) -> None:
        if fail_mode is not None and fail_mode not in ("closed", "open", "ask"):
            raise ValueError("fail_mode must be 'closed', 'open' or 'ask'")
        self.tool_name = tool_name
        self.category_hint = ToolCategory(category_hint) if category_hint else None
        self.provider = provider
        self.server = server
        self.description = description
        self._client = client
        self._fail_mode = fail_mode
        self._approval_timeout_s = approval_timeout_s
        self.poll_s = poll_s
        self.path_args = tuple(path_args) if path_args is not None else None
        self.destination = destination
        self.max_result_chars = max_result_chars

    # -- configuration --------------------------------------------------------------------------

    def _resolve_client(self) -> ContextOSClient:
        session = current_session()
        return self._client or (session.client if session else get_default_client())

    @property
    def fail_mode(self) -> str:
        if self._fail_mode:
            return self._fail_mode
        from contextos.config import load_config

        try:
            return load_config().fail_mode
        except ValueError:  # an unreadable config never weakens enforcement
            return "closed"

    @property
    def approval_timeout_s(self) -> float:
        if self._approval_timeout_s is not None:
            return self._approval_timeout_s
        from contextos.config import load_config

        try:
            return load_config().approval_timeout_s
        except ValueError:
            return 300.0

    # -- decorator ------------------------------------------------------------------------------

    def __call__(self, fn: F) -> F:
        if self.tool_name is None:
            self.tool_name = fn.__name__
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self.arun(fn, *args, **kwargs)

            async_wrapper.contextos_guard = self  # type: ignore[attr-defined]
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return self.run(fn, *args, **kwargs)

        wrapper.contextos_guard = self  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    def run(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        permit = self.authorize(bind_call(fn, args, kwargs))
        started = time.perf_counter()
        try:
            result = fn(*permit.call.args, **permit.call.kwargs)
        except Exception as exc:
            self.report(permit, error=exc, duration_ms=(time.perf_counter() - started) * 1000)
            raise
        self.report(permit, result=result, duration_ms=(time.perf_counter() - started) * 1000)
        return result

    async def arun(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        call = bind_call(fn, args, kwargs)
        permit = await asyncio.to_thread(self.authorize, call)
        started = time.perf_counter()
        try:
            result = await fn(*permit.call.args, **permit.call.kwargs)
        except Exception as exc:
            await asyncio.to_thread(self.report, permit, error=exc, duration_ms=(time.perf_counter() - started) * 1000)
            raise
        await asyncio.to_thread(self.report, permit, result=result, duration_ms=(time.perf_counter() - started) * 1000)
        return result

    # -- before the call ------------------------------------------------------------------------

    def _destination(self, arguments: dict[str, Any]) -> DestinationRef | None:
        spec = self.destination
        if spec is None:
            return None
        value = spec(arguments) if callable(spec) else arguments.get(spec)
        if isinstance(value, (list, tuple)):  # e.g. a recipient list: report the first
            value = value[0] if value else None
        return destination_from(value)

    def build_request(self, call: BoundCall, client: ContextOSClient) -> EventEnvelope:
        session = current_session()
        arguments = to_jsonable(call.arguments)
        return client.new_event(
            EventType.TOOL_REQUESTED,
            session.session_id if session else _implicit_session_id(client),
            agent=session.agent if session else client.agent,
            parent_session_id=session.parent_session_id if session else None,
            correlation_id=new_correlation_id(),
            collected_via="python_sdk.guard",
            tool=ToolRef(name=self.tool_name or "tool", provider=self.provider, server=self.server,
                         category_hint=self.category_hint, description=self.description),
            destination=self._destination(arguments),
            arguments=arguments,
        )

    def authorize(self, call: BoundCall) -> Permit:
        """Ask ContextOS whether ``call`` may run. Returns a :class:`Permit` or raises ToolDenied."""
        client = self._resolve_client()
        try:
            envelope = self.build_request(call, client)
        except ValueError as exc:  # e.g. an over-long tool name: no decision can be requested
            raise ToolDenied(f"the decision request could not be built ({exc.__class__.__name__}: "
                             f"{str(exc).splitlines()[0]}); failing closed", tool_name=self.tool_name) from None
        try:
            decision = client.decide(envelope)
        except (Unreachable, ServerError) as exc:
            return self._apply_fail_mode(exc, call, envelope, client)
        except AuthError as exc:
            raise ToolDenied(f"ContextOS rejected the API key ({exc.message}); failing closed",
                             tool_name=self.tool_name) from None
        except APIError as exc:
            raise ToolDenied(f"ContextOS could not evaluate this call ({exc.message}); failing closed",
                             tool_name=self.tool_name) from None
        return self._apply_decision(decision, call, envelope, client)

    def _apply_fail_mode(self, exc: ContextOSError, call: BoundCall, envelope: EventEnvelope,
                         client: ContextOSClient) -> Permit:
        mode = self.fail_mode
        what = "unreachable" if isinstance(exc, Unreachable) else "failing"
        self._record_unguarded(client, envelope, mode)
        if mode == "open":
            message = (f"ContextOS is {what} ({exc}); fail mode 'open' lets tool '{self.tool_name}' run "
                       "WITHOUT a policy decision")
            log.warning(message)
            warnings.warn(message, RuntimeWarning, stacklevel=4)
            return Permit(call, envelope, client, None, fail_open=True)
        if mode == "ask":
            raise ApprovalRequired(f"ContextOS is {what} ({exc}); fail mode 'ask' needs a human decision",
                                   tool_name=self.tool_name)
        raise ToolDenied(f"ContextOS is {what} ({exc}) and fail mode is 'closed'", tool_name=self.tool_name)

    def _record_unguarded(self, client: ContextOSClient, envelope: EventEnvelope, mode: str) -> None:
        """Spool the attempt so the server later sees it (as observed); same event id, so no duplicates."""
        metadata = {**envelope.metadata, "decision_unavailable": True, "fail_mode": mode,
                    "local_outcome": "ran_unguarded" if mode == "open" else "not_run"}
        try:
            client.spool_events([envelope.model_copy(update={"metadata": metadata})])
        except OSError as err:
            log.warning("Could not spool the unguarded tool attempt: %s", err)

    def _apply_decision(self, decision: DecisionResponse, call: BoundCall, envelope: EventEnvelope,
                        client: ContextOSClient) -> Permit:
        outcome = decision.decision.upper()
        if outcome in (Decision.ALLOW, Decision.AUDIT):
            return Permit(call, envelope, client, decision)
        if outcome == Decision.DENY:
            raise ToolDenied(decision.reason, decision, tool_name=self.tool_name)
        if outcome == Decision.REQUIRE_APPROVAL:
            self._await_approval(decision, client)
            return Permit(call, envelope, client, decision)
        if outcome == Decision.RESTRICT:
            return self._restrict(decision, call, envelope, client)
        raise ToolDenied(f"unrecognised decision '{decision.decision}'; failing closed", decision,
                         tool_name=self.tool_name)

    def _await_approval(self, decision: DecisionResponse, client: ContextOSClient) -> None:
        if (decision.approval_status or "").lower() == ApprovalStatus.APPROVED:
            return
        if not decision.approval_id:
            raise ToolDenied("approval is required but the server returned no approval id", decision,
                             tool_name=self.tool_name)
        timeout = self.approval_timeout_s
        if timeout <= 0:
            raise ApprovalRequired(f"approval required: {decision.reason}", decision, tool_name=self.tool_name,
                                   approval_id=decision.approval_id)
        log.info("Tool '%s' is waiting for approval %s (up to %.0fs)", self.tool_name, decision.approval_id, timeout)
        try:
            approval = client.wait_for_approval(decision.approval_id, timeout_s=timeout, poll_s=self.poll_s)
        except ApprovalTimeout:
            raise ToolDenied(f"no approval decision within {timeout:.0f}s (approval {decision.approval_id})",
                             decision, tool_name=self.tool_name) from None
        except ContextOSError as exc:  # auth / API errors while polling: fail closed
            raise ToolDenied(f"could not check approval {decision.approval_id} ({exc})", decision,
                             tool_name=self.tool_name) from None
        status = approval_status_of(approval)
        if status != ApprovalStatus.APPROVED:
            note = approval.get("decision_note") if isinstance(approval, dict) else None
            raise ToolDenied(f"approval {decision.approval_id} was {status or 'not granted'}"
                             + (f": {note}" if note else ""), decision, tool_name=self.tool_name)

    def _restrict(self, decision: DecisionResponse, call: BoundCall, envelope: EventEnvelope,
                  client: ContextOSClient) -> Permit:
        def verify(masked: dict[str, Any]) -> bool | None:
            text = json.dumps(to_jsonable(masked), ensure_ascii=False, default=str)
            found = scan_reports_secrets(client.scan(text, source_type="other"))
            return None if found is None else not found

        outcome = apply_restrictions(
            decision.restrictions,
            call.arguments,
            category_hint=self.category_hint.value if self.category_hint else None,
            path_args=self.path_args,
            verify_redaction=verify,
            jsonable=to_jsonable,
        )
        if not outcome.allowed:
            raise ToolDenied(f"{decision.reason} — {outcome.reason}", decision, tool_name=self.tool_name)
        return Permit(call.replace_arguments(outcome.arguments), envelope, client, decision,
                      restrictions_applied=outcome.applied)

    # -- after the call -------------------------------------------------------------------------

    def report(self, permit: Permit, *, result: Any = None, error: BaseException | None = None,
               duration_ms: float = 0.0) -> None:
        """Send tool.completed / tool.failed. Never raises; problems are logged."""
        request = permit.envelope
        metadata: dict[str, Any] = {"duration_ms": round(duration_ms, 1)}
        if permit.decision is not None:
            metadata["decision"] = permit.decision.decision
            metadata["policy_decision_id"] = permit.decision.policy_decision_id
        if permit.fail_open:
            metadata["ran_without_decision"] = True
        if permit.restrictions_applied:
            metadata["restrictions_applied"] = permit.restrictions_applied
        if error is not None:
            event_type, payload = EventType.TOOL_FAILED, f"{type(error).__name__}: {error}"
        else:
            event_type, payload = EventType.TOOL_COMPLETED, result
        try:
            event = permit.client.new_event(
                event_type, request.session_id, agent=request.agent, parent_session_id=request.parent_session_id,
                correlation_id=request.correlation_id, collected_via="python_sdk.guard", tool=request.tool,
                destination=request.destination, result=truncate_result(payload, self.max_result_chars),
                is_error=error is not None, metadata=metadata,
            )
            if permit.fail_open:  # the server was just unreachable: go straight to the spool
                permit.client.spool_events([event])
            else:
                permit.client.send_event(event)
        except (ContextOSError, OSError, ValueError) as exc:
            log.warning("Could not report %s for tool '%s': %s", event_type, self.tool_name, exc)


def guard(
    tool_name: str | Callable[..., Any] | None = None,
    category_hint: ToolCategory | str | None = None,
    provider: str = "python_sdk",
    **options: Any,
) -> Any:
    """Decorator factory: ``@guard("name", category_hint="http")``. Bare ``@guard`` uses the function name.

    Keyword options are those of :class:`ToolGuard` (``client``, ``fail_mode``, ``approval_timeout_s``,
    ``poll_s``, ``path_args``, ``destination``, ``server``, ``description``, ``max_result_chars``).
    """
    if callable(tool_name):
        return ToolGuard(None, category_hint, provider, **options)(tool_name)
    return ToolGuard(tool_name, category_hint, provider, **options)


__all__ = ["Permit", "ToolGuard", "guard"]
