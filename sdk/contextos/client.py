"""HTTP client for the ContextOS API (``/api/v1``). Talks HTTP only; never imports server code.

Retry policy (exponential backoff, ``max_retries`` extra attempts):
- ``POST /events`` and every GET: retried on network errors, timeouts and 429/502/503/504 — safe
  because event ids are idempotency keys and reads have no side effects.
- ``POST /decide``: retried only when the connection could not be opened (the request never left),
  so a decision is never requested twice.

Errors: :class:`~contextos.errors.Unreachable` (network / gateway), :class:`AuthError` (401/403),
:class:`ServerError` (5xx), :class:`APIError` (other 4xx). Non-blocking events fall back to the
offline spool when the server is unreachable; decisions never do.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx

from contextos._read_api import ReadAPIMixin
from contextos._version import __version__
from contextos.config import Config, load_config, mask_key
from contextos.errors import APIError, ApprovalTimeout, AuthError, ContextOSError, ServerError, Unreachable
from contextos.models import (
    AgentRef,
    ApprovalStatus,
    DecisionResponse,
    EventEnvelope,
    EventResult,
    EventType,
)
from contextos.spool import Spool

log = logging.getLogger("contextos.client")

API_PREFIX = "/api/v1"
MAX_BATCH_EVENTS = 500
MAX_BATCH_BYTES = 1_900_000  # the server rejects request bodies above ~2 MB
_GATEWAY_STATUSES = {502, 503, 504}
_RETRY_STATUSES = {429, *_GATEWAY_STATUSES}
RetryPolicy = Literal["all", "connect", "none"]


@dataclass
class SendResult:
    """Outcome of :meth:`ContextOSClient.send_events`."""

    results: list[EventResult] = field(default_factory=list)
    spooled: list[str] = field(default_factory=list)  # event ids stored offline for a later re-send

    @property
    def accepted(self) -> int:
        return sum(1 for r in self.results if r.status == "accepted")

    @property
    def rejected(self) -> list[EventResult]:
        return [r for r in self.results if r.status == "rejected"]


def default_agent_ref(config: Config | None = None) -> AgentRef:
    """Agent identity: configured ``agent_name`` or the running script's name."""
    name = config.agent_name if config and config.agent_name else None
    if not name:
        script = Path(sys.argv[0]).stem if sys.argv and sys.argv[0] not in ("", "-c") else ""
        name = script or "python-agent"
    return AgentRef(name=name[:200], framework="python_sdk", environment=config.environment if config else None)


def _normalise_base_url(url: str) -> str:
    url = url.strip().rstrip("/")
    return url[: -len(API_PREFIX)] if url.endswith(API_PREFIX) else url


def _error_from_response(response: httpx.Response) -> APIError:
    code, message, details = "http_error", f"Request failed with HTTP {response.status_code}", None
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        err = body["error"]
        code = str(err.get("code") or code)
        message = str(err.get("message") or message)
        details = err.get("details")
    elif isinstance(body, dict) and isinstance(body.get("detail"), str):
        message = body["detail"]
    status = response.status_code
    if status in (401, 403):
        return AuthError(status, code, message, details)
    if status >= 500:
        return ServerError(status, code, message, details)
    return APIError(status, code, message, details)


class ContextOSClient(ReadAPIMixin):
    """Synchronous, thread-safe ContextOS client.

    >>> client = ContextOSClient("http://localhost:8000", "ctxk_...", agent=AgentRef(name="billing-bot"))
    >>> client.health()
    {'status': 'ok'}
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        timeout: float = 5.0,
        agent: AgentRef | None = None,
        *,
        integration: str = "python_sdk",
        spool: Spool | bool = True,
        spool_max_bytes: int | None = None,
        max_retries: int = 2,
        backoff_s: float = 0.25,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = _normalise_base_url(base_url)
        self._api_key = api_key
        self.timeout = timeout
        self.agent = agent or default_agent_ref()
        self.integration = integration
        self.max_retries = max(0, max_retries)
        self.backoff_s = backoff_s
        self._sleep = sleep
        self._clock = clock
        self._outage_reported = False
        if spool is True:
            kwargs = {"max_bytes": spool_max_bytes} if spool_max_bytes else {}
            self.spool: Spool | None = Spool.for_agent(self.agent.name, **kwargs)
        else:
            self.spool = spool or None
        self._http = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 3.0)),
            transport=transport,
            headers={"User-Agent": f"contextos-python/{__version__}", "Accept": "application/json"},
            follow_redirects=False,
        )

    @classmethod
    def from_config(cls, config: Config | None = None, **overrides: Any) -> ContextOSClient:
        cfg = config or load_config()
        overrides.setdefault("agent", default_agent_ref(cfg))
        overrides.setdefault("timeout", cfg.timeout_s)
        overrides.setdefault("spool_max_bytes", cfg.spool_max_bytes)
        return cls(cfg.url, cfg.api_key, **overrides)

    def __repr__(self) -> str:  # never include the key
        return f"ContextOSClient(base_url={self.base_url!r}, api_key={mask_key(self._api_key)!r}, agent={self.agent.name!r})"

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ContextOSClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport ------------------------------------------------------------------------------

    def _send_raw(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None,
                  retry: RetryPolicy = "all", auth: bool = True) -> httpx.Response:
        headers: dict[str, str] = {}
        if auth:
            if not self._api_key:
                raise AuthError(401, "no_api_key", "No API key configured: set CONTEXTOS_API_KEY or run `contextos init`")
            headers["Authorization"] = f"Bearer {self._api_key}"
        url = self.base_url + API_PREFIX + path
        clean_params = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        attempt = 0
        while True:
            try:
                response = self._http.request(method, url, json=json_body, params=clean_params or None, headers=headers)
            except httpx.TransportError as exc:
                retryable = retry == "all" or (retry == "connect" and isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)))
                if retryable and attempt < self.max_retries:
                    self._backoff(attempt)
                    attempt += 1
                    continue
                raise Unreachable(f"Cannot reach ContextOS at {self.base_url} ({type(exc).__name__})") from None
            if response.status_code in _RETRY_STATUSES and retry == "all" and attempt < self.max_retries:
                self._backoff(attempt, response.headers.get("Retry-After"))
                attempt += 1
                continue
            log.debug("%s %s -> %s", method, path, response.status_code)
            return response

    def _backoff(self, attempt: int, retry_after: str | None = None) -> None:
        delay = self.backoff_s * (2**attempt)
        if retry_after and retry_after.isdigit():
            delay = min(max(delay, float(retry_after)), 30.0)
        self._sleep(delay)

    def _request(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None,
                 retry: RetryPolicy = "all", auth: bool = True) -> Any:
        response = self._send_raw(method, path, json_body=json_body, params=params, retry=retry, auth=auth)
        if response.status_code in _GATEWAY_STATUSES:
            raise Unreachable(f"ContextOS at {self.base_url} is unavailable (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise _error_from_response(response)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise APIError(response.status_code, "invalid_response", "Server returned a non-JSON response") from None

    # -- events ---------------------------------------------------------------------------------

    def new_event(self, event_type: EventType | str, session_id: str, **fields: Any) -> EventEnvelope:
        """Build an envelope stamped with this client's agent, integration, id and timestamp."""
        fields.setdefault("agent", self.agent)
        fields.setdefault("integration", self.integration)
        return EventEnvelope(event_type=EventType(event_type), session_id=session_id, **fields)

    def send_event(self, event: EventEnvelope | dict[str, Any], *, spool: bool = True) -> SendResult:
        return self.send_events([event], spool=spool)

    def send_events(self, events: Iterable[EventEnvelope | dict[str, Any]], *, spool: bool = True) -> SendResult:
        """POST events in batches (<= 500 events, < 2 MB). Unreachable server → spooled (if enabled)."""
        wire = [e.to_wire() if isinstance(e, EventEnvelope) else dict(e) for e in events]
        outcome = SendResult()
        batches = list(_batches(wire))
        for index, batch in enumerate(batches):
            try:
                outcome.results.extend(self._post_batch(batch))
            except Unreachable:
                if not spool or self.spool is None:
                    raise
                pending = [e for b in batches[index:] for e in b]
                try:
                    stored = self.spool.append(pending)
                except OSError as exc:
                    log.warning("ContextOS unreachable and the spool at %s could not be written (%s): "
                                "%d event(s) not recorded", self.spool.path, exc.strerror or exc, len(pending))
                    return outcome
                outcome.spooled.extend(e["event_id"] for e in pending[:stored])
                # Warn once per outage; later spooled events are logged at debug level.
                level = logging.DEBUG if self._outage_reported else logging.WARNING
                log.log(level, "ContextOS unreachable: %d event(s) spooled to %s; they are re-sent automatically "
                        "after the next successful send", stored, self.spool.path)
                self._outage_reported = True
                return outcome
        self._outage_reported = False
        for rejected in outcome.rejected:
            log.warning("ContextOS rejected event %s: %s", rejected.event_id, rejected.error)
        if outcome.results:
            self._flush_spool_quietly()
        return outcome

    def _post_batch(self, batch: list[dict[str, Any]]) -> list[EventResult]:
        try:
            data = self._request("POST", "/events", json_body={"events": batch}, retry="all")
        except APIError as exc:
            if exc.status_code not in (413, 422) or isinstance(exc, (AuthError, ServerError)):
                raise
            if len(batch) == 1:  # isolate a poison event instead of blocking the rest
                return [EventResult(event_id=str(batch[0].get("event_id")), status="rejected", error=exc.message)]
            middle = len(batch) // 2
            return self._post_batch(batch[:middle]) + self._post_batch(batch[middle:])
        results = data.get("results", []) if isinstance(data, dict) else []
        return [EventResult.model_validate(r) for r in results]

    def spool_events(self, events: Iterable[EventEnvelope | dict[str, Any]]) -> int:
        """Store events offline without trying the network (used right after a failed decision)."""
        wire = [e.to_wire() if isinstance(e, EventEnvelope) else dict(e) for e in events]
        if self.spool is None:
            log.warning("ContextOS unreachable and spooling is disabled: %d event(s) not recorded", len(wire))
            return 0
        return self.spool.append(wire)

    def flush_spool(self) -> int:
        """Re-send spooled events now. Returns how many the server acknowledged."""
        if self.spool is None:
            return 0
        return self.spool.flush(lambda batch: [r.event_id for r in self._post_batch(batch)])

    def _flush_spool_quietly(self) -> None:
        if self.spool is None or not self.spool.path.parent.exists():
            return
        if not self.spool.path.exists() and not any(self.spool.path.parent.glob(self.spool.path.name + ".*.flushing")):
            return
        try:
            delivered = self.flush_spool()
            if delivered:
                log.info("Re-sent %d spooled event(s) to ContextOS", delivered)
        except (ContextOSError, OSError) as exc:
            log.warning("Could not flush the ContextOS spool: %s", exc)

    # -- decisions ------------------------------------------------------------------------------

    def decide(self, envelope: EventEnvelope) -> DecisionResponse:
        """Ask for a policy decision on a ``tool.requested`` event. Never spooled."""
        if envelope.event_type != EventType.TOOL_REQUESTED:
            raise ValueError("decide() only accepts tool.requested events")
        data = self._request("POST", "/decide", json_body=envelope.to_wire(), retry="connect")
        return DecisionResponse.model_validate(data)

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        return self._request("GET", f"/decide/approvals/{quote(approval_id, safe='')}")

    def wait_for_approval(self, approval_id: str, timeout_s: float = 300.0, poll_s: float = 2.0) -> dict[str, Any]:
        """Poll until the approval leaves ``pending``; returns the approval. Raises :class:`ApprovalTimeout`."""
        deadline = self._clock() + timeout_s
        last_status: str | None = None
        while True:
            try:
                approval = self.get_approval(approval_id)
                last_status = approval_status_of(approval)
                if last_status and last_status != ApprovalStatus.PENDING:
                    return approval
            except Unreachable as exc:  # transient: keep waiting until the deadline
                log.info("Approval poll failed (%s); retrying", exc)
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise ApprovalTimeout(approval_id, timeout_s, last_status)
            self._sleep(min(poll_s, remaining))

    # -- utilities ------------------------------------------------------------------------------

    def scan(self, content: str, source_type: str | None = None) -> dict[str, Any]:
        """Run detection on ``content`` without persisting anything (``POST /scan``)."""
        body: dict[str, Any] = {"content": content}
        if source_type:
            body["source_type"] = source_type
        return self._request("POST", "/scan", json_body=body, retry="all")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health", auth=False)

    def probe_scopes(self) -> dict[str, bool | None]:
        """Which scopes the key has, using requests that cannot change state.

        ``read``: ``GET /agents?limit=1``. ``ingest`` / ``decide``: an empty body, which the server
        authorises first and then rejects with 422 — so 422 proves the scope, 403 disproves it.
        ``None`` means the endpoint did not answer conclusively. Raises :class:`AuthError` for an
        invalid key.
        """
        probes: Sequence[tuple[str, str, str, Any]] = (
            ("read", "GET", "/agents", None),
            ("ingest", "POST", "/events", {"events": []}),
            ("decide", "POST", "/decide", {}),
        )
        scopes: dict[str, bool | None] = {}
        for scope, method, path, body in probes:
            params = {"limit": 1} if method == "GET" else None
            response = self._send_raw(method, path, json_body=body, params=params, retry="none")
            if response.status_code == 401:
                raise _error_from_response(response)
            if response.status_code == 403:
                scopes[scope] = False
            elif response.status_code < 300 or response.status_code == 422:
                scopes[scope] = True
            else:
                scopes[scope] = None
        return scopes


def approval_status_of(approval: Any) -> str | None:
    """Lower-cased status from an approval payload (``status`` or ``approval_status``)."""
    if not isinstance(approval, dict):
        return None
    raw = approval.get("status") or approval.get("approval_status")
    return str(raw).lower() if raw else None


def _batches(events: list[dict[str, Any]]) -> Iterable[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    size = 0
    for event in events:
        event_size = len(json.dumps(event, separators=(",", ":"), default=str))
        if batch and (len(batch) >= MAX_BATCH_EVENTS or size + event_size > MAX_BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(event)
        size += event_size
    if batch:
        yield batch


__all__ = ["API_PREFIX", "MAX_BATCH_EVENTS", "ContextOSClient", "SendResult", "approval_status_of", "default_agent_ref"]
