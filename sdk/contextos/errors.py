"""Typed SDK errors.

Hierarchy::

    ContextOSError
    ├── Unreachable        the server could not be reached (network error, timeout, 502/503/504)
    ├── APIError           the server answered with an error envelope (status, code, message)
    │   ├── AuthError      401/403: invalid, revoked or under-scoped API key
    │   └── ServerError    500 and other 5xx: the server failed while processing the request
    ├── ApprovalTimeout    an approval was still pending when the client stopped waiting
    └── ToolDenied         a guarded tool was NOT executed (see ``reason`` and ``decision``)
        └── ApprovalRequired  a human decision is needed before the tool may run

Messages never contain API keys or raw tool arguments.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contextos.models import DecisionResponse


class ContextOSError(Exception):
    """Base class for every error raised by the SDK."""


class Unreachable(ContextOSError):  # noqa: N818 - public SDK names
    """The ContextOS server could not be reached (or answered with a gateway/unavailable status)."""


class APIError(ContextOSError):
    """The server returned an error response (uniform ``{"error": {code, message, details}}`` envelope)."""

    def __init__(self, status_code: int, code: str, message: str, details: Any = None) -> None:
        super().__init__(f"{message} (HTTP {status_code}, {code})")
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


class AuthError(APIError):
    """The API key is missing, invalid, revoked, or lacks the scope this call needs."""


class ServerError(APIError):
    """The server failed while handling the request (HTTP 5xx other than gateway errors)."""


class ApprovalTimeout(ContextOSError):  # noqa: N818 - public SDK names
    """The approval was still pending when ``wait_for_approval`` gave up."""

    def __init__(self, approval_id: str, waited_s: float, last_status: str | None = None) -> None:
        super().__init__(f"Approval {approval_id} was not decided within {waited_s:.0f}s")
        self.approval_id = approval_id
        self.waited_s = waited_s
        self.last_status = last_status


class ToolDenied(ContextOSError):  # noqa: N818 - public SDK names
    """Raised by :func:`contextos.guard` when a tool call is not allowed to run.

    The wrapped function has NOT been executed when this is raised.
    """

    def __init__(
        self,
        reason: str,
        decision: DecisionResponse | None = None,
        *,
        tool_name: str | None = None,
    ) -> None:
        prefix = f"Tool '{tool_name}' was not run: " if tool_name else "Tool was not run: "
        super().__init__(prefix + reason)
        self.reason = reason
        self.decision = decision
        self.tool_name = tool_name


class ApprovalRequired(ToolDenied):
    """A human must decide before the tool may run.

    Raised when the server could not be reached and the fail mode is ``ask`` (``approval_id`` is
    ``None``: the host application should ask its user), or when a REQUIRE_APPROVAL decision cannot
    be waited for. Subclasses :class:`ToolDenied`, so code that only handles denials stays safe.
    """

    def __init__(
        self,
        reason: str,
        decision: DecisionResponse | None = None,
        *,
        tool_name: str | None = None,
        approval_id: str | None = None,
    ) -> None:
        super().__init__(reason, decision, tool_name=tool_name)
        self.approval_id = approval_id


__all__ = [
    "APIError",
    "ApprovalRequired",
    "ApprovalTimeout",
    "AuthError",
    "ContextOSError",
    "ServerError",
    "ToolDenied",
    "Unreachable",
]
