"""ContextOS Python SDK.

- :class:`ContextOSClient` — HTTP client for the ContextOS API (events, decisions, approvals, scan).
- :class:`AgentSession` — report what an agent run consumes (context, prompts, messages, delegation).
- :func:`guard` / :class:`ToolGuard` — enforce policy decisions on Python tool functions.

Configuration resolves from ``CONTEXTOS_*`` environment variables, then ``.contextos/config.json``
(searched upward from the working directory), then ``~/.contextos/config.json``. The SDK talks to
the server over HTTP only.
"""

from contextos._version import __version__
from contextos.client import ContextOSClient, SendResult
from contextos.config import Config, load_config, mask_key
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
from contextos.guard import ToolGuard, guard
from contextos.models import (
    AgentRef,
    DecisionResponse,
    DelegationRef,
    DestinationRef,
    EventEnvelope,
    EventResult,
    EventType,
    MessageRef,
    SourceRef,
    SourceType,
    ToolCategory,
    ToolRef,
)
from contextos.session import AgentSession, current_session, set_default_client

__all__ = [
    "APIError",
    "AgentRef",
    "AgentSession",
    "ApprovalRequired",
    "ApprovalTimeout",
    "AuthError",
    "Config",
    "ContextOSClient",
    "ContextOSError",
    "DecisionResponse",
    "DelegationRef",
    "DestinationRef",
    "EventEnvelope",
    "EventResult",
    "EventType",
    "MessageRef",
    "SendResult",
    "ServerError",
    "SourceRef",
    "SourceType",
    "ToolCategory",
    "ToolDenied",
    "ToolGuard",
    "ToolRef",
    "Unreachable",
    "__version__",
    "current_session",
    "guard",
    "load_config",
    "mask_key",
    "set_default_client",
]
