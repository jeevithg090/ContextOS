"""Redaction of the identifiers an event carries (names and ids), before anything is stored or matched.

Content, arguments and results are redacted by the pipeline itself. Identifiers are different: they are
matched as keys (agent by name, session by external id, tool by name, idempotency by event id,
correlation of a request with its result), so they cannot be truncated or replaced at random. The
redaction engine's placeholder is deterministic (``[REDACTED:<type>:<keyed fingerprint>]``): the same
raw value always becomes the same stored value, so every match keeps working, while a credential
pasted into an identifier is never persisted, logged, audited or shown. Identifiers in which no secret
is recognised are returned unchanged (the common case costs one scan per field and no copy).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.engines.redaction import redact_text
from app.events.envelope import EventEnvelope

_TOP_LEVEL = ("event_id", "session_id", "parent_session_id", "correlation_id", "integration", "collected_via")
_AGENT = ("name", "framework", "version", "environment")
_TOOL = ("name", "provider", "server")
_MESSAGE = ("from_agent", "from_session_id", "to_agent")


def redact_identifier(value: str | None) -> str | None:
    """``value`` with any recognised secret replaced by its deterministic placeholder."""
    if not value:
        return value
    return redact_text(value).text


def _changes(model: BaseModel, fields: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in fields:
        value = getattr(model, name)
        if isinstance(value, str):
            clean = redact_identifier(value)
            if clean != value:
                out[name] = clean
    return out


def _copy(model: BaseModel | None, fields: tuple[str, ...]) -> BaseModel | None:
    if model is None:
        return None
    changes = _changes(model, fields)
    return model.model_copy(update=changes) if changes else model


def sanitize_identifiers(env: EventEnvelope) -> EventEnvelope:
    """The envelope with every identifier redacted (the same object when nothing changed)."""
    updates = _changes(env, _TOP_LEVEL)
    agent = _copy(env.agent, _AGENT)
    if agent is not env.agent:
        updates["agent"] = agent
    tool = _copy(env.tool, _TOOL)
    if tool is not env.tool:
        updates["tool"] = tool
    if env.delegation is not None:
        child = _copy(env.delegation.child_agent, _AGENT)
        changes = _changes(env.delegation, ("child_session_id",))
        if child is not env.delegation.child_agent:
            changes["child_agent"] = child
        if changes:
            updates["delegation"] = env.delegation.model_copy(update=changes)
    message = _copy(env.message, _MESSAGE)
    if message is not env.message:
        updates["message"] = message
    return env.model_copy(update=updates) if updates else env
