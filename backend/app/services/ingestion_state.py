"""Shared state, errors and redaction helpers for the ingestion pipeline (``app.services.ingestion``).

Everything here is in-memory bookkeeping for ONE event: the resolved entities, the references the
event produced and the raw secret values seen in its content. Raw values never leave this object:
they exist only so detection excerpts can be scrubbed of secret fragments before persistence.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.security import sha256_hex
from app.domain.enums import EventType
from app.engines.policy import PolicySpec
from app.engines.redaction import SecretMatch, redact_text, redact_value
from app.engines.trust import TrustRuleSpec
from app.events.envelope import EventEnvelope
from app.models import Agent, AgentSession, IngestedEvent, Integration, Organization
from app.services.ingestion_config import policy_specs, trust_rule_specs

# Integrations that return the decision at a real execution boundary that honours it.
ENFORCING_INTEGRATIONS = frozenset({"claude_code", "mcp_gateway", "openai_codex", "python_sdk"})
DEFAULT_INTEGRATION = "custom"

_SCRUB_MIN_FRAGMENT = 6
_SCRUB_MARK = "[REDACTED]"
_MAX_PAYLOAD_STRING = 2000
_MAX_PAYLOAD_ITEMS = 200
_MAX_PAYLOAD_DEPTH = 12
_ECHO_WINDOW = 16
_ECHO_MARK = "[EVENT CONTENT REMOVED]"


class AttributionRejectedError(AppError):
    """An API key bound to one agent tried to report events for another agent."""

    status_code = 403
    code = "attribution_rejected"


class DecisionFailedError(AppError):
    """The pipeline failed while deciding; the integration applies its configured fail mode."""

    status_code = 500
    code = "decision_failed"


@dataclass
class IngestContext:
    """Who is submitting events. Built from the authenticated principal (or by the Simulation Lab)."""

    org_id: str
    actor_type: str  # "api_key" | "user" | "system"
    actor_id: str | None = None
    api_key_id: str | None = None
    bound_agent_id: str | None = None
    is_simulation: bool = False
    simulation_run_id: str | None = None


@dataclass
class Caches:
    """Per-request caches of org configuration (shared by every event of one batch)."""

    org: Organization | None = None
    settings: dict[str, Any] | None = None
    policies: list[PolicySpec] | None = None
    source_rules: list[TrustRuleSpec] | None = None
    destination_rules: list[TrustRuleSpec] | None = None
    integrations: dict[str, Integration] = field(default_factory=dict)
    # Live-update notices buffered for the whole request: session id -> ingested event ids, agent ids.
    touched_sessions: dict[str, list[str]] = field(default_factory=dict)
    touched_agents: set[str] = field(default_factory=set)


@dataclass
class PipelineState:
    db: Session
    ctx: IngestContext
    env: EventEnvelope
    event: IngestedEvent
    caches: Caches
    now: datetime
    via_decide: bool = False
    agent: Agent | None = None
    session: AgentSession | None = None
    refs: dict[str, Any] = field(default_factory=dict)
    raw_secrets: list[str] = field(default_factory=list)  # in memory only; never persisted
    # session id -> {fingerprint: (secret type, context item id)} of high-confidence secrets seen in
    # that session's context (see ingestion_known_secrets); dropped when new secrets are recorded.
    known_fingerprints: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)

    # -- configuration ----------------------------------------------------------------------------

    @property
    def org(self) -> Organization:
        assert self.caches.org is not None
        return self.caches.org

    @property
    def settings(self) -> dict[str, Any]:
        assert self.caches.settings is not None
        return self.caches.settings

    @property
    def store_previews(self) -> bool:
        return bool(self.settings.get("store_previews", True))

    def policies(self) -> list[PolicySpec]:
        if self.caches.policies is None:
            self.caches.policies = policy_specs(self.db, self.ctx.org_id)
        return self.caches.policies

    def source_rules(self) -> list[TrustRuleSpec]:
        if self.caches.source_rules is None:
            self.caches.source_rules = trust_rule_specs(self.db, self.ctx.org_id, "source")
        return self.caches.source_rules

    def destination_rules(self) -> list[TrustRuleSpec]:
        if self.caches.destination_rules is None:
            self.caches.destination_rules = trust_rule_specs(self.db, self.ctx.org_id, "destination")
        return self.caches.destination_rules

    @property
    def integration_kind(self) -> str:
        return integration_kind(self.env)

    @property
    def enforcement(self) -> str:
        """Honest enforcement claim for a decision on this event (see docs/ARCHITECTURE.md)."""
        if not self.via_decide:
            return "observed"
        return "enforced" if self.integration_kind in ENFORCING_INTEGRATIONS else "advisory"

    # -- references --------------------------------------------------------------------------------

    def add_ref(self, key: str, value: str) -> None:
        values = self.refs.setdefault(key, [])
        if value not in values:
            values.append(value)

    def remember_secrets(self, raw: str, matches: list[SecretMatch]) -> None:
        for m in matches:
            value = raw[m.start : m.end]
            if len(value) >= _SCRUB_MIN_FRAGMENT and value not in self.raw_secrets:
                self.raw_secrets.append(value)

    def remember_raw(self, values: list[str]) -> None:
        for value in values:
            if len(value) >= _SCRUB_MIN_FRAGMENT and value not in self.raw_secrets:
                self.raw_secrets.append(value)

    def scrub(self, text: str | None) -> str | None:
        """Remove any fragment (>= 6 chars) of a raw secret seen in this event from ``text``.

        Detection excerpts are cut around a match, so a secret straddling the cut can survive
        redaction as a partial string; this closes that gap.
        """
        return scrub_fragments(text, self.raw_secrets)


def integration_kind(env: EventEnvelope) -> str:
    kind = (env.integration or "").strip().lower()
    return kind[:48] if kind else DEFAULT_INTEGRATION


# -- redaction helpers -----------------------------------------------------------------------------


def scrub_fragments(text: str | None, secrets: list[str]) -> str | None:
    if not text or not secrets:
        return text
    out = text
    for secret in secrets:
        for _ in range(8):  # bounded: each pass removes one fragment
            matcher = difflib.SequenceMatcher(None, out, secret, autojunk=False)
            match = matcher.find_longest_match(0, len(out), 0, len(secret))
            if match.size < _SCRUB_MIN_FRAGMENT:
                break
            out = out[: match.a] + _SCRUB_MARK + out[match.a + match.size :]
    return out


def redact_str(value: str | None, *, limit: int | None = None) -> str | None:
    if value is None:
        return None
    text = redact_text(value).text
    if limit is not None and len(text) > limit:
        text = text[: max(limit - 1, 0)] + "…"
    return text


def preview_of(redacted: str, chars: int | None = None) -> str:
    chars = chars or get_settings().preview_chars
    return redacted if len(redacted) <= chars else redacted[: max(chars - 1, 0)] + "…"


def result_text(result: Any) -> tuple[str, str]:
    """(text, content_type) of a tool result as the agent sees it."""
    if result is None:
        return "", "text/plain"
    if isinstance(result, str):
        return result, "text/plain"
    return json.dumps(result, ensure_ascii=False, sort_keys=True, default=str), "application/json"


def text_digest(raw: str | None, *, store_previews: bool) -> dict[str, Any] | None:
    """What the event log keeps of context text: hash + length (+ redacted preview if enabled)."""
    if raw is None:
        return None
    digest: dict[str, Any] = {"sha256": sha256_hex(raw), "length": len(raw)}
    if store_previews:
        digest["preview"] = preview_of(redact_text(raw).text)
    return digest


def bounded(value: Any, depth: int = 0) -> Any:
    """Cap string lengths, list sizes and nesting of an (already redacted) JSON value."""
    if isinstance(value, str):
        return value if len(value) <= _MAX_PAYLOAD_STRING else value[: _MAX_PAYLOAD_STRING - 1] + "…"
    if depth >= _MAX_PAYLOAD_DEPTH and isinstance(value, dict | list):
        return "[TRUNCATED: nested too deeply]"
    if isinstance(value, dict):
        items = list(value.items())
        out = {str(k): bounded(v, depth + 1) for k, v in items[:_MAX_PAYLOAD_ITEMS]}
        if len(items) > _MAX_PAYLOAD_ITEMS:
            out["_truncated_keys"] = len(items) - _MAX_PAYLOAD_ITEMS
        return out
    if isinstance(value, list):
        out_list = [bounded(v, depth + 1) for v in value[:_MAX_PAYLOAD_ITEMS]]
        if len(value) > _MAX_PAYLOAD_ITEMS:
            out_list.append(f"[TRUNCATED: {len(value) - _MAX_PAYLOAD_ITEMS} more items]")
        return out_list
    return value


def raw_payload_json(env: EventEnvelope) -> str:
    return json.dumps(env.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), default=str)


def redacted_payload(env: EventEnvelope, *, store_previews: bool) -> dict[str, Any]:
    """The event as persisted: context text reduced to digests, everything else redacted and bounded."""
    data = env.model_dump(mode="json", exclude_none=True)
    if env.content is not None:
        data["content"] = text_digest(env.content, store_previews=store_previews)
    if env.result is not None:
        data["result"] = text_digest(result_text(env.result)[0], store_previews=store_previews)
    if env.message is not None:
        data["message"]["content"] = text_digest(env.message.content, store_previews=store_previews)
    if env.delegation is not None and env.delegation.task is not None:
        data["delegation"]["task"] = text_digest(env.delegation.task, store_previews=store_previews)
    if env.event_type == EventType.MCP_SERVER_CONNECTED and isinstance(data.get("metadata"), dict):
        tools = data["metadata"].get("tools")
        if isinstance(tools, list):
            data["metadata"]["tools"] = [_tool_listing_digest(t, store_previews) for t in tools[:_MAX_PAYLOAD_ITEMS]]
    redacted, _ = redact_value(data)
    return bounded(redacted)


def _tool_listing_digest(tool: Any, store_previews: bool) -> Any:
    if not isinstance(tool, dict):
        return tool
    out = {k: v for k, v in tool.items() if k not in ("description", "inputSchema", "input_schema")}
    desc = tool.get("description")
    if isinstance(desc, str):
        out["description"] = text_digest(desc, store_previews=store_previews)
    return out


def safe_error_text(exc: BaseException, limit: int = 1000, *, echo_sources: list[str] | None = None) -> str:
    """Exception text for persistence: redacted, stripped of echoed event content, truncated."""
    message = redact_str(f"{type(exc).__name__}: {exc}") or type(exc).__name__
    message = scrub_echoes(message, echo_sources or [])
    return message if len(message) <= limit else message[: limit - 1] + "…"


def raw_strings(env: EventEnvelope) -> list[str]:
    """Every client-supplied text value of an event (content, results, arguments, metadata...)."""
    out: list[str] = []
    _string_leaves(env.model_dump(mode="json", exclude_none=True), out, 0)
    return out


def _string_leaves(value: Any, out: list[str], depth: int) -> None:
    if depth > _MAX_PAYLOAD_DEPTH * 2 or len(out) > 10_000:
        return
    if isinstance(value, str):
        if len(value) >= _ECHO_WINDOW:
            out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _string_leaves(key, out, depth + 1)
            _string_leaves(item, out, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _string_leaves(item, out, depth + 1)


def scrub_echoes(text: str, sources: list[str], *, window: int | None = None) -> str:
    """Replace every span of ``text`` that repeats ``window``+ consecutive characters of a source.

    Exception messages and tracebacks often echo the input being processed; on the failure path
    this keeps raw context content (which may hold secrets no detector recognises) out of storage
    and logs. Linear in the size of the sources (one pass of ``window``-grams).
    """
    size = window or _ECHO_WINDOW
    if not text or len(text) < size or not sources:
        return text
    grams: dict[str, list[int]] = {}
    for i in range(len(text) - size + 1):
        grams.setdefault(text[i : i + size], []).append(i)
    covered = bytearray(len(text))
    for source in sources:
        for j in range(len(source) - size + 1):
            for i in grams.get(source[j : j + size], ()):
                covered[i : i + size] = b"\x01" * size
    if not any(covered):
        return text
    parts: list[str] = []
    i = 0
    while i < len(text):
        if covered[i]:
            while i < len(text) and covered[i]:
                i += 1
            parts.append(_ECHO_MARK)
        else:
            parts.append(text[i])
            i += 1
    return "".join(parts)
