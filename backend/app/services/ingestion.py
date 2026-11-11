"""The ingestion pipeline: the only entry points that turn integration events into security state.

    ingest_event(db, ctx, envelope) -> EventResult          # POST /events (observed), Simulation Lab
    decide_tool_request(db, ctx, envelope) -> DecisionResponse  # POST /decide (enforced / advisory)
    ingest_batch(db, ctx, events) -> list[EventResult]      # one SAVEPOINT per event

Steps (docs/ARCHITECTURE.md, "The ingestion pipeline"): validate (envelope, extra="forbid") →
authorise attribution (bound API keys) → idempotency on (org, client event id) → redact →
resolve entities → classify trust → detect → provenance → session risk → policy → findings and
incidents → persist the redacted event, audit, notify (after commit).

Failures: an exception while processing one event rolls back that event's SAVEPOINT and records
the (redacted) event with ``processing_status="error"`` — it is logged and visible, never silently
dropped. ``decide_tool_request`` then raises ``DecisionFailedError`` (HTTP 500) so the integration
applies its fail mode. Callers commit.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, PayloadTooLargeError, ValidationFailedError
from app.core.ids import new_id
from app.core.logging import get_logger
from app.core.security import sha256_hex
from app.core.timeutil import utcnow
from app.domain.enums import EventType
from app.engines.redaction import redact_text, redact_value
from app.events.envelope import DecisionResponse, EventEnvelope, EventResult
from app.models import Agent, Approval, IngestedEvent, Organization, PolicyDecision
from app.services.approvals import get_approval_status
from app.services.audit import append_audit
from app.services.bootstrap import effective_org_settings
from app.services.ingestion_entities import (
    find_session_by_external,
    resolve_agent,
    resolve_session,
    touch_integration,
)
from app.services.ingestion_handlers import (
    handle_context,
    handle_delegation,
    handle_mcp_connected,
    handle_message,
    handle_prompt,
)
from app.services.ingestion_identity import sanitize_identifiers
from app.services.ingestion_known_secrets import find_known, redact_known
from app.services.ingestion_results import handle_tool_result
from app.services.ingestion_risk import update_session_risk
from app.services.ingestion_state import (
    AttributionRejectedError,
    Caches,
    DecisionFailedError,
    IngestContext,
    PipelineState,
    bounded,
    raw_payload_json,
    raw_strings,
    redact_str,
    redacted_payload,
    safe_error_text,
    scrub_echoes,
)
from app.services.ingestion_tools import decide_request
from app.services.notify import notify
from app.services.org_counters import reserve

__all__ = [
    "AttributionRejectedError",
    "DecisionFailedError",
    "IngestContext",
    "decide_tool_request",
    "ingest_batch",
    "ingest_event",
]

log = get_logger(__name__)
_HANDLERS = {
    EventType.PROMPT_SUBMITTED: handle_prompt,
    EventType.CONTEXT_INGESTED: handle_context,
    EventType.AGENT_MESSAGE: handle_message,
    EventType.AGENT_DELEGATED: handle_delegation,
    EventType.MCP_SERVER_CONNECTED: handle_mcp_connected,
}


@dataclass
class _Outcome:
    result: EventResult
    row: IngestedEvent | None = None
    failed: bool = False


# -- public API ------------------------------------------------------------------------------------


def ingest_event(db: Session, ctx: IngestContext, envelope: EventEnvelope, *, _caches: Caches | None = None) -> EventResult:
    """Record one event as observed. Tool requests are evaluated and recorded with enforcement
    ``observed`` (no approval is opened: nobody is waiting on the decision)."""
    caches = _caches or Caches()
    outcome = _run(db, ctx, envelope, via_decide=False, caches=caches)
    if _caches is None:
        _flush_batch_notices(db, ctx, caches)
    return outcome.result


def ingest_batch(db: Session, ctx: IngestContext, events: list[EventEnvelope]) -> list[EventResult]:
    caches = Caches()
    limit = get_settings().max_event_bytes
    results: list[EventResult] = []
    for envelope in events:
        if len(raw_payload_json(envelope).encode()) > limit:
            results.append(EventResult(event_id=envelope.event_id, status="rejected",
                                       error=f"Event exceeds the {limit}-byte limit"))
            continue
        results.append(ingest_event(db, ctx, envelope, _caches=caches))
    _flush_batch_notices(db, ctx, caches)
    return results


def decide_tool_request(db: Session, ctx: IngestContext, envelope: EventEnvelope) -> DecisionResponse:
    """Synchronous decision for a ``tool.requested`` event. Duplicate event ids return the original
    decision (safe retry); approval status reflects its current state."""
    if envelope.event_type != EventType.TOOL_REQUESTED:
        raise ValidationFailedError("POST /decide accepts only tool.requested events",
                                    details={"event_type": str(envelope.event_type)})
    limit = get_settings().max_event_bytes  # same per-event limit as POST /events (also without Content-Length)
    if len(raw_payload_json(envelope).encode()) > limit:
        raise PayloadTooLargeError(f"Event exceeds the {limit}-byte limit")
    caches = Caches()
    outcome = _run(db, ctx, envelope, via_decide=True, caches=caches)
    result = outcome.result
    if result.status == "rejected":
        raise AttributionRejectedError(result.error or "Event rejected")
    if outcome.failed:
        raise DecisionFailedError("ContextOS could not evaluate this tool request; apply the configured fail mode",
                             details={"ingested_event_id": result.ingested_event_id})
    row = outcome.row
    assert row is not None
    if result.status == "duplicate":
        if row.processing_status == "error":
            raise DecisionFailedError("The original request with this event_id failed to process; send a new event_id",
                                 details={"ingested_event_id": row.id})
        if not (row.refs or {}).get("policy_decision_id"):
            raise ConflictError("This event_id was already used for an event that has no decision",
                                details={"ingested_event_id": row.id, "event_type": row.event_type})
    _flush_batch_notices(db, ctx, caches)
    return _decision_response(db, ctx.org_id, row)


# -- pipeline --------------------------------------------------------------------------------------


def _org(db: Session, caches: Caches, org_id: str) -> Organization:
    if caches.org is None:
        caches.org = db.execute(select(Organization).where(Organization.id == org_id)).scalar_one()
        caches.settings = effective_org_settings(caches.org)
    return caches.org


def _visible_to(ctx: IngestContext, row: IngestedEvent) -> bool:
    """Whether the submitter may see ``row`` as its own duplicate (agent-bound keys: only their agent)."""
    if not ctx.bound_agent_id:
        return True
    if row.agent_id is not None:
        return row.agent_id == ctx.bound_agent_id
    return row.api_key_id is not None and row.api_key_id == ctx.api_key_id  # failed before the agent was known


def _attribution_error(db: Session, ctx: IngestContext, envelope: EventEnvelope) -> str | None:
    if not ctx.bound_agent_id:
        return None
    bound = db.scalar(select(Agent).where(Agent.organization_id == ctx.org_id, Agent.id == ctx.bound_agent_id))
    if bound is not None and bound.name == envelope.agent.name:
        return None
    bound_name = bound.name if bound else ctx.bound_agent_id
    return (f"This API key is bound to agent '{bound_name}' and cannot report events for agent "
            f"'{envelope.agent.name}'. Use a key bound to that agent, or an unbound key.")


def _run(db: Session, ctx: IngestContext, env: EventEnvelope, *, via_decide: bool, caches: Caches) -> _Outcome:
    started = time.perf_counter()
    env = sanitize_identifiers(env)  # names and ids are stored and matched in redacted form
    _org(db, caches, ctx.org_id)  # loads the organisation's settings for this request
    existing = db.scalar(select(IngestedEvent).where(
        IngestedEvent.organization_id == ctx.org_id, IngestedEvent.client_event_id == env.event_id))
    problem = _attribution_error(db, ctx, env)
    if existing is not None and not problem and not _visible_to(ctx, existing):
        # A key bound to one agent re-used another agent's event id: never answer with that event's
        # references or decision (the id is unique per organisation, so it cannot be stored either).
        problem = "This event_id is already used by an event of another agent; send a new event_id."
    elif existing is not None:
        return _duplicate(existing)
    if problem:
        append_audit(
            db, ctx.org_id, action="ingest.attribution_rejected", actor_type=ctx.actor_type, actor_id=ctx.actor_id,
            target_type="api_key", target_id=ctx.api_key_id,
            details={"bound_agent_id": ctx.bound_agent_id, "reported_agent": redact_str(env.agent.name, limit=200),
                     "event_type": str(env.event_type), "client_event_id": env.event_id,
                     "reason": "event_id_of_another_agent" if existing is not None else "agent_mismatch"},
        )
        return _Outcome(EventResult(event_id=env.event_id, status="rejected", error=problem))

    # Reserve the sequence number OUTSIDE the savepoint: it is used by the processed row or by the
    # error row, and the write opens a real transaction before the SAVEPOINT on every backend.
    sequence = reserve(db, ctx.org_id, "event_seq")[0]  # atomic: concurrent requests never share a number
    now = utcnow()
    payload: dict[str, Any] | None = None
    try:
        with db.begin_nested():
            payload = redacted_payload(env, store_previews=bool(caches.settings.get("store_previews", True)))
            row = _new_row(ctx, env, sequence=sequence, now=now, payload=payload)
            db.add(row)
            db.flush()
            st = PipelineState(db=db, ctx=ctx, env=env, event=row, caches=caches, now=now, via_decide=via_decide)
            _process(st, started)
            _finalize(st, row)
    except IntegrityError:  # the savepoint rollback also dropped the notices this event queued
        again = db.scalar(select(IngestedEvent).where(
            IngestedEvent.organization_id == ctx.org_id, IngestedEvent.client_event_id == env.event_id))
        if again is not None:  # a concurrent request stored the same event first
            return _duplicate(again)
        raise
    except Exception as exc:  # noqa: BLE001 - recorded on the event and surfaced, never swallowed
        return _record_failure(db, ctx, env, sequence=sequence, now=now, payload=payload, exc=exc)
    _queue_notices(db, ctx, caches, st)
    return _Outcome(EventResult(event_id=env.event_id, status="accepted", ingested_event_id=row.id, refs=row.refs),
                    row=row)


def _new_row(ctx: IngestContext, env: EventEnvelope, *, sequence: int, now: Any, payload: dict[str, Any],
             status: str = "processed", error: str | None = None) -> IngestedEvent:
    return IngestedEvent(
        id=new_id("ingested_event"), organization_id=ctx.org_id, client_event_id=env.event_id,
        event_type=str(env.event_type), schema_version=env.schema_version, sequence=sequence,
        correlation_id=redact_str(env.correlation_id, limit=200), integration=(env.integration or None),
        occurred_at=env.timestamp, received_at=now, payload_redacted=payload,
        payload_hash=sha256_hex(raw_payload_json(env)), refs={}, processing_status=status,
        processing_error=error, api_key_id=ctx.api_key_id, is_simulation=ctx.is_simulation,
    )


def _process(st: PipelineState, started: float) -> None:
    env, db = st.env, st.db
    st.agent = resolve_agent(st, env.agent)
    parent = None
    if env.parent_session_id and env.parent_session_id != env.session_id:
        parent = find_session_by_external(db, st.ctx.org_id, env.parent_session_id)
    st.session = resolve_session(st, st.agent, env.session_id, parent=parent)
    integration = touch_integration(st, decision=st.via_decide)
    if integration is not None and st.agent.integration_id is None:
        st.agent.integration_id = integration.id
    session = st.session
    session.event_count = (session.event_count or 0) + 1
    session.last_event_at = st.now
    st.event.agent_id, st.event.session_id = st.agent.id, session.id

    event_type = env.event_type
    if event_type == EventType.SESSION_ENDED:
        session.status, session.ended_at = "ended", st.now
    elif session.status == "ended":
        session.status, session.ended_at = "active", None  # resumed (e.g. claude --resume)
    if event_type in (EventType.SESSION_STARTED, EventType.SESSION_ENDED) and env.metadata:
        redacted, _ = redact_value(env.metadata)
        session.session_metadata = bounded({**(session.session_metadata or {}), **redacted})

    if event_type == EventType.TOOL_REQUESTED:
        update_session_risk(st, view=decide_request(st, started=started).view)
        return
    if event_type in (EventType.TOOL_COMPLETED, EventType.TOOL_FAILED):
        handle_tool_result(st, started)
    elif event_type in _HANDLERS:
        _HANDLERS[event_type](st)
    update_session_risk(st)


def _finalize(st: PipelineState, row: IngestedEvent) -> None:
    refs = dict(st.refs)
    assert st.agent is not None and st.session is not None
    refs["agent_id"], refs["session_id"] = st.agent.id, st.session.id
    for single, many in (("context_item_id", "context_item_ids"), ("source_id", "source_ids")):
        if refs.get(many):
            refs[single] = refs[many][0]
    if refs.get("incident_ids"):
        refs["incident_ids"] = list(dict.fromkeys(refs["incident_ids"]))
    row.refs = refs
    # The stored payload was redacted before the session was known: remove any secret this session
    # saw earlier that appears here in a form no detector recognises (same placeholder as the engine).
    known = find_known(st, row.payload_redacted)
    if known:
        row.payload_redacted = redact_known(row.payload_redacted, known)
    st.db.flush()


def _duplicate(row: IngestedEvent) -> _Outcome:
    error = None
    if row.processing_status == "error":
        error = f"The original event failed to process: {row.processing_error or 'unknown error'}"
    return _Outcome(EventResult(event_id=row.client_event_id, status="duplicate", ingested_event_id=row.id,
                                error=error, refs=row.refs or {}), row=row)


def _record_failure(db: Session, ctx: IngestContext, env: EventEnvelope, *, sequence: int, now: Any,
                    payload: dict[str, Any] | None, exc: Exception) -> _Outcome:
    echoes = raw_strings(env)
    message = safe_error_text(exc, echo_sources=echoes)
    trace = scrub_echoes(redact_text("".join(traceback.format_exception(exc))).text[-8000:], echoes)
    if payload is None:  # redaction itself failed: keep only identifiers, never content
        payload = {"event_type": str(env.event_type), "session_id": env.session_id,
                   "agent": {"name": redact_str(env.agent.name, limit=200)}}
    row = _new_row(ctx, env, sequence=sequence, now=now, payload=payload, status="error", error=message)
    db.add(row)
    db.flush()
    log.error("ingestion.processing_failed", extra={
        "org_id": ctx.org_id, "ingested_event_id": row.id, "client_event_id": env.event_id,
        "event_type": str(env.event_type), "error": message, "trace": trace,
    })
    append_audit(db, ctx.org_id, action="ingest.processing_failed", actor_type=ctx.actor_type,
                 actor_id=ctx.actor_id, target_type="ingested_event", target_id=row.id,
                 details={"event_type": str(env.event_type), "error": message[:300]})
    return _Outcome(EventResult(event_id=env.event_id, status="accepted", ingested_event_id=row.id,
                                error=f"Event recorded but processing failed: {message}",
                                refs={"processing_status": "error"}), row=row, failed=True)


# -- notifications ---------------------------------------------------------------------------------


def _queue_notices(db: Session, ctx: IngestContext, caches: Caches, st: PipelineState) -> None:
    """Decision notices go out per event; sessions and agents are announced once per request."""
    assert st.agent is not None and st.session is not None
    if st.refs.get("policy_decision_id"):
        notify(db, ctx.org_id, "decision.made", id=st.refs["policy_decision_id"], decision=st.refs.get("decision"),
               session_id=st.session.id, tool_invocation_id=st.refs.get("tool_invocation_id"))
    caches.touched_sessions.setdefault(st.session.id, []).append(st.event.id)
    caches.touched_agents.add(st.agent.id)
    if st.refs.get("child_session_id"):
        caches.touched_sessions.setdefault(st.refs["child_session_id"], [])
    if st.refs.get("child_agent_id"):
        caches.touched_agents.add(st.refs["child_agent_id"])


def _flush_batch_notices(db: Session, ctx: IngestContext, caches: Caches) -> None:
    for session_id, event_ids in caches.touched_sessions.items():
        if event_ids:
            notify(db, ctx.org_id, "event.ingested", id=event_ids[-1], session_id=session_id, count=len(event_ids))
        notify(db, ctx.org_id, "session.updated", id=session_id)
    for agent_id in sorted(caches.touched_agents):
        notify(db, ctx.org_id, "agent.updated", id=agent_id)
    caches.touched_sessions.clear()
    caches.touched_agents.clear()


# -- decision responses ----------------------------------------------------------------------------


def _decision_response(db: Session, org_id: str, row: IngestedEvent) -> DecisionResponse:
    refs = row.refs or {}
    decision = db.scalar(select(PolicyDecision).where(
        PolicyDecision.organization_id == org_id, PolicyDecision.id == refs["policy_decision_id"]))
    assert decision is not None
    approval: Approval | None = None
    if refs.get("approval_id"):
        approval = get_approval_status(db, org_id, refs["approval_id"])
    return DecisionResponse(
        decision=decision.decision,
        enforcement=decision.enforcement,
        reason=decision.explanation,
        policy_decision_id=decision.id,
        tool_invocation_id=decision.tool_invocation_id or refs.get("tool_invocation_id") or "",
        approval_id=approval.id if approval else None,
        approval_status=approval.status if approval else None,
        matched_policies=list(decision.matched_policies or []),
        restrictions=dict(refs.get("restrictions") or {}),
        risk=dict(refs.get("risk") or {}),
    )
