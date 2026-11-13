"""Execute a scenario's steps through the real ingestion pipeline.

Every event is built as an :class:`EventEnvelope` and submitted with an :class:`IngestContext`
flagged ``is_simulation=True`` — so the rows the pipeline writes (sessions, context items, decisions,
findings, approvals, incidents) carry the simulation flag and the run id. Tool requests go through
``decide_tool_request`` as the configured enforcing integration would send them; nothing is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.core.timeutil import utcnow
from app.domain.enums import EventType, SourceType
from app.events.envelope import EventEnvelope
from app.models import ToolInvocation
from app.services.ingestion import IngestContext, decide_tool_request, ingest_event
from app.services.ingestion_entities import find_session_by_external
from app.simulations.model import (
    CHILD,
    ChildReply,
    ContextRead,
    Delegate,
    McpListing,
    RunVars,
    Scenario,
    StepOutcome,
    ToolCall,
    resolve_args,
    resolve_text,
)

log = get_logger(__name__)

# Decisions under which a simulated enforcing integration lets the call run.
_RUNS = frozenset({"ALLOW", "AUDIT"})


@dataclass
class Actors:
    agent_name: str
    framework: str
    version: str | None
    main_session: str
    child_agent: str | None = None
    child_session: str | None = None


@dataclass
class Execution:
    outcomes: dict[str, StepOutcome] = field(default_factory=dict)
    session_ids: list[str] = field(default_factory=list)
    error: str | None = None


class _Builder:
    def __init__(self, run_id: str, actors: Actors) -> None:
        self.run_id = run_id
        self.actors = actors
        self.counter = 0

    def envelope(self, event_type: EventType, *, actor: str = "main", **fields: Any) -> EventEnvelope:
        self.counter += 1
        a = self.actors
        if actor == CHILD:
            agent = {"name": a.child_agent, "framework": "simulation"}
            session, parent = a.child_session, a.main_session
        else:
            agent = {"name": a.agent_name, "framework": a.framework, "version": a.version}
            session, parent = a.main_session, None
        integration = fields.pop("integration", "claude_code")
        return EventEnvelope.model_validate({
            "event_id": f"{self.run_id}-{self.counter:03d}",
            "event_type": event_type.value,
            "timestamp": utcnow(),
            "agent": {k: v for k, v in agent.items() if v is not None},
            "session_id": session,
            "parent_session_id": parent,
            "integration": integration,
            "collected_via": f"simulation_lab:{event_type.value}",
            **fields,
        })


def execute(db: Any, ctx: IngestContext, scenario: Scenario, actors: Actors, rv: RunVars) -> Execution:
    """Submit every step in order. A pipeline failure stops the run (recorded as ``error``)."""
    b = _Builder(ctx.simulation_run_id or "sim", actors)
    out = Execution()
    used_child = False
    ingest(db, ctx, b.envelope(EventType.SESSION_STARTED, metadata={"simulation_scenario": scenario.id}))
    for step in scenario.steps:
        try:
            outcome = _run_step(db, ctx, b, step, rv)
        except Exception as exc:  # recorded on the run and logged; the run is marked failed
            log.warning("simulation step failed", extra={"scenario": scenario.id, "step": step.label,
                                                          "error_type": type(exc).__name__})
            out.outcomes[step.label] = StepOutcome(label=step.label, kind=type(step).__name__,
                                                   error=f"{type(exc).__name__}: {getattr(exc, 'message', '')}"[:300])
            out.error = f"Step '{step.label}' could not be processed by the pipeline ({type(exc).__name__})."
            break
        out.outcomes[step.label] = outcome
        used_child = used_child or isinstance(step, Delegate) or getattr(step, "actor", None) == CHILD
    if used_child:
        ingest(db, ctx, b.envelope(EventType.SESSION_ENDED, actor=CHILD))
    ingest(db, ctx, b.envelope(EventType.SESSION_ENDED))
    for external in (actors.main_session, actors.child_session):
        if not external:
            continue
        session = find_session_by_external(db, ctx.org_id, external)
        if session is not None and session.simulation_run_id == ctx.simulation_run_id:
            out.session_ids.append(session.id)
    return out


def ingest(db: Any, ctx: IngestContext, envelope: EventEnvelope) -> dict[str, Any]:
    result = ingest_event(db, ctx, envelope)
    if result.status == "rejected":
        raise ValueError(result.error or "event rejected")
    return dict(result.refs or {})


def _run_step(db: Any, ctx: IngestContext, b: _Builder, step: Any, rv: RunVars) -> StepOutcome:
    if isinstance(step, ToolCall):
        return _tool_call(db, ctx, b, step, rv)
    if isinstance(step, ContextRead):
        refs = ingest(db, ctx, b.envelope(
            EventType.CONTEXT_INGESTED, actor=step.actor,
            source={"type": step.source_type, "identifier": step.identifier},
            content=resolve_text(step.content, rv), content_type=step.content_type))
        return StepOutcome(label=step.label, kind="context", refs=refs, session_id=refs.get("session_id"))
    if isinstance(step, McpListing):
        refs = ingest(db, ctx, b.envelope(
            EventType.MCP_SERVER_CONNECTED, integration="mcp_gateway",
            source={"type": SourceType.MCP_SERVER.value, "identifier": step.server},
            metadata={"tools": [{"name": n, "description": d} for n, d in step.tools]}))
        return StepOutcome(label=step.label, kind="mcp_listing", refs=refs, session_id=refs.get("session_id"))
    if isinstance(step, Delegate):
        refs = ingest(db, ctx, b.envelope(
            EventType.AGENT_DELEGATED,
            delegation={"child_agent": {"name": b.actors.child_agent, "framework": "simulation"},
                        "child_session_id": b.actors.child_session, "task": step.task}))
        return StepOutcome(label=step.label, kind="delegation", refs=refs, session_id=refs.get("session_id"))
    if isinstance(step, ChildReply):
        refs = ingest(db, ctx, b.envelope(
            EventType.AGENT_MESSAGE,
            message={"from_agent": b.actors.child_agent, "from_session_id": b.actors.child_session,
                     "to_agent": b.actors.agent_name, "content": resolve_text(step.content, rv) or ""}))
        return StepOutcome(label=step.label, kind="agent_message", refs=refs, session_id=refs.get("session_id"))
    raise TypeError(f"unknown step type {type(step).__name__}")


def _tool_call(db: Any, ctx: IngestContext, b: _Builder, step: ToolCall, rv: RunVars) -> StepOutcome:
    arguments = resolve_args(step.arguments, rv)
    tool = {"name": step.tool, "provider": step.provider, **({"server": step.server} if step.server else {})}
    correlation = f"{b.run_id}-{step.label}"[:200]
    response = decide_tool_request(db, ctx, b.envelope(
        EventType.TOOL_REQUESTED, actor=step.actor, integration=step.integration, tool=tool, arguments=arguments,
        correlation_id=correlation))
    outcome = StepOutcome(
        label=step.label, kind="tool_call", decision=response.decision, enforcement=response.enforcement,
        approval_id=response.approval_id,
        refs={"policy_decision_id": response.policy_decision_id, "tool_invocation_id": response.tool_invocation_id,
              "approval_id": response.approval_id, "risk": dict(response.risk or {}),
              "matched_policies": [m.get("name") for m in response.matched_policies][:5]},
    )
    invocation = db.get(ToolInvocation, response.tool_invocation_id)  # server-generated id from this run
    outcome.session_id = invocation.session_id if invocation is not None else None
    outcome.executed = response.decision in _RUNS
    result = resolve_text(step.result, rv)
    if outcome.executed and result is not None:
        refs = ingest(db, ctx, b.envelope(
            EventType.TOOL_COMPLETED, actor=step.actor, integration=step.integration, tool=tool,
            arguments=arguments, result=result, correlation_id=correlation))
        if refs.get("context_item_id"):
            outcome.refs["context_item_id"] = refs["context_item_id"]
    return outcome
