"""Simulation Lab: run controlled attack scenarios through the real pipeline and check the outcome.

Public contract (used by ``contextos-server seed-demo`` and the workspace's verify-with-simulation):

    list_scenarios() -> list[Scenario]                       # each has .id, .name, .demo
    get_scenario(scenario_id) -> Scenario                    # NotFoundError for unknown ids
    run_scenario(db, org_id, scenario_id, *, triggered_by_user_id=None, agent_id=None,
                 agent_version=None, suite_run_id=None) -> SimulationRun   # flush only; caller commits

A run never executes a tool and never makes a network request: it submits events describing agent
activity to ``app.services.ingestion`` with ``is_simulation=True`` and then evaluates the scenario's
expectations against the rows the pipeline wrote for the run's own sessions. Approvals the
simulated requests opened are cancelled at the end of the run so they never wait in the queue.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.core.ids import new_id
from app.core.logging import get_logger
from app.core.timeutil import utcnow
from app.domain.enums import ApprovalStatus
from app.models import Agent, Approval, Organization, SecurityPolicy, SimulationRun
from app.services.approvals import cancel_approval
from app.services.audit import append_audit
from app.services.ingestion import IngestContext
from app.services.notify import notify
from app.services.scoping import get_scoped
from app.simulations.model import Delegate, RunVars, RunView, Scenario
from app.simulations.runner import Actors, execute
from app.simulations.scenarios import SCENARIOS, SCENARIOS_BY_ID

log = get_logger(__name__)
CLOSE_REASON = "Closed by Simulation Lab: simulated requests are never executed."


def list_scenarios() -> list[Scenario]:
    return list(SCENARIOS)


def get_scenario(scenario_id: str) -> Scenario:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if scenario is None:
        raise NotFoundError(f"Simulation scenario '{scenario_id}' not found")
    return scenario


def policy_snapshot(db: Session, org_id: str) -> list[dict[str, Any]]:
    rows = db.scalars(select(SecurityPolicy).where(SecurityPolicy.organization_id == org_id)
                      .order_by(SecurityPolicy.priority, SecurityPolicy.name))
    return [{"policy_id": p.id, "name": p.name, "version": p.version, "enabled": p.enabled, "mode": p.mode,
             "outcome": p.outcome} for p in rows]


def run_scenario(
    db: Session,
    org_id: str,
    scenario_id: str,
    *,
    triggered_by_user_id: str | None = None,
    agent_id: str | None = None,
    agent_version: str | None = None,
    suite_run_id: str | None = None,
    actor_type: str = "system",
    actor_id: str | None = None,
) -> SimulationRun:
    """Run one scenario. Unknown scenario or another org's agent → NotFoundError (404)."""
    scenario = get_scenario(scenario_id)
    agent = get_scoped(db, Agent, agent_id, org_id, label="Agent") if agent_id else None
    now = utcnow()
    run = SimulationRun(
        id=new_id("simulation_run"), organization_id=org_id, scenario_id=scenario.id, scenario_name=scenario.name,
        suite_run_id=suite_run_id, agent_id=agent.id if agent else None,
        agent_version=agent_version or (agent.version if agent else None), status="running",
        policy_snapshot=policy_snapshot(db, org_id), results=[], summary="", started_at=now,
        triggered_by_user_id=triggered_by_user_id,
    )
    db.add(run)
    db.flush()
    org = db.get(Organization, org_id)
    audit_before = int(org.audit_seq or 0) if org else 0
    agent_seen = agent.last_seen_at if agent else None

    rv = RunVars.generate()
    base_name = agent.name if agent else f"sim-{scenario.id}"
    delegate = next((s for s in scenario.steps if isinstance(s, Delegate)), None)
    actors = Actors(
        agent_name=base_name, framework=agent.framework if agent else "simulation",
        # A real agent's registered version is never changed by a simulation; it is recorded on the run.
        version=None if agent else agent_version, main_session=f"{run.id}-main",
        child_agent=f"sim-{delegate.child_agent}" if delegate else None,
        child_session=f"{run.id}-child" if delegate else None,
    )
    ctx = IngestContext(org_id=org_id, actor_type="system", actor_id=None, is_simulation=True,
                        simulation_run_id=run.id)
    execution = execute(db, ctx, scenario, actors, rv)
    if agent is not None:
        agent.last_seen_at = agent_seen  # simulated traffic must not make a real agent look active
    run.session_id = execution.session_ids[0] if execution.session_ids else None
    closed = _close_approvals(db, org_id, execution.session_ids)

    view = RunView(db=db, org_id=org_id, run_id=run.id, session_ids=execution.session_ids,
                   outcomes=execution.outcomes, vars=rv, audit_seq_before=audit_before)
    results = _evaluate(scenario, view, execution)
    checks = [r for r in results if r["kind"] == "expectation"]
    passed_n = sum(1 for r in checks if r["passed"])
    run.results = results
    run.completed_at = utcnow()
    if execution.error:
        run.status, run.passed, run.error = "failed", False, execution.error
        run.summary = f"The run stopped early: {execution.error} {passed_n} of {len(checks)} checks passed."
    else:
        run.status, run.passed = "completed", passed_n == len(checks)
        run.summary = (f"All {len(checks)} checks passed." if run.passed
                       else f"{len(checks) - passed_n} of {len(checks)} checks failed: "
                            + "; ".join(r["expectation"] for r in checks if not r["passed"])[:900])
    if closed:
        run.summary += f" {closed} simulated approval request(s) were closed automatically."
    db.flush()
    append_audit(db, org_id, action="simulation.completed", actor_type=actor_type, actor_id=actor_id,
                 target_type="simulation_run", target_id=run.id,
                 details={"scenario_id": scenario.id, "status": run.status, "passed": run.passed,
                          "suite_run_id": suite_run_id, "agent_id": run.agent_id, "session_id": run.session_id,
                          "checks": len(checks), "checks_passed": passed_n})
    notify(db, org_id, "simulation.completed", id=run.id, passed=run.passed, suite_run_id=suite_run_id)
    return run


def _close_approvals(db: Session, org_id: str, session_ids: list[str]) -> int:
    if not session_ids:
        return 0
    pending = list(db.scalars(select(Approval).where(
        Approval.organization_id == org_id, Approval.session_id.in_(session_ids),
        Approval.status == ApprovalStatus.PENDING.value)))
    for approval in pending:
        cancel_approval(db, org_id, approval.id, actor_type="system", actor_id=None, reason=CLOSE_REASON)
    return len(pending)


def _evaluate(scenario: Scenario, view: RunView, execution: Any) -> list[dict[str, Any]]:
    """Expectation results first, then informational observations (one per step)."""
    out: list[dict[str, Any]] = []
    for exp in scenario.expectations:
        try:
            res = exp.check(view)
            row = {"expected": res.expected, "actual": res.actual, "passed": res.passed, "evidence": res.evidence}
        except Exception as exc:  # a broken check fails visibly instead of passing silently
            log.warning("simulation check failed", extra={"scenario": scenario.id, "check": exp.id,
                                                           "error_type": type(exc).__name__})
            row = {"expected": "check runs", "actual": f"check error: {type(exc).__name__}", "passed": False,
                   "evidence": []}
        out.append({"kind": "expectation", "step": exp.id, "expectation": exp.description, **row,
                    "evidence_ids": [e["id"] for e in row["evidence"]]})
    for label in scenario.step_labels():
        o = execution.outcomes.get(label)
        if o is None:
            out.append({"kind": "observation", "step": label, "expectation": f"Step '{label}'", "expected": None,
                        "actual": "not run (an earlier step failed)", "passed": None, "evidence": [],
                        "evidence_ids": []})
            continue
        if o.error:
            actual = f"pipeline error: {o.error}"
        elif o.decision:
            actual = f"{o.decision} ({o.enforcement})" + ("" if o.executed else " — not run")
        else:
            actual = "recorded"
        evidence = o.evidence()
        out.append({"kind": "observation", "step": label, "expectation": f"Step '{label}' ({o.kind})",
                    "expected": None, "actual": actual, "passed": None, "decision": o.decision,
                    "enforcement": o.enforcement, "session_id": o.session_id,
                    "matched_policies": o.refs.get("matched_policies") or [], "evidence": evidence,
                    "evidence_ids": [e["id"] for e in evidence]})
    return out


def run_suite(db: Session, org_id: str, scenario_ids: list[str] | None = None, *, agent_id: str | None = None,
              agent_version: str | None = None, triggered_by_user_id: str | None = None,
              actor_type: str = "system", actor_id: str | None = None) -> tuple[str, list[SimulationRun]]:
    """Run several scenarios (all when ``scenario_ids`` is empty) as one regression suite."""
    ids = list(dict.fromkeys(scenario_ids or [s.id for s in SCENARIOS]))
    for sid in ids:
        get_scenario(sid)  # validate every id before running anything
    if agent_id:
        get_scoped(db, Agent, agent_id, org_id, label="Agent")
    suite_run_id = new_id("suite_run")
    runs = [run_scenario(db, org_id, sid, triggered_by_user_id=triggered_by_user_id, agent_id=agent_id,
                         agent_version=agent_version, suite_run_id=suite_run_id, actor_type=actor_type,
                         actor_id=actor_id) for sid in ids]
    return suite_run_id, runs
