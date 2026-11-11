"""Simulation Lab: controlled attack scenarios and security regression suites.

Reading needs ``read``. Starting a run writes simulated events through the pipeline, so it needs
``write`` for signed-in users or the ``ingest`` scope for API keys (the CLI's ``contextos simulate``).
An API key bound to one agent may only run simulations against that agent and only sees that agent's
runs (another agent's run is 404); suites span agents, so bound keys get 403 there.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, check_bound_agent, get_principal, require, require_org_wide
from app.core.errors import PermissionDeniedError
from app.database.session import get_db
from app.domain.enums import Permission
from app.models import SimulationRun
from app.schemas.common import Page
from app.schemas.simulations import (
    RunIn,
    ScenarioCheckOut,
    ScenarioList,
    ScenarioOut,
    SimulationRunOut,
    SuiteCompareOut,
    SuiteIn,
    SuiteOut,
    SuiteSummaryOut,
)
from app.services import simulations as sims
from app.services import simulations_suites as suites
from app.services.scoping import get_scoped, paginate, scoped
from app.simulations.model import Scenario

router = APIRouter(prefix="/simulations", tags=["simulations"])


def _runner(principal: Principal = Depends(get_principal)) -> Principal:
    needed = Permission.INGEST.value if principal.kind == "api_key" else Permission.WRITE.value
    principal.require(needed)
    return principal


def _check_agent(principal: Principal, agent_id: str | None) -> None:
    if principal.bound_agent_id and agent_id != principal.bound_agent_id:
        raise PermissionDeniedError("This API key is bound to one agent; pass that agent's agent_id to simulate it")


def _scenario_out(s: Scenario) -> ScenarioOut:
    return ScenarioOut(id=s.id, name=s.name, description=s.description, category=s.category, use_case=s.use_case,
                       demo=s.demo, tags=list(s.tags), steps=s.step_labels(),
                       checks=[ScenarioCheckOut(id=e.id, description=e.description) for e in s.expectations])


def _run_out(run: SimulationRun) -> SimulationRunOut:
    out = SimulationRunOut.model_validate(run)
    checks = [r for r in (run.results or []) if r.get("kind") == "expectation"]
    out.checks_total = len(checks)
    out.checks_passed = sum(1 for r in checks if r.get("passed"))
    return out


@router.get("/scenarios", response_model=ScenarioList)
def list_scenarios(_: Principal = Depends(require(Permission.READ.value))) -> ScenarioList:
    return ScenarioList(items=[_scenario_out(s) for s in sims.list_scenarios()])


@router.get("/scenarios/{scenario_id}", response_model=ScenarioOut)
def get_scenario(scenario_id: str, _: Principal = Depends(require(Permission.READ.value))) -> ScenarioOut:
    return _scenario_out(sims.get_scenario(scenario_id))


@router.post("/runs", response_model=SimulationRunOut, status_code=201)
def start_run(body: RunIn, principal: Principal = Depends(_runner), db: Session = Depends(get_db)) -> SimulationRunOut:
    _check_agent(principal, body.agent_id)
    run = sims.run_scenario(db, principal.org_id, body.scenario_id, triggered_by_user_id=principal.user_id,
                            agent_id=body.agent_id, agent_version=body.agent_version,
                            actor_type=principal.actor_type, actor_id=principal.actor_id)
    db.commit()
    return _run_out(run)


@router.get("/runs", response_model=Page[SimulationRunOut])
def list_runs(
    scenario_id: str | None = Query(None, max_length=100),
    suite_run_id: str | None = Query(None, max_length=40),
    agent_id: str | None = Query(None, max_length=40),
    passed: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(require(Permission.READ.value)),
    db: Session = Depends(get_db),
) -> Page[SimulationRunOut]:
    query = scoped(SimulationRun, principal.org_id)
    if principal.bound_agent_id:
        query = query.where(SimulationRun.agent_id == principal.bound_agent_id)
    if scenario_id:
        query = query.where(SimulationRun.scenario_id == scenario_id)
    if suite_run_id:
        query = query.where(SimulationRun.suite_run_id == suite_run_id)
    if agent_id:
        query = query.where(SimulationRun.agent_id == agent_id)
    if passed is not None:
        query = query.where(SimulationRun.passed.is_(passed))
    items, total = paginate(db, query.order_by(SimulationRun.started_at.desc(), SimulationRun.id.desc()),
                            limit=limit, offset=offset)
    return Page[SimulationRunOut](items=[_run_out(r) for r in items], total=total, limit=limit, offset=offset)


@router.get("/runs/{run_id}", response_model=SimulationRunOut)
def get_run(run_id: str, principal: Principal = Depends(require(Permission.READ.value)),
            db: Session = Depends(get_db)) -> SimulationRunOut:
    run = get_scoped(db, SimulationRun, run_id, principal.org_id, label="Simulation run")
    check_bound_agent(principal, run.agent_id, label="Simulation run", obj_id=run_id)
    return _run_out(run)


@router.post("/suites", response_model=SuiteOut, status_code=201)
def start_suite(body: SuiteIn, principal: Principal = Depends(_runner), db: Session = Depends(get_db)) -> SuiteOut:
    _check_agent(principal, body.agent_id)
    _, runs = sims.run_suite(db, principal.org_id, body.scenario_ids, agent_id=body.agent_id,
                             agent_version=body.agent_version, triggered_by_user_id=principal.user_id,
                             actor_type=principal.actor_type, actor_id=principal.actor_id)
    db.commit()
    return SuiteOut(**suites.suite_summary(runs), runs=[_run_out(r) for r in runs])


@router.get("/suites", response_model=Page[SuiteSummaryOut])
def list_suites(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                principal: Principal = Depends(require_org_wide(Permission.READ.value)),
                db: Session = Depends(get_db)) -> Page[SuiteSummaryOut]:
    rows, total = suites.list_suites(db, principal.org_id, limit=limit, offset=offset)
    return Page[SuiteSummaryOut](items=[SuiteSummaryOut(**r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/suites/compare", response_model=SuiteCompareOut)
def compare(base: str = Query(..., max_length=40), head: str = Query(..., max_length=40),
            principal: Principal = Depends(require_org_wide(Permission.READ.value)),
            db: Session = Depends(get_db)) -> SuiteCompareOut:
    return SuiteCompareOut(**suites.compare_suites(db, principal.org_id, base, head))


@router.get("/suites/{suite_run_id}", response_model=SuiteOut)
def get_suite(suite_run_id: str, principal: Principal = Depends(require_org_wide(Permission.READ.value)),
              db: Session = Depends(get_db)) -> SuiteOut:
    runs = suites.suite_runs(db, principal.org_id, suite_run_id)
    return SuiteOut(**suites.suite_summary(runs), runs=[_run_out(r) for r in runs])

