"""Simulation Lab API models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORM


class ScenarioCheckOut(BaseModel):
    id: str
    description: str


class ScenarioOut(BaseModel):
    id: str
    name: str
    description: str
    category: str
    use_case: str
    demo: bool
    tags: list[str]
    steps: list[str]
    checks: list[ScenarioCheckOut]


class ScenarioList(BaseModel):
    items: list[ScenarioOut]
    note: str = ("Scenarios submit synthetic, inert events to the real pipeline. Nothing is executed and no "
                 "network request is made; every row a run creates is flagged as a simulation.")


class RunIn(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=100)
    agent_id: str | None = Field(default=None, max_length=40,
                                 description="Run against a registered agent (regression testing); default: a dedicated simulated agent")
    agent_version: str | None = Field(default=None, max_length=64)


class SuiteIn(BaseModel):
    scenario_ids: list[str] | None = Field(default=None, max_length=50,
                                           description="Scenarios to run; omit to run the whole catalogue")
    agent_id: str | None = Field(default=None, max_length=40)
    agent_version: str | None = Field(default=None, max_length=64)


class SimulationRunOut(BaseModel):
    model_config = ORM

    id: str
    scenario_id: str
    scenario_name: str
    suite_run_id: str | None
    agent_id: str | None
    agent_version: str | None
    session_id: str | None
    status: str
    passed: bool | None
    summary: str
    error: str | None
    results: list[dict[str, Any]]
    policy_snapshot: list[dict[str, Any]]
    started_at: datetime
    completed_at: datetime | None
    triggered_by_user_id: str | None
    checks_total: int = 0
    checks_passed: int = 0
    is_simulation: bool = True


class SuiteSummaryOut(BaseModel):
    suite_run_id: str
    run_count: int
    passed_count: int
    failed_count: int
    started_at: datetime
    completed_at: datetime | None
    agent_id: str | None
    agent_version: str | None


class SuiteOut(SuiteSummaryOut):
    runs: list[SimulationRunOut]


class CheckChangeOut(BaseModel):
    check: str
    expectation: str
    base_passed: bool | None
    head_passed: bool | None
    base_actual: str
    head_actual: str


class DecisionChangeOut(BaseModel):
    step: str
    base: str | None
    head: str | None


class ScenarioDiffOut(BaseModel):
    scenario_id: str
    scenario_name: str
    status: str  # regressed | fixed | unchanged_pass | unchanged_fail | added | removed
    base_run_id: str | None
    head_run_id: str | None
    base_passed: bool | None
    head_passed: bool | None
    check_changes: list[CheckChangeOut]
    decision_changes: list[DecisionChangeOut]
    new_finding_categories: list[str]
    resolved_finding_categories: list[str]


class PolicyChangeOut(BaseModel):
    policy_id: str
    name: str | None
    change: str


class SuiteCompareOut(BaseModel):
    base: SuiteSummaryOut
    head: SuiteSummaryOut
    scenarios: list[ScenarioDiffOut]
    counts: dict[str, int]
    regressions: int
    policy_changes: list[PolicyChangeOut]
    note: str
