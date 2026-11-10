"""Aggregates every route module under ``/api/v1``. Route modules own their prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    admin,
    agents,
    approvals,
    audit,
    auth,
    context,
    events,
    findings,
    health,
    incidents,
    integrations,
    overview,
    policies,
    provenance,
    replay,
    sessions,
    simulations,
    trust,
    workspace_ai,
    workspace_analytics,
    workspace_boards,
    workspace_tasks,
)

api_router = APIRouter(prefix="/api/v1")

for module in (
    health,
    auth,
    admin,
    events,
    agents,
    sessions,
    context,
    provenance,
    trust,
    findings,
    policies,
    approvals,
    incidents,
    replay,
    simulations,
    overview,
    integrations,
    audit,
    workspace_boards,
    workspace_tasks,
    workspace_ai,
    workspace_analytics,
):
    api_router.include_router(module.router)
