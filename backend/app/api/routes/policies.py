"""Policy Studio: policies, validation and dry-run evaluation.

Authorisation: reading, validating and dry-run testing need ``read``; creating, editing and
deleting need ``policy:manage``. Every lookup is scoped to the caller's organisation (404 otherwise).

Static paths are registered before ``/{policy_id}`` so they are never captured as an id.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.engines.policy import FIELD_CATALOG, OPERATORS, explain_conditions
from app.models import SecurityPolicy
from app.schemas.common import Page
from app.schemas.policies import (
    DecisionName,
    DecisionSummaryOut,
    ModeName,
    PolicyCreate,
    PolicyDecisionMatchOut,
    PolicyMatchStats,
    PolicyOut,
    PolicyPatch,
    PolicyTestIn,
    PolicyTestOut,
    ValidateIn,
    ValidateOut,
)
from app.services import policy_service, policy_testing
from app.services.policy_service import Actor

router = APIRouter(prefix="/policies", tags=["policies"])

READ = Depends(require(Permission.READ.value))
# Recorded decisions span every agent: API keys bound to one agent get 403.
DECISIONS_READ = Depends(require_org_wide(Permission.READ.value))
MANAGE = Depends(require(Permission.POLICY_MANAGE.value))


def _actor(principal: Principal) -> Actor:
    return Actor(type=principal.actor_type, id=principal.actor_id)


def _out(row: SecurityPolicy, stats: dict[str, Any] | None) -> PolicyOut:
    return PolicyOut(
        id=row.id,
        name=row.name,
        description=row.description,
        enabled=row.enabled,
        mode=row.mode,
        priority=row.priority,
        outcome=row.outcome,
        conditions=row.conditions or {},
        restrictions=row.restrictions or {},
        severity=row.severity,
        tags=[str(t) for t in (row.tags or [])],
        version=row.version,
        is_builtin=row.is_builtin,
        builtin_key=row.builtin_key,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        explanation=explain_conditions(row.conditions or {}),
        stats=PolicyMatchStats.model_validate(stats) if stats is not None else None,
    )


def _with_stats(db: Session, org_id: str, row: SecurityPolicy) -> PolicyOut:
    stats = policy_service.match_stats(db, org_id).get(row.id, policy_service.empty_stats())
    return _out(row, stats)


# ----------------------------------------------------------------------------- catalog + drafts


@router.get("/fields")
def list_fields(principal: Principal = READ) -> list[dict[str, Any]]:
    """Every field a condition may reference (``FIELD_CATALOG``), with type, description and valid ops."""
    return FIELD_CATALOG


@router.get("/operators")
def list_operators(principal: Principal = READ) -> list[dict[str, Any]]:
    """Condition operators with their plain-English label and the kind of value they take."""
    return OPERATORS


@router.post("/validate", response_model=ValidateOut)
def validate_policy(body: ValidateIn, principal: Principal = READ) -> ValidateOut:
    return ValidateOut.model_validate(
        policy_service.validate_draft(body.conditions, outcome=body.outcome, restrictions=body.restrictions)
    )


@router.post("/test", response_model=PolicyTestOut)
def test_policy(body: PolicyTestIn, principal: Principal = DECISIONS_READ, db: Session = Depends(get_db)) -> PolicyTestOut:
    """Dry run: evaluate a draft and/or saved policies against an input. Nothing is persisted."""
    result = policy_testing.run_policy_test(
        db,
        principal.org_id,
        draft=body.policy.model_dump() if body.policy else None,
        policy_ids=body.policy_ids,
        with_org_policies=body.with_org_policies,
        input_data=body.input,
        policy_decision_id=body.policy_decision_id,
    )
    return PolicyTestOut.model_validate(result)


@router.get("/recent-decisions", response_model=Page[DecisionSummaryOut])
def recent_decisions(
    principal: Principal = DECISIONS_READ,
    db: Session = Depends(get_db),
    decision: DecisionName | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    include_simulated: bool = Query(False, description="Include decisions recorded by Simulation Lab runs"),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[DecisionSummaryOut]:
    """Recorded decisions to use as dry-run test inputs (their redacted input snapshots)."""
    items, total = policy_service.recent_decisions(
        db, principal.org_id, limit=limit, offset=offset, decision=decision, session_id=session_id,
        agent_id=agent_id, include_simulated=include_simulated,
    )
    return Page(items=[DecisionSummaryOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


# ----------------------------------------------------------------------------- collection


@router.get("", response_model=Page[PolicyOut])
def list_policies(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    enabled: bool | None = None,
    mode: ModeName | None = None,
    outcome: DecisionName | None = None,
    builtin: bool | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[PolicyOut]:
    """Policies ordered by evaluation precedence, each with its last-7-days match statistics."""
    rows = policy_service.list_policies(
        db, principal.org_id, enabled=enabled, mode=mode, outcome=outcome, builtin=builtin, q=q
    )
    stats = policy_service.match_stats(db, principal.org_id)
    page = rows[offset : offset + limit]
    return Page(
        items=[_out(r, stats.get(r.id, policy_service.empty_stats())) for r in page],
        total=len(rows),
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(body: PolicyCreate, principal: Principal = MANAGE, db: Session = Depends(get_db)) -> PolicyOut:
    row = policy_service.create_policy(db, principal.org_id, _actor(principal), body.model_dump())
    return _out(row, policy_service.empty_stats())


# ----------------------------------------------------------------------------- item


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(policy_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> PolicyOut:
    return _with_stats(db, principal.org_id, policy_service.get_policy(db, principal.org_id, policy_id))


@router.patch("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str, body: PolicyPatch, principal: Principal = MANAGE, db: Session = Depends(get_db)
) -> PolicyOut:
    row = policy_service.get_policy(db, principal.org_id, policy_id)
    row = policy_service.update_policy(
        db, principal.org_id, _actor(principal), row, body.model_dump(exclude_unset=True)
    )
    return _with_stats(db, principal.org_id, row)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: str, principal: Principal = MANAGE, db: Session = Depends(get_db)) -> Response:
    row = policy_service.get_policy(db, principal.org_id, policy_id)
    policy_service.delete_policy(db, principal.org_id, _actor(principal), row)
    return Response(status_code=204)


@router.get("/{policy_id}/decisions", response_model=Page[PolicyDecisionMatchOut])
def policy_decisions(
    policy_id: str,
    principal: Principal = DECISIONS_READ,
    db: Session = Depends(get_db),
    days: int = Query(30, ge=1, le=365),
    include_simulated: bool = Query(False, description="Include decisions recorded by Simulation Lab runs"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[PolicyDecisionMatchOut]:
    """Recorded decisions in which this policy matched (enforce or monitor), newest first."""
    items, total = policy_service.decisions_for_policy(
        db, principal.org_id, policy_id, days=days, limit=limit, offset=offset, include_simulated=include_simulated
    )
    return Page(
        items=[PolicyDecisionMatchOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset
    )
