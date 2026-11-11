"""Replay Lab: recorded session replay and counterfactual policy evaluation.

Authorisation: ``read`` for both endpoints (a counterfactual is a read-only simulation: nothing is
persisted, audited or returned to an integration). Every lookup is scoped to the caller's
organisation; other organisations' sessions and policies are 404.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.replay import CounterfactualIn, CounterfactualOut, ReplayOut
from app.services import replay_service

router = APIRouter(prefix="/replay", tags=["replay"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403


@router.get("/sessions/{session_id}", response_model=ReplayOut)
def replay_session(
    session_id: str,
    principal: Principal = READ,
    db: Session = Depends(get_db),
    decision_id: str | None = Query(None, max_length=40, description="Return the window containing this decision"),
    limit: int = Query(500, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> ReplayOut:
    """The session's recorded events as replayable steps, in server sequence order, with the recorded
    outcome of each decision and session risk recomputed from recorded events after every step."""
    return ReplayOut.model_validate(replay_service.session_replay(
        db, principal.org_id, session_id, limit=limit, offset=offset, decision_id=decision_id,
    ))


@router.post("/counterfactual", response_model=CounterfactualOut)
def run_counterfactual(body: CounterfactualIn, principal: Principal = READ,
                       db: Session = Depends(get_db)) -> CounterfactualOut:
    """SIMULATION: re-evaluate every recorded policy decision of the session against its recorded
    input snapshot under a hypothetical policy set. Outcomes are hypothetical, not historical fact."""
    return CounterfactualOut.model_validate(replay_service.counterfactual(db, principal.org_id, body))
