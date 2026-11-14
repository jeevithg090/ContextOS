"""Agent sessions and their timelines.

Authorisation: ``read``. Every lookup is scoped to the caller's organisation (404 otherwise); an API
key bound to one agent sees only that agent's sessions (another agent's session is 404).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, check_bound_agent, require
from app.database.session import get_db
from app.domain.enums import Permission
from app.models import AgentSession
from app.schemas.common import Page
from app.schemas.sessions import SessionDetailOut, SessionSummaryOut, TimelinePage
from app.services import sessions_service
from app.services.scoping import get_scoped

router = APIRouter(prefix="/sessions", tags=["sessions"])

READ = Depends(require(Permission.READ.value))


def _check_readable(db: Session, principal: Principal, session_id: str) -> None:
    if principal.bound_agent_id:
        session = get_scoped(db, AgentSession, session_id, principal.org_id, label="Session")
        check_bound_agent(principal, session.agent_id, label="Session", obj_id=session_id)


@router.get("", response_model=Page[SessionSummaryOut])
def list_sessions(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    agent_id: str | None = Query(None, max_length=40),
    status: str | None = Query(None, pattern="^(active|ended)$"),
    min_risk: int | None = Query(None, ge=0, le=100),
    trifecta: bool | None = None,
    include_simulated: bool = False,
    q: str | None = Query(None, max_length=200, description="Matches the integration's session id"),
    sort: str = Query("recent", pattern="^(recent|risk)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[SessionSummaryOut]:
    if principal.bound_agent_id:
        if agent_id and agent_id != principal.bound_agent_id:
            return Page[SessionSummaryOut](items=[], total=0, limit=limit, offset=offset)
        agent_id = principal.bound_agent_id
    items, total = sessions_service.list_sessions(
        db,
        principal.org_id,
        agent_id=agent_id,
        status=status,
        min_risk=min_risk,
        trifecta=trifecta,
        include_simulated=include_simulated,
        q=q,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    return Page[SessionSummaryOut].model_validate(
        {"items": items, "total": total, "limit": limit, "offset": offset}
    )


@router.get("/{session_id}", response_model=SessionDetailOut)
def get_session(
    session_id: str, principal: Principal = READ, db: Session = Depends(get_db)
) -> SessionDetailOut:
    """Session with its risk state (lethal-trifecta conditions and their evidence), parent/child
    sessions and counts."""
    _check_readable(db, principal, session_id)
    return SessionDetailOut.model_validate(sessions_service.session_detail(db, principal.org_id, session_id))


@router.get("/{session_id}/timeline", response_model=TimelinePage)
def session_timeline(
    session_id: str,
    principal: Principal = READ,
    db: Session = Depends(get_db),
    invocation_id: str | None = Query(
        None, max_length=40, description="Return the page containing this tool call"
    ),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> TimelinePage:
    """Events in server sequence order with plain-language titles and links to the records they produced."""
    _check_readable(db, principal, session_id)
    return TimelinePage.model_validate(
        sessions_service.session_timeline(
            db, principal.org_id, session_id, limit=limit, offset=offset, focus_invocation_id=invocation_id
        )
    )
