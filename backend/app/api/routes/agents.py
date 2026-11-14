"""Agent registry, profiles, identity/delegation graph and security posture.

Authorisation: reads need ``read``; registering and editing need ``write``. Editing a field that
policies evaluate (environment, labels, status — including quarantine) additionally needs
``policy:manage``. Every lookup is scoped to the caller's organisation (404 otherwise).

An API key bound to one agent sees only that agent (another agent is 404; the org-wide ``/graph`` is
403).

``/graph`` is registered before ``/{agent_id}`` so it is never captured as an id.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, check_bound_agent, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.models import Agent
from app.schemas.agents import (
    AgentCreate,
    AgentDetailOut,
    AgentGraphOut,
    AgentPage,
    AgentPatch,
    AgentPostureOut,
    AgentSort,
    AgentStatusName,
    AgentToolOut,
    EnvironmentName,
)
from app.schemas.common import Page
from app.schemas.sessions import SessionSummaryOut
from app.services import agents_service, sessions_service
from app.services.agents_service import Actor
from app.services.scoping import get_scoped

router = APIRouter(prefix="/agents", tags=["agents"])

READ = Depends(require(Permission.READ.value))
WRITE = Depends(require(Permission.WRITE.value))


def _actor(principal: Principal) -> Actor:
    return Actor(type=principal.actor_type, id=principal.actor_id)


def _agent(db: Session, org_id: str, agent_id: str) -> Agent:
    return get_scoped(db, Agent, agent_id, org_id, label="Agent")


def _readable_agent(db: Session, principal: Principal, agent_id: str) -> Agent:
    agent = _agent(db, principal.org_id, agent_id)
    check_bound_agent(principal, agent.id, label="Agent", obj_id=agent_id)
    return agent


@router.get("", response_model=AgentPage)
def list_agents(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    environment: EnvironmentName | None = None,
    framework: str | None = Query(None, max_length=64),
    status: AgentStatusName | None = None,
    include_simulated: bool = False,
    sort: AgentSort = "last_seen",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AgentPage:
    """Agent inventory with session, finding and tool counts. Simulation Lab agents are hidden unless
    ``include_simulated`` is true (``facets.simulated`` says how many exist)."""
    items, total, facets = agents_service.list_agents(
        db,
        principal.org_id,
        q=q,
        environment=environment,
        framework=framework,
        status=status,
        include_simulated=include_simulated,
        sort=sort,
        limit=limit,
        offset=offset,
        only_agent_id=principal.bound_agent_id,
    )
    return AgentPage.model_validate(
        {"items": items, "total": total, "limit": limit, "offset": offset, "facets": facets}
    )


@router.post("", response_model=AgentDetailOut, status_code=201)
def register_agent(
    body: AgentCreate, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> AgentDetailOut:
    """Pre-register an agent with its declared tools. Integrations reporting the same name attach to it."""
    agent = agents_service.create_agent(db, principal.org_id, _actor(principal), body.model_dump(mode="json"))
    return AgentDetailOut.model_validate(agents_service.agent_detail(db, principal.org_id, agent))


@router.get("/graph", response_model=AgentGraphOut)
def agent_graph(
    principal: Principal = Depends(require_org_wide(Permission.READ.value)),
    db: Session = Depends(get_db),
    include_simulated: bool = False,
) -> AgentGraphOut:
    """Agents and the delegation/messaging relationships observed between them."""
    return AgentGraphOut.model_validate(
        agents_service.agent_graph(db, principal.org_id, include_simulated=include_simulated)
    )


@router.get("/{agent_id}", response_model=AgentDetailOut)
def get_agent(agent_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> AgentDetailOut:
    agent = _readable_agent(db, principal, agent_id)
    return AgentDetailOut.model_validate(agents_service.agent_detail(db, principal.org_id, agent))


@router.patch("/{agent_id}", response_model=AgentDetailOut)
def update_agent(
    agent_id: str, body: AgentPatch, principal: Principal = WRITE, db: Session = Depends(get_db)
) -> AgentDetailOut:
    agent = _agent(db, principal.org_id, agent_id)
    changes = body.model_dump(mode="json", exclude_unset=True)
    agent = agents_service.update_agent(
        db,
        principal.org_id,
        _actor(principal),
        agent,
        changes,
        may_manage_policy=principal.has(Permission.POLICY_MANAGE.value),
    )
    return AgentDetailOut.model_validate(agents_service.agent_detail(db, principal.org_id, agent))


@router.get("/{agent_id}/sessions", response_model=Page[SessionSummaryOut])
def agent_sessions(
    agent_id: str,
    principal: Principal = READ,
    db: Session = Depends(get_db),
    status: str | None = Query(None, pattern="^(active|ended)$"),
    sort: str = Query("recent", pattern="^(recent|risk)$"),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[SessionSummaryOut]:
    agent = _readable_agent(db, principal, agent_id)
    items, total = sessions_service.list_sessions(
        db,
        principal.org_id,
        agent_id=agent.id,
        status=status,
        include_simulated=True,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    return Page[SessionSummaryOut].model_validate(
        {"items": items, "total": total, "limit": limit, "offset": offset}
    )


@router.get("/{agent_id}/tools", response_model=Page[AgentToolOut])
def agent_tools(
    agent_id: str,
    principal: Principal = READ,
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[AgentToolOut]:
    """Observed tools (usage, server-side category and risk, decision breakdown) plus declared tools
    that have not been observed yet."""
    agent = _readable_agent(db, principal, agent_id)
    tools = agents_service.agent_tools(db, principal.org_id, agent)
    return Page[AgentToolOut].model_validate(
        {"items": tools[offset : offset + limit], "total": len(tools), "limit": limit, "offset": offset}
    )


@router.get("/{agent_id}/posture", response_model=AgentPostureOut)
def agent_posture(
    agent_id: str, principal: Principal = READ, db: Session = Depends(get_db)
) -> AgentPostureOut:
    """Explainable 0-100 posture (higher is better), computed now from persisted configuration and activity."""
    agent = _readable_agent(db, principal, agent_id)
    return AgentPostureOut.model_validate(agents_service.agent_posture(db, principal.org_id, agent))
