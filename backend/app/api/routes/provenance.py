"""Provenance / Context Trust Graph.

    GET /provenance/graph?session_id=|agent_id=|context_item_id=|finding_id=&depth=&limit=
        Graph for one scope (no scope: the most recent high-risk session) with risky paths.
    GET /provenance/scopes?q=          Sessions, agents and findings the graph can be scoped to (scope picker).
    GET /provenance/nodes/{type}/{id}  Inspector detail for one node (resource ids contain "/").

All endpoints need ``read`` and are scoped to the caller's organisation (404 for other orgs' ids).
Edges are relationships ContextOS observed; responses carry that disclaimer.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.database.session import get_db
from app.domain.enums import Permission
from app.schemas.provenance import NodeDetailOut, ProvenanceGraphOut, ScopeOptionsOut
from app.services import provenance_service

router = APIRouter(prefix="/provenance", tags=["provenance"])

READ = Depends(require(Permission.READ.value))
_ID = {"default": None, "max_length": 64}


@router.get("/graph", response_model=ProvenanceGraphOut)
def get_graph(
    session_id: str | None = Query(**_ID, description="Session scope (includes delegated parent/child sessions)"),
    agent_id: str | None = Query(**_ID, description="Agent scope (its most recent sessions)"),
    context_item_id: str | None = Query(**_ID, description="Expand N hops from one context item"),
    finding_id: str | None = Query(**_ID, description="Expand N hops from a finding and its evidence"),
    depth: int = Query(provenance_service.DEFAULT_DEPTH, ge=1, le=4, description="Hops for item/finding scopes"),
    limit: int = Query(provenance_service.DEFAULT_NODE_LIMIT, ge=20, le=1000, description="Maximum nodes returned"),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> ProvenanceGraphOut:
    return provenance_service.build_provenance_graph(
        db, principal.org_id, session_id=session_id, agent_id=agent_id, context_item_id=context_item_id,
        finding_id=finding_id, depth=depth, limit=limit,
    )


@router.get("/scopes", response_model=ScopeOptionsOut)
def get_scopes(
    q: str | None = Query(None, max_length=200, description="Filter by agent name, session id or finding title/rule"),
    limit: int = Query(25, ge=1, le=100),
    principal: Principal = READ,
    db: Session = Depends(get_db),
) -> ScopeOptionsOut:
    return provenance_service.scope_options(db, principal.org_id, q=q, limit=limit)


@router.get("/nodes/{node_type}/{node_id:path}", response_model=NodeDetailOut)
def get_node(node_type: str, node_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> NodeDetailOut:
    return provenance_service.node_detail(db, principal.org_id, node_type, node_id)
