"""Integration registry, health and setup.

- ``GET /integrations`` — integrations that have sent real (non-simulated) traffic, with health and
  evidence counts, plus the capability catalog (what each integration observes and enforces).
- ``GET /integrations/{kind}/setup`` — setup steps for a catalog kind, rendered with this request's
  server URL. API keys are never included: the steps point to Settings → API keys.

Both require the ``read`` permission (users, or API keys with the read scope).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.core.errors import NotFoundError
from app.database.session import get_db
from app.schemas.integrations import IntegrationsOut, SetupGuideOut
from app.services import integrations_service

router = APIRouter(prefix="/integrations", tags=["integrations"])

READ = Depends(require("read"))


@router.get("", response_model=IntegrationsOut)
def list_integrations(principal: Principal = READ, db: Session = Depends(get_db)) -> IntegrationsOut:
    """Connected integrations (connected = an event in the last 15 minutes) and the capability catalog."""
    return integrations_service.integrations_overview(db, principal.org_id)


@router.get("/{kind}/setup", response_model=SetupGuideOut)
def setup_guide(kind: str, request: Request, principal: Principal = READ) -> SetupGuideOut:
    """Step-by-step setup for one integration kind. Planned kinds return their interim path."""
    guide = integrations_service.setup_guide(kind.strip().lower(), str(request.base_url))
    if guide is None:
        raise NotFoundError(f"Integration '{kind}' is not in the catalog")
    return guide
