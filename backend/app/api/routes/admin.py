"""Organisation settings, members, roles and API keys.

Authorisation:
- ``GET /org`` — any principal with ``read`` (users, or API keys with the read scope).
- ``GET /org/members`` — signed-in users with ``read`` (member emails are not exposed to API keys).
- Everything that changes state, and the API-key listing — signed-in users with ``admin``.
Changes involving the ``owner`` role additionally require an owner (enforced in the service).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Principal, require
from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.timeutil import utcnow
from app.database.session import get_db
from app.models import ApiKey, Membership, Organization, User
from app.schemas.admin import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    MemberCreate,
    MemberOut,
    MemberRoleUpdate,
    OrgOut,
    OrgSettingsOut,
    OrgSettingsPatch,
)
from app.schemas.common import Page
from app.services import auth_service
from app.services.auth_service import Actor
from app.services.bootstrap import effective_org_settings, update_org_settings

router = APIRouter(prefix="/org", tags=["organisation"])


def _user_with(permission: str) -> Callable[..., Principal]:
    def _dep(principal: Principal = Depends(require(permission))) -> Principal:
        if principal.kind != "user":
            raise PermissionDeniedError("This endpoint requires a signed-in user")
        return principal

    return _dep


def _actor(principal: Principal) -> Actor:
    return Actor(type=principal.actor_type, id=principal.actor_id, role=principal.role)


def _org(db: Session, org_id: str) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organisation not found")
    return org


def _org_out(db: Session, org: Organization) -> OrgOut:
    now = utcnow()
    members = (
        db.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == org.id))
        or 0
    )
    active_keys = (
        db.scalar(
            select(func.count())
            .select_from(ApiKey)
            .where(
                ApiKey.organization_id == org.id,
                ApiKey.revoked_at.is_(None),
                (ApiKey.expires_at.is_(None)) | (ApiKey.expires_at > now),
            )
        )
        or 0
    )
    settings = effective_org_settings(org)
    return OrgOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        created_at=org.created_at,
        settings=OrgSettingsOut.model_validate({k: settings[k] for k in OrgSettingsOut.model_fields}),
        member_count=int(members),
        active_api_key_count=int(active_keys),
    )


def _member_out(membership: Membership, user: User) -> MemberOut:
    return MemberOut(
        id=membership.id,
        user_id=user.id,
        name=user.name,
        email=user.email,
        role=membership.role,  # type: ignore[arg-type]
        is_active=user.is_active,
        created_at=membership.created_at,
        last_login_at=user.last_login_at,
    )


# ----------------------------------------------------------------------------- organisation


@router.get("", response_model=OrgOut)
def get_org(principal: Principal = Depends(require("read")), db: Session = Depends(get_db)) -> OrgOut:
    return _org_out(db, _org(db, principal.org_id))


@router.patch("/settings", response_model=OrgOut)
def patch_settings(
    body: OrgSettingsPatch, principal: Principal = Depends(_user_with("admin")), db: Session = Depends(get_db)
) -> OrgOut:
    org = _org(db, principal.org_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    update_org_settings(db, org, changes, actor_type=principal.actor_type, actor_id=principal.actor_id)
    db.flush()
    return _org_out(db, org)


# ----------------------------------------------------------------------------- members


@router.get("/members", response_model=Page[MemberOut])
def list_members(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(_user_with("read")),
    db: Session = Depends(get_db),
) -> Page[MemberOut]:
    rows, total = auth_service.list_members(db, principal.org_id, limit=limit, offset=offset)
    return Page(items=[_member_out(m, u) for m, u in rows], total=total, limit=limit, offset=offset)


@router.post("/members", response_model=MemberOut, status_code=201)
def add_member(
    body: MemberCreate, principal: Principal = Depends(_user_with("admin")), db: Session = Depends(get_db)
) -> MemberOut:
    membership, user, _created = auth_service.add_member(
        db,
        principal.org_id,
        _actor(principal),
        email=body.email,
        name=body.name,
        role=body.role,
        password=body.password,
    )
    return _member_out(membership, user)


@router.patch("/members/{membership_id}", response_model=MemberOut)
def change_role(
    membership_id: str,
    body: MemberRoleUpdate,
    principal: Principal = Depends(_user_with("admin")),
    db: Session = Depends(get_db),
) -> MemberOut:
    membership, user = auth_service.change_member_role(
        db, principal.org_id, _actor(principal), membership_id, body.role
    )
    return _member_out(membership, user)


@router.delete("/members/{membership_id}", status_code=204, response_class=Response)
def remove_member(
    membership_id: str, principal: Principal = Depends(_user_with("admin")), db: Session = Depends(get_db)
) -> Response:
    auth_service.remove_member(db, principal.org_id, _actor(principal), membership_id)
    return Response(status_code=204)


# ----------------------------------------------------------------------------- API keys


@router.get("/api-keys", response_model=Page[ApiKeyOut])
def list_api_keys(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(_user_with("admin")),
    db: Session = Depends(get_db),
) -> Page[ApiKeyOut]:
    items, total = auth_service.list_api_keys(db, principal.org_id, limit=limit, offset=offset)
    return Page(items=[ApiKeyOut.model_validate(i) for i in items], total=total, limit=limit, offset=offset)


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    body: ApiKeyCreate, principal: Principal = Depends(_user_with("admin")), db: Session = Depends(get_db)
) -> ApiKeyCreated:
    key, raw, agent = auth_service.create_api_key(
        db,
        principal.org_id,
        _actor(principal),
        name=body.name,
        scopes=body.scopes,
        agent_id=body.agent_id,
        expires_in_days=body.expires_in_days,
    )
    creator = db.get(User, principal.user_id) if principal.user_id else None
    view = auth_service.api_key_view(key, agent.name if agent else None, creator.name if creator else None)
    return ApiKeyCreated(**view, key=raw)


@router.delete("/api-keys/{key_id}", status_code=204, response_class=Response)
def revoke_api_key(
    key_id: str, principal: Principal = Depends(_user_with("admin")), db: Session = Depends(get_db)
) -> Response:
    auth_service.revoke_api_key(db, principal.org_id, _actor(principal), key_id)
    return Response(status_code=204)
