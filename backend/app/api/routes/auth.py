"""Login, logout, current user, first-run bootstrap.

Browser sessions use an opaque token in an httpOnly, SameSite=Lax cookie. Cookie-authenticated
unsafe requests must carry ``X-Requested-With: contextos`` (enforced in ``app.api.deps`` and, for
logout, here).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import CSRF_HEADER, CSRF_VALUE, ORG_HEADER, Principal, require_user
from app.core.config import get_settings
from app.core.errors import ConflictError, PermissionDeniedError
from app.core.security import SESSION_TOKEN_PREFIX
from app.core.timeutil import utcnow
from app.database.session import get_db
from app.models import User
from app.schemas.auth import LoginIn, MeOut, SetupIn, SetupStatusOut
from app.services import auth_service
from app.services.audit import append_audit
from app.services.bootstrap import create_organization

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )


@router.get("/setup-status", response_model=SetupStatusOut)
def setup_status(db: Session = Depends(get_db)) -> SetupStatusOut:
    return SetupStatusOut(needs_setup=auth_service.needs_setup(db))


@router.post("/setup", response_model=MeOut, status_code=201)
def setup(body: SetupIn, request: Request, response: Response, db: Session = Depends(get_db)) -> MeOut:
    """First run only: create the organisation and its owner, seed defaults and sign in."""
    if not auth_service.needs_setup(db):
        raise ConflictError("This ContextOS server is already set up. Sign in instead.")
    org, user = create_organization(
        db, name=body.organization_name, owner_email=body.email, owner_name=body.name, password=body.password
    )
    token = auth_service.create_session(db, user, user_agent=request.headers.get("user-agent"))
    user.last_login_at = utcnow()
    append_audit(
        db,
        org.id,
        action="auth.setup_completed",
        actor_type="user",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"ip": _client_ip(request)},
    )
    _set_session_cookie(response, token)
    return auth_service.build_me(db, user, org.id, "owner")


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> MeOut:
    user, token = auth_service.login(
        db,
        email=body.email,
        password=body.password,
        client_ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    membership = auth_service.resolve_membership(db, user.id, request.headers.get(ORG_HEADER))
    if membership is None:
        raise PermissionDeniedError("Not a member of the requested organisation")
    _set_session_cookie(response, token)
    return auth_service.build_me(db, user, membership.organization_id, membership.role)


@router.post("/logout", status_code=204, response_class=Response)
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    """Revoke the current session (if any) and clear the cookie. Idempotent."""
    settings = get_settings()
    auth_header = request.headers.get("Authorization", "")
    from_cookie = False
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    else:
        token = request.cookies.get(settings.session_cookie_name, "")
        from_cookie = bool(token)
    if from_cookie and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise PermissionDeniedError("Missing CSRF header")
    if token.startswith(SESSION_TOKEN_PREFIX):
        revoked = auth_service.revoke_session(db, token)
        if revoked is not None:
            for membership, _org in auth_service.user_memberships(db, revoked.user_id):
                append_audit(
                    db,
                    membership.organization_id,
                    action="auth.logout",
                    actor_type="user",
                    actor_id=revoked.user_id,
                    target_type="auth_session",
                    target_id=revoked.id,
                )
    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(require_user), db: Session = Depends(get_db)) -> MeOut:
    user = db.get(User, principal.user_id)
    if user is None or principal.role is None:
        raise PermissionDeniedError("This endpoint requires a signed-in user")
    return auth_service.build_me(db, user, principal.org_id, principal.role)
