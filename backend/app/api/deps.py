"""Authentication, authorisation and tenant scoping dependencies.

Two credential types:
- Browser users: opaque session token in an httpOnly cookie (or ``Authorization: Bearer ctxs_...``).
  Cookie-authenticated unsafe requests must carry ``X-Requested-With: contextos`` (CSRF defence).
- Integrations: API keys ``Authorization: Bearer ctxk_...`` with scopes (ingest / decide / read).

Every route receives a ``Principal`` and MUST scope queries with ``principal.org_id``
(use ``app.services.scoping``). Cross-organisation access is impossible by construction only if
that rule is followed — tests in tests/integration/test_isolation.py enforce it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.security import API_KEY_PREFIX, SESSION_TOKEN_PREFIX, hash_token
from app.core.timeutil import utcnow
from app.database.session import get_db
from app.domain.enums import ROLE_PERMISSIONS
from app.models import ApiKey, AuthSession, Membership, User

ORG_HEADER = "X-ContextOS-Org"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "contextos"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Principal:
    org_id: str
    kind: str  # "user" | "api_key"
    permissions: set[str] = field(default_factory=set)
    user_id: str | None = None
    role: str | None = None
    api_key_id: str | None = None
    bound_agent_id: str | None = None  # API keys bound to one agent

    @property
    def actor_type(self) -> str:
        return self.kind

    @property
    def actor_id(self) -> str | None:
        return self.user_id or self.api_key_id

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise PermissionDeniedError(f"Missing permission '{permission}'")


def _extract_token(request: Request) -> tuple[str | None, bool]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip(), False
    cookie = request.cookies.get(get_settings().session_cookie_name)
    return (cookie, True) if cookie else (None, False)


def _principal_from_api_key(db: Session, token: str) -> Principal:
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(token)))
    now = utcnow()
    if key is None or key.revoked_at is not None or (key.expires_at is not None and key.expires_at <= now):
        raise AuthenticationError("Invalid or revoked API key")
    key.last_used_at = now
    return Principal(
        org_id=key.organization_id,
        kind="api_key",
        permissions=set(key.scopes or []),
        api_key_id=key.id,
        bound_agent_id=key.agent_id,
    )


def _principal_from_session(db: Session, token: str, requested_org: str | None) -> Principal:
    auth = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    now = utcnow()
    if auth is None or auth.revoked_at is not None or auth.expires_at <= now:
        raise AuthenticationError("Session expired — sign in again")
    user = db.get(User, auth.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User is disabled")
    query = select(Membership).where(Membership.user_id == user.id)
    if requested_org:
        query = query.where(Membership.organization_id == requested_org)
    membership = db.scalars(query.order_by(Membership.created_at)).first()
    if membership is None:
        raise PermissionDeniedError("Not a member of the requested organisation")
    return Principal(
        org_id=membership.organization_id,
        kind="user",
        permissions=set(ROLE_PERMISSIONS.get(membership.role, set())),
        user_id=user.id,
        role=membership.role,
    )


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    token, from_cookie = _extract_token(request)
    if not token:
        raise AuthenticationError("Authentication required")
    if token.startswith(API_KEY_PREFIX):
        principal = _principal_from_api_key(db, token)
    elif token.startswith(SESSION_TOKEN_PREFIX):
        if from_cookie and request.method in _UNSAFE_METHODS and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise PermissionDeniedError("Missing CSRF header")
        principal = _principal_from_session(db, token, request.headers.get(ORG_HEADER))
    else:
        raise AuthenticationError("Unrecognised credential")
    request.state.principal = principal
    return principal


def require(permission: str) -> Callable[..., Principal]:
    """Dependency factory: ``principal: Principal = Depends(require("policy:manage"))``."""

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        principal.require(permission)
        return principal

    return _dep


def require_user(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.kind != "user":
        raise PermissionDeniedError("This endpoint requires a signed-in user")
    return principal
