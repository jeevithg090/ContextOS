"""Authentication, authorisation and tenant scoping dependencies.

Two credential types:
- Browser users: opaque session token in an httpOnly cookie (or ``Authorization: Bearer ctxs_...``).
  Cookie-authenticated unsafe requests must carry ``X-Requested-With: contextos`` (CSRF defence).
- Integrations: API keys ``Authorization: Bearer ctxk_...`` with scopes (ingest / decide / read).

Every route receives a ``Principal`` and MUST scope queries with ``principal.org_id``
(use ``app.services.scoping``). Cross-organisation access is impossible by construction only if
that rule is followed — tests/integration/test_org_isolation_sweep.py requests every id route as another
organisation and fails on any non-404 answer (or an unclassified new route).

API keys bound to one agent (``Principal.bound_agent_id``) may only see that agent's records. Routes
that filter per agent (events, context, approvals, agents, sessions, simulation runs) apply the binding
themselves (another agent's record is 404); routes whose answers span every agent use
``require_org_wide`` and refuse bound keys with 403.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationError, NotFoundError, PermissionDeniedError
from app.core.logging import get_logger
from app.core.security import API_KEY_PREFIX, SESSION_TOKEN_PREFIX, hash_token
from app.core.timeutil import utcnow
from app.database.session import get_db, session_factory
from app.domain.enums import ROLE_PERMISSIONS
from app.models import ApiKey, AuthSession, Membership, User

ORG_HEADER = "X-ContextOS-Org"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "contextos"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
BOUND_KEY_MESSAGE = (
    "This API key is bound to one agent; this endpoint returns organisation-wide data. "
    "Use an unbound API key or sign in."
)
log = get_logger(__name__)


@dataclass
class Principal:
    org_id: str
    kind: str  # "user" | "api_key"
    permissions: set[str] = field(default_factory=set)
    user_id: str | None = None
    role: str | None = None
    api_key_id: str | None = None
    bound_agent_id: str | None = None  # API keys bound to one agent
    auth_session_id: str | None = None  # browser/CLI session behind a user principal

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
        auth_session_id=auth.id,
    )


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    token, from_cookie = _extract_token(request)
    if not token:
        raise AuthenticationError("Authentication required")
    if token.startswith(API_KEY_PREFIX):
        principal = _principal_from_api_key(db, token)
    elif token.startswith(SESSION_TOKEN_PREFIX):
        if (
            from_cookie
            and request.method in _UNSAFE_METHODS
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE
        ):
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


def require_org_wide(permission: str) -> Callable[..., Principal]:
    """``require(permission)`` that also refuses API keys bound to one agent (403).

    For routes whose answers span every agent of the organisation and are not filtered per agent.
    """

    def _dep(principal: Principal = Depends(require(permission))) -> Principal:
        if principal.bound_agent_id:
            raise PermissionDeniedError(BOUND_KEY_MESSAGE)
        return principal

    return _dep


def check_bound_agent(principal: Principal, agent_id: str | None, *, label: str, obj_id: str) -> None:
    """404 (never 403) when an agent-bound API key asks for a record that belongs to another agent."""
    if principal.bound_agent_id and agent_id != principal.bound_agent_id:
        raise NotFoundError(f"{label} '{obj_id}' not found")


def credential_still_valid(db: Session, principal: Principal, permission: str) -> bool:
    """Re-check, now, the credential a long-lived response (the SSE stream) was authorised with.

    False once the API key is revoked, expired or lost the scope, or the session is revoked or expired,
    the user disabled, or their membership removed or downgraded below ``permission``.
    """
    now = utcnow()
    if principal.kind == "api_key":
        key = db.scalar(
            select(ApiKey).where(
                ApiKey.id == principal.api_key_id, ApiKey.organization_id == principal.org_id
            )
        )
        return (
            key is not None
            and key.revoked_at is None
            and (key.expires_at is None or key.expires_at > now)
            and permission in (key.scopes or [])
        )
    if principal.auth_session_id is not None:
        auth = db.scalar(select(AuthSession).where(AuthSession.id == principal.auth_session_id))
        if auth is None or auth.revoked_at is not None or auth.expires_at <= now:
            return False
    user = db.get(User, principal.user_id) if principal.user_id else None
    if user is None or not user.is_active:
        return False
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id, Membership.organization_id == principal.org_id
        )
    )
    return membership is not None and permission in ROLE_PERMISSIONS.get(membership.role, set())


def recheck_credential(principal: Principal, permission: str) -> bool:
    """``credential_still_valid`` in its own short session (callable from a worker thread)."""
    db = session_factory()()
    try:
        return credential_still_valid(db, principal, permission)
    except Exception:  # noqa: BLE001 - cannot confirm the credential: treat it as no longer valid
        log.exception("auth.recheck_failed", extra={"org_id": principal.org_id, "kind": principal.kind})
        return False
    finally:
        db.close()


def require_user(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.kind != "user":
        raise PermissionDeniedError("This endpoint requires a signed-in user")
    return principal
