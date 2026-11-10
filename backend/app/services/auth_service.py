"""Identity services: login sessions, brute-force limiting, the ``/me`` view, members and API keys.

Security properties:
- Passwords are verified with scrypt; unknown emails are checked against a dummy hash so response
  time does not reveal whether an account exists. Every credential failure returns the same message.
- Repeated failures are rate limited per (email, client IP): 5 failures in 5 minutes → HTTP 429.
- Session tokens and API keys are random; only their SHA-256 hashes are stored. A raw API key is
  returned exactly once, at creation.
- Role changes that touch the ``owner`` role require an owner, and an organisation can never lose its
  last owner.

Functions take an explicit ``Actor`` rather than the HTTP ``Principal`` so the CLI can reuse them.
All writes happen in the caller's transaction, except where noted.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import (
    AppError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationFailedError,
)
from app.core.ids import new_id
from app.core.security import (
    generate_api_key,
    generate_session_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.core.timeutil import utcnow
from app.domain.enums import API_KEY_SCOPES, ROLE_PERMISSIONS, Role
from app.models import Agent, ApiKey, AuthSession, Membership, Organization, User
from app.schemas.auth import MeMembership, MeOrganization, MeOut, MeUser
from app.services.audit import append_audit
from app.services.bootstrap import validate_password
from app.services.scoping import get_scoped

INVALID_CREDENTIALS = "Invalid email or password"
_ROLES = {r.value for r in Role}


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"


@dataclass(frozen=True)
class Actor:
    """Who is performing an administrative action (for authorisation checks and the audit trail)."""

    type: str  # "user" | "api_key" | "system"
    id: str | None = None
    role: str | None = None

    @property
    def is_owner(self) -> bool:
        return self.type == "system" or self.role == Role.OWNER


SYSTEM_ACTOR = Actor(type="system")


# ----------------------------------------------------------------------------- rate limiting


class LoginRateLimiter:
    """In-memory sliding-window limiter for failed logins. Per process: with several API replicas the
    effective limit is multiplied by the replica count (documented limitation)."""

    def __init__(
        self,
        max_failures: int = 5,
        window_s: float = 300.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.max_failures = max_failures
        self.window_s = window_s
        self._clock = clock
        self._max_keys = max_keys
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float] | None:
        bucket = self._failures.get(key)
        if bucket is None:
            return None
        while bucket and bucket[0] <= now - self.window_s:
            bucket.popleft()
        if not bucket:
            del self._failures[key]
            return None
        return bucket

    def retry_after(self, key: str) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        with self._lock:
            now = self._clock()
            bucket = self._prune(key, now)
            if bucket is None or len(bucket) < self.max_failures:
                return 0
            return max(1, int(bucket[0] + self.window_s - now + 0.999))

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            if len(self._failures) >= self._max_keys:
                for stale in list(self._failures):
                    self._prune(stale, now)
            bucket = self._prune(key, now)
            if bucket is None:
                if len(self._failures) >= self._max_keys:
                    # Still full of live entries: evict the oldest key rather than grow unbounded.
                    oldest = min(self._failures, key=lambda k: self._failures[k][-1])
                    del self._failures[oldest]
                bucket = self._failures.setdefault(key, deque())
            bucket.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


login_limiter = LoginRateLimiter()


def rate_limit_key(email: str, client_ip: str | None) -> str:
    return f"{(email or '').strip().lower()}|{client_ip or '-'}"


# ----------------------------------------------------------------------------- sessions & login

_dummy_hash: str | None = None


def _dummy_password_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(24))
    return _dummy_hash


def needs_setup(db: Session) -> bool:
    return db.scalar(select(User.id).limit(1)) is None


def create_session(db: Session, user: User, *, user_agent: str | None = None) -> str:
    """Create a browser session and return the raw token (set it as the cookie; never log it)."""
    raw, token_hash = generate_session_token()
    db.add(
        AuthSession(
            id=new_id("auth_session"),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=utcnow() + timedelta(hours=get_settings().session_ttl_hours),
            user_agent=(user_agent or "")[:400] or None,
        )
    )
    db.flush()
    return raw


def revoke_session(db: Session, token: str) -> AuthSession | None:
    """Revoke the session for ``token``. Returns it if it was active, else ``None``."""
    auth = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if auth is None or auth.revoked_at is not None:
        return None
    auth.revoked_at = utcnow()
    return auth


def user_memberships(db: Session, user_id: str) -> list[tuple[Membership, Organization]]:
    rows = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user_id)
        .order_by(Membership.created_at, Membership.id)
    ).all()
    return [(m, o) for m, o in rows]


def _audit_each_org(db: Session, org_ids: Iterable[str], *, action: str, user_id: str, details: dict[str, Any]) -> None:
    for org_id in dict.fromkeys(org_ids):
        append_audit(
            db, org_id, action=action, actor_type="user", actor_id=user_id,
            target_type="user", target_id=user_id, details=details,
        )


def login(db: Session, *, email: str, password: str, client_ip: str | None, user_agent: str | None) -> tuple[User, str]:
    """Verify credentials and open a session. Returns ``(user, raw_session_token)``.

    On a credential failure the ``auth.login_failed`` audit entries are COMMITTED before the error is
    raised (the request transaction is rolled back on errors, which would otherwise drop them).
    """
    key = rate_limit_key(email, client_ip)
    wait = login_limiter.retry_after(key)
    if wait:
        raise RateLimitedError(
            f"Too many failed sign-in attempts. Try again in {wait} seconds.", details={"retry_after_s": wait}
        )

    user = db.scalar(select(User).where(User.email == (email or "").strip().lower()))
    if user is None:
        verify_password(password, _dummy_password_hash())  # equalise timing with the known-user path
        login_limiter.record_failure(key)
        raise AuthenticationError(INVALID_CREDENTIALS)

    memberships = user_memberships(db, user.id)
    if not verify_password(password, user.password_hash) or not user.is_active:
        login_limiter.record_failure(key)
        reason = "inactive_user" if user.is_active is False else "bad_password"
        _audit_each_org(
            db, (m.organization_id for m, _ in memberships), action="auth.login_failed",
            user_id=user.id, details={"reason": reason, "ip": client_ip},
        )
        db.commit()
        raise AuthenticationError(INVALID_CREDENTIALS)

    if not memberships:
        raise PermissionDeniedError("Your account is not a member of any organisation. Ask an administrator to add you.")

    login_limiter.reset(key)
    user.last_login_at = utcnow()
    token = create_session(db, user, user_agent=user_agent)
    _audit_each_org(
        db, (m.organization_id for m, _ in memberships), action="auth.login",
        user_id=user.id, details={"ip": client_ip},
    )
    return user, token


def resolve_membership(db: Session, user_id: str, requested_org: str | None = None) -> Membership | None:
    """The membership a session acts in: the requested org if given, else the oldest membership."""
    query = select(Membership).where(Membership.user_id == user_id)
    if requested_org:
        query = query.where(Membership.organization_id == requested_org)
    return db.scalars(query.order_by(Membership.created_at, Membership.id)).first()


def build_me(db: Session, user: User, org_id: str, role: str) -> MeOut:
    memberships = user_memberships(db, user.id)
    org = next((o for m, o in memberships if o.id == org_id), None) or db.get(Organization, org_id)
    if org is None:
        raise PermissionDeniedError("Not a member of the requested organisation")
    return MeOut(
        user=MeUser(id=user.id, email=user.email, name=user.name),
        organization=MeOrganization(id=org.id, name=org.name, slug=org.slug),
        role=role,
        permissions=sorted(ROLE_PERMISSIONS.get(role, set())),
        memberships=[MeMembership(organization_id=o.id, organization_name=o.name, role=m.role) for m, o in memberships],
    )


# ----------------------------------------------------------------------------- members


def _lock_org(db: Session, org_id: str) -> None:
    """Serialise owner-count checks per organisation (row lock on PostgreSQL; SQLite serialises writes)."""
    db.execute(select(Organization.id).where(Organization.id == org_id).with_for_update())


def _owner_count(db: Session, org_id: str) -> int:
    return int(
        db.scalar(
            select(func.count()).select_from(Membership)
            .where(Membership.organization_id == org_id, Membership.role == Role.OWNER.value)
        )
        or 0
    )


def _check_role(role: str) -> None:
    if role not in _ROLES:
        raise ValidationFailedError(f"Unknown role '{role}'")


def list_members(db: Session, org_id: str, *, limit: int, offset: int) -> tuple[list[tuple[Membership, User]], int]:
    base = select(Membership, User).join(User, User.id == Membership.user_id).where(Membership.organization_id == org_id)
    total = int(db.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == org_id)) or 0)
    rows = db.execute(base.order_by(Membership.created_at, Membership.id).limit(limit).offset(offset)).all()
    return [(m, u) for m, u in rows], total


def add_member(
    db: Session, org_id: str, actor: Actor, *, email: str, name: str, role: str, password: str | None
) -> tuple[Membership, User, bool]:
    """Add a member. Creates the user when the email is new (``password`` required); otherwise adds the
    existing user without touching their password or name. Returns ``(membership, user, created_user)``."""
    _check_role(role)
    if role == Role.OWNER and not actor.is_owner:
        raise PermissionDeniedError("Only an owner can add another owner")
    user = db.scalar(select(User).where(User.email == email))
    created = False
    if user is None:
        if not password:
            raise ValidationFailedError("A password is required to create a new user")
        validate_password(password)
        user = User(id=new_id("user"), email=email, name=name, password_hash=hash_password(password))
        db.add(user)
        db.flush()
        created = True
    elif db.scalar(select(Membership.id).where(Membership.organization_id == org_id, Membership.user_id == user.id)):
        raise ConflictError(f"{email} is already a member of this organisation")
    membership = Membership(id=new_id("membership"), organization_id=org_id, user_id=user.id, role=role)
    db.add(membership)
    db.flush()
    append_audit(
        db, org_id, action="member.added", actor_type=actor.type, actor_id=actor.id,
        target_type="membership", target_id=membership.id,
        details={"user_id": user.id, "email": email, "role": role, "new_user": created},
    )
    return membership, user, created


def change_member_role(db: Session, org_id: str, actor: Actor, membership_id: str, role: str) -> tuple[Membership, User]:
    _check_role(role)
    _lock_org(db, org_id)
    membership = get_scoped(db, Membership, membership_id, org_id, label="Member")
    user = db.get(User, membership.user_id)
    if user is None:  # cannot happen while the FK holds; never act on a dangling membership
        raise NotFoundError(f"Member '{membership_id}' not found")
    previous = membership.role
    if previous == role:
        return membership, user
    if Role.OWNER in (previous, role) and not actor.is_owner:
        raise PermissionDeniedError("Only an owner can grant or remove the owner role")
    if previous == Role.OWNER and _owner_count(db, org_id) <= 1:
        raise ConflictError("This is the organisation's last owner. Make someone else an owner first.")
    membership.role = role
    append_audit(
        db, org_id, action="member.role_changed", actor_type=actor.type, actor_id=actor.id,
        target_type="membership", target_id=membership.id,
        details={"user_id": user.id, "from": previous, "to": role},
    )
    return membership, user


def remove_member(db: Session, org_id: str, actor: Actor, membership_id: str) -> None:
    _lock_org(db, org_id)
    membership = get_scoped(db, Membership, membership_id, org_id, label="Member")
    if actor.type == "user" and membership.user_id == actor.id:
        raise ConflictError("You cannot remove yourself. Ask another administrator to do it.")
    if membership.role == Role.OWNER:
        if not actor.is_owner:
            raise PermissionDeniedError("Only an owner can remove an owner")
        if _owner_count(db, org_id) <= 1:
            raise ConflictError("This is the organisation's last owner and cannot be removed.")
    details = {"user_id": membership.user_id, "role": membership.role}
    db.delete(membership)
    db.flush()
    append_audit(
        db, org_id, action="member.removed", actor_type=actor.type, actor_id=actor.id,
        target_type="membership", target_id=membership_id, details=details,
    )


# ----------------------------------------------------------------------------- API keys


def api_key_status(key: ApiKey) -> str:
    if key.revoked_at is not None:
        return "revoked"
    if key.expires_at is not None and key.expires_at <= utcnow():
        return "expired"
    return "active"


def list_api_keys(db: Session, org_id: str, *, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
    query = (
        select(ApiKey, Agent.name, User.name)
        .outerjoin(Agent, (Agent.id == ApiKey.agent_id) & (Agent.organization_id == org_id))
        .outerjoin(User, User.id == ApiKey.created_by_user_id)
        .where(ApiKey.organization_id == org_id)
    )
    total = int(db.scalar(select(func.count()).select_from(ApiKey).where(ApiKey.organization_id == org_id)) or 0)
    rows = db.execute(query.order_by(ApiKey.created_at.desc(), ApiKey.id.desc()).limit(limit).offset(offset)).all()
    return [api_key_view(key, agent_name, creator) for key, agent_name, creator in rows], total


def api_key_view(key: ApiKey, agent_name: str | None = None, creator_name: str | None = None) -> dict[str, Any]:
    """Display fields for an API key. Never includes the hash."""
    return {
        "id": key.id,
        "name": key.name,
        "prefix": key.prefix,
        "scopes": sorted(key.scopes or []),
        "agent_id": key.agent_id,
        "agent_name": agent_name,
        "created_by_user_id": key.created_by_user_id,
        "created_by_name": creator_name,
        "created_at": key.created_at,
        "last_used_at": key.last_used_at,
        "expires_at": key.expires_at,
        "revoked_at": key.revoked_at,
        "status": api_key_status(key),
    }


def create_api_key(
    db: Session,
    org_id: str,
    actor: Actor,
    *,
    name: str,
    scopes: Iterable[str],
    agent_id: str | None = None,
    expires_in_days: int | None = None,
) -> tuple[ApiKey, str, Agent | None]:
    """Create an API key. Returns ``(row, raw_key, bound_agent)``; show ``raw_key`` once, never store it."""
    scope_set = set(scopes)
    if not scope_set:
        raise ValidationFailedError("Choose at least one scope")
    unknown = scope_set - API_KEY_SCOPES
    if unknown:
        raise ValidationFailedError(f"Unknown scope(s): {', '.join(sorted(unknown))}. Allowed: ingest, decide, read")
    if expires_in_days is not None and not 1 <= expires_in_days <= 3650:
        raise ValidationFailedError("Expiry must be between 1 and 3650 days")
    agent = get_scoped(db, Agent, agent_id, org_id, label="Agent") if agent_id else None
    raw, prefix, key_hash = generate_api_key()
    key = ApiKey(
        id=new_id("api_key"),
        organization_id=org_id,
        name=name,
        prefix=prefix,
        key_hash=key_hash,
        scopes=sorted(scope_set),
        agent_id=agent.id if agent else None,
        created_by_user_id=actor.id if actor.type == "user" else None,
        expires_at=utcnow() + timedelta(days=expires_in_days) if expires_in_days else None,
    )
    db.add(key)
    db.flush()
    append_audit(
        db, org_id, action="api_key.created", actor_type=actor.type, actor_id=actor.id,
        target_type="api_key", target_id=key.id,
        details={"name": name, "prefix": prefix, "scopes": key.scopes, "agent_id": key.agent_id,
                 "expires_in_days": expires_in_days},
    )
    return key, raw, agent


def revoke_api_key(db: Session, org_id: str, actor: Actor, key_id: str) -> ApiKey:
    key = get_scoped(db, ApiKey, key_id, org_id, label="API key")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        append_audit(
            db, org_id, action="api_key.revoked", actor_type=actor.type, actor_id=actor.id,
            target_type="api_key", target_id=key.id, details={"name": key.name, "prefix": key.prefix},
        )
    return key
