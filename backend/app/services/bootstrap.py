"""Organisation bootstrap: create a tenant with its owner, seed its defaults, resolve its settings.

Used by first-run setup (``POST /auth/setup``), the ``contextos-server create-org`` CLI command and
tests. Everything happens in the caller's transaction; the caller commits.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, ValidationFailedError
from app.core.ids import new_id
from app.core.security import hash_password, verify_password
from app.domain.enums import Role
from app.engines.redaction import redact_text
from app.models import Board, Membership, Organization, User
from app.schemas.auth import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, clean_name, normalize_email
from app.services.audit import append_audit
from app.services.seed import seed_security_defaults
from app.services.workspace_boards import seed_default_board

_SLUG_MAX = 60


def default_org_settings() -> dict[str, Any]:
    """Server defaults for organisation settings (stored explicitly on new organisations).

    - ``fail_mode``: what integrations should do when ContextOS cannot be reached. ``closed`` = deny,
      ``open`` = allow, ``ask`` = defer to the agent host's own permission prompt. Applied by each
      integration locally (ContextOS cannot answer while unreachable); used as the default in
      generated integration setup.
    - ``default_decision``: the policy outcome when no policy matches (``ALLOW`` or ``AUDIT``).
    - ``approval_timeout_s``: how long an approval request waits before it expires.
    - ``retention_days``: how long recorded event data is meant to be kept.
    - ``store_previews``: whether redacted, truncated content previews are stored alongside hashes.
    """
    settings = get_settings()
    return {
        "retention_days": settings.retention_days,
        "fail_mode": "ask",
        "default_decision": "ALLOW",
        "approval_timeout_s": settings.approval_default_timeout_s,
        "store_previews": True,
    }


def effective_org_settings(org: Organization) -> dict[str, Any]:
    """Stored settings merged over the defaults. Unknown stored keys are preserved."""
    return {**default_org_settings(), **(org.settings or {})}


def update_org_settings(
    db: Session, org: Organization, changes: dict[str, Any], *, actor_type: str, actor_id: str | None
) -> dict[str, dict[str, Any]]:
    """Apply validated changes (``name`` plus settings keys). Returns ``{field: {"from", "to"}}`` for
    the fields that actually changed and audits them as ``organization.settings_updated``."""
    current = effective_org_settings(org)
    diff: dict[str, dict[str, Any]] = {}
    new_settings = dict(org.settings or {})
    for field, value in changes.items():
        if field == "name":
            value = redact_name(value)
            if value != org.name:
                diff["name"] = {"from": org.name, "to": value}
                org.name = value
            continue
        if field not in current:
            raise ValidationFailedError(f"Unknown setting '{field}'")
        if current[field] != value:
            diff[field] = {"from": current[field], "to": value}
        new_settings[field] = value
    if diff:
        # Assign a new dict so SQLAlchemy detects the change to the JSON column.
        org.settings = {**default_org_settings(), **new_settings}
        append_audit(
            db, org.id, action="organization.settings_updated", actor_type=actor_type, actor_id=actor_id,
            target_type="organization", target_id=org.id, details={"changes": diff},
        )
    return diff


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return (slug or "org")[:_SLUG_MAX].strip("-") or "org"


def unique_slug(db: Session, name: str) -> str:
    base = slugify(name)
    candidate = base
    suffix = 2
    while db.scalar(select(Organization.id).where(Organization.slug == candidate)) is not None:
        tail = f"-{suffix}"
        candidate = base[: _SLUG_MAX - len(tail)] + tail
        suffix += 1
    return candidate


def redact_name(value: str) -> str:
    """A display name (organisation, user, API key) with any credential pasted into it redacted."""
    return redact_text(value).text


def validate_password(password: str) -> None:
    if not password or len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationFailedError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValidationFailedError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")


def create_organization(
    db: Session, *, name: str, owner_email: str, owner_name: str, password: str
) -> tuple[Organization, User]:
    """Create an organisation, its owner membership and its security defaults.

    If ``owner_email`` already belongs to a user, that user becomes the owner only when ``password``
    is their current password (an operator cannot silently attach someone else's account).
    """
    try:
        org_name = redact_name(clean_name(name))
        email = normalize_email(owner_email)
        display_name = redact_name(clean_name(owner_name))
    except ValueError as exc:
        raise ValidationFailedError(str(exc)) from exc
    if len(org_name) > 200 or len(display_name) > 200:
        raise ValidationFailedError("Names must be at most 200 characters")

    user = db.scalar(select(User).where(User.email == email))
    if user is not None:
        if not verify_password(password, user.password_hash):
            raise ConflictError(
                "A user with this email already exists. Supply their current password to make them "
                "the owner of the new organisation."
            )
    else:
        validate_password(password)
        user = User(id=new_id("user"), email=email, name=display_name, password_hash=hash_password(password))
        db.add(user)

    org = Organization(id=new_id("organization"), name=org_name, slug=unique_slug(db, org_name), settings=default_org_settings())
    db.add(org)
    db.flush()
    membership = Membership(id=new_id("membership"), organization_id=org.id, user_id=user.id, role=Role.OWNER.value)
    db.add(membership)
    db.flush()

    append_audit(
        db,
        org.id,
        action="organization.created",
        actor_type="user",
        actor_id=user.id,
        target_type="organization",
        target_id=org.id,
        details={"name": org.name, "slug": org.slug, "owner_user_id": user.id},
    )
    seeded = seed_org_defaults(db, org.id, created_by=user.id)
    append_audit(
        db,
        org.id,
        action="organization.defaults_seeded",
        actor_type="system",
        target_type="organization",
        target_id=org.id,
        details=seeded,
    )
    return org, user


def seed_org_defaults(db: Session, org_id: str, created_by: str | None = None) -> dict[str, Any]:
    """Install the built-in policy pack, default trust rules and the default Engineering Workspace boards.

    Idempotent. Returns counts of what was created.
    """
    result: dict[str, Any] = dict(seed_security_defaults(db, org_id))
    boards = seed_default_board(db, org_id, created_by)
    result["default_board"] = bool(boards) or _has_boards(db, org_id)
    result["boards_created"] = len(boards)
    return result


def _has_boards(db: Session, org_id: str) -> bool:
    return db.scalar(select(func.count()).select_from(Board).where(Board.organization_id == org_id)) > 0
