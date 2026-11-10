"""Authentication schemas: first-run setup, login and the ``GET /auth/me`` contract.

The ``MeOut`` shape is mirrored by ``frontend/src/features/auth/AuthProvider.tsx`` — change both
together.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 256

# Deliberately simple: one "@", no whitespace, a dot in the domain. Deliverability is not our concern
# (ContextOS never sends email); we only need a stable, unambiguous login identifier.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    """Lower-case and trim an email address; raise ``ValueError`` if it is not plausibly an email."""
    email = (value or "").strip().lower()
    if len(email) > 320 or not _EMAIL_RE.match(email):
        raise ValueError("Enter a valid email address")
    return email


def clean_name(value: str) -> str:
    """Trim a display name; reject names that are empty after trimming."""
    name = " ".join((value or "").split())
    if not name:
        raise ValueError("Must not be blank")
    return name


class _Strict(BaseModel):
    # Passwords are never trimmed or altered, so whitespace stripping is applied per field instead
    # of model-wide.
    model_config = ConfigDict(extra="forbid")


class SetupStatusOut(BaseModel):
    needs_setup: bool


class SetupIn(_Strict):
    organization_name: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    email: str
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("organization_name", "name")
    @classmethod
    def _clean_names(cls, value: str) -> str:
        return clean_name(value)


class LoginIn(BaseModel):
    # Not normalised through the strict validator: a malformed email must produce the same uniform
    # "invalid email or password" answer as an unknown one, not a 422 that hints at the cause.
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class MeUser(BaseModel):
    id: str
    email: str
    name: str


class MeOrganization(BaseModel):
    id: str
    name: str
    slug: str


class MeMembership(BaseModel):
    organization_id: str
    organization_name: str
    role: str


class MeOut(BaseModel):
    user: MeUser
    organization: MeOrganization
    role: str
    permissions: list[str]
    memberships: list[MeMembership]
