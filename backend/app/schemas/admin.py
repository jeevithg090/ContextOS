"""Organisation administration schemas: settings, members and API keys."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.auth import PASSWORD_MAX_LENGTH, clean_name, normalize_email

FailMode = Literal["closed", "open", "ask"]
DefaultDecision = Literal["ALLOW", "AUDIT"]
ApiKeyScope = Literal["ingest", "decide", "read"]
RoleName = Literal["owner", "admin", "security_analyst", "developer", "viewer"]  # == domain.enums.Role

RETENTION_DAYS_RANGE = (1, 3650)
APPROVAL_TIMEOUT_RANGE = (30, 86_400)


# ----------------------------------------------------------------------------- organisation


class OrgSettingsOut(BaseModel):
    """Effective settings: stored values merged over the server defaults."""

    retention_days: int
    fail_mode: FailMode
    default_decision: DefaultDecision
    approval_timeout_s: int
    store_previews: bool


class OrgOut(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime
    settings: OrgSettingsOut
    member_count: int
    active_api_key_count: int


class OrgSettingsPatch(BaseModel):
    """Partial update. Omitted fields are left unchanged; unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    retention_days: int | None = Field(default=None, ge=RETENTION_DAYS_RANGE[0], le=RETENTION_DAYS_RANGE[1])
    fail_mode: FailMode | None = None
    default_decision: DefaultDecision | None = None
    approval_timeout_s: int | None = Field(default=None, ge=APPROVAL_TIMEOUT_RANGE[0], le=APPROVAL_TIMEOUT_RANGE[1])
    store_previews: bool | None = None

    @field_validator("name")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return None if value is None else clean_name(value)


# ----------------------------------------------------------------------------- members


class MemberOut(BaseModel):
    id: str  # membership id (used by PATCH/DELETE /org/members/{id})
    user_id: str
    name: str
    email: str
    role: RoleName
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class MemberCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    name: str = Field(min_length=1, max_length=200)
    role: RoleName
    # Required only when the email does not belong to an existing user. An existing user's password
    # is never changed through this endpoint.
    password: str | None = Field(default=None, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_name(value)


class MemberRoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: RoleName


# ----------------------------------------------------------------------------- API keys


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str  # first characters of the key; safe to display, never enough to authenticate
    scopes: list[str]
    agent_id: str | None
    agent_name: str | None
    created_by_user_id: str | None
    created_by_name: str | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    status: Literal["active", "expired", "revoked"]


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    scopes: list[ApiKeyScope] = Field(min_length=1)
    agent_id: str | None = Field(default=None, max_length=40)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_name(value)

    @field_validator("scopes")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return sorted(set(value))

    @field_validator("agent_id")
    @classmethod
    def _blank_agent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="The raw API key. Shown exactly once; only its hash is stored.")
