"""API schemas for the integration registry: connected integrations, capability catalog, setup guides.

Enforcement vocabulary is the same as everywhere else (``app.domain.enums.EnforcementMode``):
``enforced`` (decided at an execution boundary that honours the decision), ``advisory`` (decision
returned, but the integration may not honour it), ``observed`` (reported after the fact).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

EnforcementLiteral = Literal["enforced", "advisory", "observed"]
HealthLiteral = Literal["connected", "stale", "never_seen"]
CatalogStatus = Literal["supported", "planned"]


class CapabilityOut(BaseModel):
    """One thing an integration can see (monitoring) or stop (enforcement)."""

    name: str
    mode: EnforcementLiteral
    description: str


class CatalogEntryOut(BaseModel):
    kind: str
    name: str
    status: CatalogStatus
    summary: str
    # Strongest enforcement this integration can provide; None for planned integrations.
    best_enforcement: EnforcementLiteral | None
    monitoring: list[CapabilityOut]
    enforcement: list[CapabilityOut]
    limitations: list[str]
    # Planned integrations: the host surface a native adapter would most likely use.
    integration_surface: str | None = None
    # Planned integrations: what can be used today (an existing adapter), if anything.
    available_today: str | None = None
    interim_kind: str | None = None
    docs_path: str | None = None
    api_key_scopes: list[str] = Field(default_factory=list)
    # Health of this kind in the caller's organisation (best across its integration rows).
    health: HealthLiteral = "never_seen"
    last_event_at: datetime | None = None


class EnforcementCountsOut(BaseModel):
    """Recorded policy decisions (real traffic only) by the enforcement claim stored with them."""

    enforced: int = 0
    advisory: int = 0
    observed: int = 0


class ConnectedIntegrationOut(BaseModel):
    id: str
    kind: str
    name: str
    display_name: str
    supported: bool  # a first-party ContextOS adapter exists for this kind
    best_enforcement: EnforcementLiteral
    health: HealthLiteral
    health_detail: str
    first_seen_at: datetime
    last_event_at: datetime | None
    event_count: int
    decision_count: int
    events_24h: int
    decisions: EnforcementCountsOut
    agent_count: int
    last_error: str | None = None


class IntegrationsOut(BaseModel):
    connected: list[ConnectedIntegrationOut]
    catalog: list[CatalogEntryOut]
    # Connected = an event within this window; the same rule the Overview uses.
    stale_after_minutes: int
    stale_after_hours: int
    generated_at: datetime


class SetupCommandOut(BaseModel):
    language: str  # bash | json | toml | python
    code: str
    title: str | None = None


class SetupLinkOut(BaseModel):
    label: str
    href: str  # in-app route, e.g. "/settings?tab=api-keys"


class SetupStepOut(BaseModel):
    title: str
    description: str
    commands: list[SetupCommandOut] = Field(default_factory=list)
    link: SetupLinkOut | None = None


class SetupScopeOut(BaseModel):
    scope: str
    required: bool
    purpose: str


class SetupGuideOut(BaseModel):
    kind: str
    name: str
    status: CatalogStatus
    # For planned integrations the steps describe the interim path through an existing adapter.
    interim_kind: str | None = None
    server_url: str
    server_url_note: str
    api_key_scopes: list[SetupScopeOut]
    steps: list[SetupStepOut]
    verification: str
    notes: list[str]
    docs_path: str | None = None
    # The organisation's fail mode written into the setup commands (None when unknown).
    fail_mode: str | None = None
