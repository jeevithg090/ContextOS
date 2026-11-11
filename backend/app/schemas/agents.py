"""Agent registry schemas: inventory, registration, profile edits, observed tools, posture and the
identity/delegation graph. Mirrored by ``frontend/src/features/agents/types.ts``.

Tool categories and risk levels are always classified server-side (``risk.classify_tool``); a
category sent at registration is only a hint, recorded next to the server's classification.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.enums import ToolCategory
from app.schemas.common import Page
from app.schemas.sessions import FindingBriefOut

EnvironmentName = Literal["development", "staging", "production"]
AgentStatusName = Literal["active", "inactive", "quarantined"]
AgentSort = Literal["last_seen", "risk", "name", "created"]

QUARANTINE_LABEL = "quarantined"
MAX_LABELS = 30
LABEL_MAX = 64
MAX_DECLARED_TOOLS = 200
MAX_LIST_ENTRIES = 100
GRAPH_NOTE = (
    "Edges are delegations and messages ContextOS observed between agents. They show who handed work or "
    "content to whom, not that one agent caused another's actions."
)
_FRAMEWORK = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")


def _clean_text_list(values: list[str] | None, *, max_items: int, max_len: int, lower: bool = False) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        value = " ".join(str(raw).split())
        if lower:
            value = value.lower()
        if not value:
            continue
        if len(value) > max_len:
            raise ValueError(f"entries must be at most {max_len} characters")
        if value not in out:
            out.append(value)
    if len(out) > max_items:
        raise ValueError(f"at most {max_items} entries")
    return out


def clean_labels(labels: list[str] | None) -> list[str]:
    cleaned = _clean_text_list(labels, max_items=MAX_LABELS, max_len=LABEL_MAX, lower=True)
    if QUARANTINE_LABEL in cleaned:
        raise ValueError(f"the label '{QUARANTINE_LABEL}' is reserved: set status to 'quarantined' instead")
    return cleaned


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeclaredToolIn(_In):
    name: str = Field(min_length=1, max_length=200)
    category: ToolCategory | None = Field(default=None, description="Hint only; ContextOS classifies the tool")

    @field_validator("name")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("tool name must not be blank")
        return value


class DeclaredCapabilitiesIn(_In):
    tools: list[DeclaredToolIn] = Field(default_factory=list, max_length=MAX_DECLARED_TOOLS)
    permissions: list[str] = Field(default_factory=list, max_length=MAX_LIST_ENTRIES)
    mcp_servers: list[str] = Field(default_factory=list, max_length=MAX_LIST_ENTRIES)

    @field_validator("tools")
    @classmethod
    def _unique_tools(cls, tools: list[DeclaredToolIn]) -> list[DeclaredToolIn]:
        seen: dict[str, DeclaredToolIn] = {}
        for tool in tools:
            seen.setdefault(tool.name, tool)
        return list(seen.values())

    @field_validator("permissions", "mcp_servers")
    @classmethod
    def _clean(cls, values: list[str]) -> list[str]:
        return _clean_text_list(values, max_items=MAX_LIST_ENTRIES, max_len=200)


class AgentCreate(_In):
    name: str = Field(min_length=1, max_length=200, description="Must match the name the integration reports")
    description: str | None = Field(default=None, max_length=4000)
    framework: str = Field(default="custom", max_length=64)
    version: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default=None, max_length=200)
    environment: EnvironmentName = "development"
    labels: list[str] = Field(default_factory=list)
    declared_capabilities: DeclaredCapabilitiesIn = Field(default_factory=DeclaredCapabilitiesIn)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("framework")
    @classmethod
    def _framework(cls, value: str) -> str:
        value = value.strip().lower() or "custom"
        if not _FRAMEWORK.match(value):
            raise ValueError("framework may contain lowercase letters, digits and _ . : - only")
        return value

    @field_validator("labels")
    @classmethod
    def _labels(cls, value: list[str]) -> list[str]:
        return clean_labels(value)


class AgentPatch(_In):
    """Partial update. Omitted fields are unchanged; ``null`` clears description/owner.

    ``environment``, ``labels`` and ``status`` are inputs to policy evaluation, so changing them
    requires ``policy:manage`` in addition to ``write``.
    """

    description: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=200)
    environment: EnvironmentName | None = None
    labels: list[str] | None = None
    status: AgentStatusName | None = None
    declared_capabilities: DeclaredCapabilitiesIn | None = None

    @field_validator("labels")
    @classmethod
    def _labels(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else clean_labels(value)


# ----------------------------------------------------------------------------- read models


class DeclaredToolOut(BaseModel):
    name: str
    category: str
    risk_level: str
    category_hint: str | None = None


class DeclaredCapabilitiesOut(BaseModel):
    tools: list[DeclaredToolOut]
    permissions: list[str]
    mcp_servers: list[str]


class AgentSummaryOut(BaseModel):
    id: str
    name: str
    description: str | None
    framework: str
    version: str | None
    owner: str | None
    environment: str
    labels: list[str]
    status: str
    is_simulation: bool
    created_at: datetime
    last_seen_at: datetime | None
    risk_score: int = Field(description="Highest risk score among the agent's active sessions")
    risk_level: str
    session_count: int
    active_session_count: int
    open_findings: int = Field(description="Findings for this agent that are open or acknowledged")
    max_open_severity: str | None
    declared_tool_count: int
    observed_tool_count: int
    integration_kind: str | None


class FacetCount(BaseModel):
    value: str
    count: int


class AgentFacets(BaseModel):
    frameworks: list[FacetCount]
    environments: list[FacetCount]
    statuses: list[FacetCount]
    simulated: int = Field(description="Simulation Lab agents (hidden unless include_simulated=true)")


class AgentPage(Page[AgentSummaryOut]):
    facets: AgentFacets


class IntegrationRefOut(BaseModel):
    id: str
    kind: str
    name: str
    status: str
    last_event_at: datetime | None
    supports_enforcement: bool
    enforcement_basis: str


class QuarantinePolicyOut(BaseModel):
    id: str
    name: str
    outcome: str
    scope: Literal["all_calls", "some_calls"]


class QuarantineOut(BaseModel):
    active: bool
    label: str = QUARANTINE_LABEL
    enforced: bool = Field(description="An enabled enforce-mode policy denies or gates every call of a quarantined agent")
    policies: list[QuarantinePolicyOut]
    explanation: str
    suggested_policy: dict[str, object]


class RelatedAgentOut(BaseModel):
    id: str
    name: str
    framework: str
    environment: str
    status: str
    risk_score: int
    risk_level: str


class AgentRelationshipOut(BaseModel):
    id: str
    direction: Literal["outgoing", "incoming"]  # outgoing: this agent delegated to / messaged the other
    relationship_type: str
    other_agent: RelatedAgentOut
    event_count: int
    crosses_trust_boundary: bool
    first_seen_at: datetime
    last_seen_at: datetime
    last_parent_session_id: str | None
    last_child_session_id: str | None


class AgentDetailOut(AgentSummaryOut):
    declared_capabilities: DeclaredCapabilitiesOut
    integration: IntegrationRefOut | None
    findings_by_severity: dict[str, int]
    recent_findings: list[FindingBriefOut]
    relationships: list[AgentRelationshipOut]
    decisions_by_enforcement: dict[str, int]
    quarantine: QuarantineOut


class AgentToolOut(BaseModel):
    tool_id: str | None
    name: str
    provider: str | None
    server: str | None
    category: str
    risk_level: str
    classification_reason: str | None
    declared: bool
    observed: bool
    invocation_count: int
    first_used_at: datetime | None
    last_used_at: datetime | None
    decisions: dict[str, int]
    statuses: dict[str, int]
    enforcement: dict[str, int]
    credential_calls: int = Field(description="Calls whose arguments contained a credential (stored redacted)")


class PostureEvidenceOut(BaseModel):
    type: str
    id: str
    detail: str


class PostureDimensionOut(BaseModel):
    key: str
    label: str
    score: int
    max_score: int
    explanation: str
    evidence: list[PostureEvidenceOut]
    recommendation: str | None


class PostureBasisOut(BaseModel):
    declared_tool_count: int
    observed_tool_count: int
    enabled_policy_count: int
    approval_policy_count: int
    trust_rule_count: int
    untrusted_source_count: int
    open_finding_count: int
    sessions_with_trifecta: int
    total_sessions: int
    integration_kind: str | None
    supports_enforcement: bool
    decisions_by_enforcement: dict[str, int]


class AgentPostureOut(BaseModel):
    agent_id: str
    score: int
    grade: str
    summary: str
    dimensions: list[PostureDimensionOut]
    basis: PostureBasisOut
    computed_at: datetime


class GraphNodeOut(BaseModel):
    id: str
    name: str
    owner: str | None
    framework: str
    environment: str
    status: str
    risk_score: int
    risk_level: str
    is_simulation: bool
    session_count: int
    open_findings: int


class GraphEdgeOut(BaseModel):
    id: str
    source: str  # parent / sending agent
    target: str  # child / receiving agent
    relationship_type: str
    event_count: int
    crosses_trust_boundary: bool
    first_seen_at: datetime
    last_seen_at: datetime
    last_parent_session_id: str | None
    last_child_session_id: str | None


class AgentGraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    truncated: bool
    note: str = GRAPH_NOTE
