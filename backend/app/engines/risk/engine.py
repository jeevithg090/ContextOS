"""STUB — to be implemented by the risk work package. Keep these signatures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolClassification:
    category: str  # ToolCategory
    risk_level: str  # RiskLevel
    outbound: bool  # can transmit data outside the environment
    reads_sensitive: bool  # typically reads private data (files, DB, env)
    reason: str


@dataclass
class SessionSignals:
    """Observable facts about one session, assembled by the ingestion service from the DB."""

    # [{"id", "trust_level", "source_type", "source_id", "contains_secrets", "sensitivity",
    #   "detection_max_severity": str|None, "detection_categories": [...]}]
    context_items: list[dict[str, Any]] = field(default_factory=list)
    # [{"id", "tool_name", "category", "status", "decision", "sensitive_resources": [...],
    #   "destination_classification": str|None, "outbound": bool, "sensitive_data_detected": bool}]
    tool_invocations: list[dict[str, Any]] = field(default_factory=list)
    # Agent's declared tools (capability, not usage): [{"name","category"}]
    declared_tools: list[dict[str, Any]] = field(default_factory=list)
    # [{"id","category","severity","status"}]
    findings: list[dict[str, Any]] = field(default_factory=list)
    inherited_risk: dict[str, Any] = field(default_factory=dict)  # from a parent/child session


@dataclass
class RiskFactor:
    key: str
    label: str
    weight: int  # contribution to the 0-100 score
    explanation: str
    evidence: list[dict[str, str]] = field(default_factory=list)  # [{"type","id","detail"}]


@dataclass
class SessionRisk:
    score: int
    level: str  # RiskLevel
    sensitive_access: bool
    untrusted_exposure: bool
    outbound_channel: bool
    factors: list[RiskFactor] = field(default_factory=list)
    # {"sensitive_access": [evidence], "untrusted_exposure": [...], "outbound_channel": [...]}
    trifecta_evidence: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    summary: str = ""

    @property
    def trifecta(self) -> bool:
        return self.sensitive_access and self.untrusted_exposure and self.outbound_channel

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trifecta"] = self.trifecta
        return data


@dataclass
class PostureInputs:
    agent: dict[str, Any]  # {"id","name","environment","framework","status"}
    declared_tools: list[dict[str, Any]] = field(default_factory=list)
    observed_tools: list[dict[str, Any]] = field(default_factory=list)  # [{"name","category","risk_level","count"}]
    policies: list[dict[str, Any]] = field(default_factory=list)  # enabled policies: [{"id","name","outcome","mode","conditions"}]
    trust_rule_count: int = 0
    untrusted_source_count: int = 0
    open_findings: list[dict[str, Any]] = field(default_factory=list)  # [{"id","severity","category"}]
    integration: dict[str, Any] = field(default_factory=dict)  # {"kind","supports_enforcement","status"}
    approval_policy_count: int = 0
    sessions_with_trifecta: int = 0
    total_sessions: int = 0


@dataclass
class PostureDimension:
    key: str
    label: str
    score: int
    max_score: int
    explanation: str
    evidence: list[dict[str, str]] = field(default_factory=list)
    recommendation: str | None = None


@dataclass
class PostureAssessment:
    score: int  # 0-100, higher is better
    grade: str  # A-F
    dimensions: list[PostureDimension] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_tool(
    name: str,
    provider: str,
    *,
    category_hint: str | None = None,
    server: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> ToolClassification:
    raise NotImplementedError


def extract_resources(category: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
    raise NotImplementedError


def extract_destination(
    category: str, arguments: dict[str, Any], resources: list[dict[str, Any]]
) -> dict[str, str] | None:
    raise NotImplementedError


def compute_session_risk(signals: SessionSignals) -> SessionRisk:
    raise NotImplementedError


def compute_agent_posture(inputs: PostureInputs) -> PostureAssessment:
    raise NotImplementedError
