"""STUB — to be implemented by the policy work package. Keep these signatures and field names:
the field names of EvaluationInput ARE the policy DSL's field paths and are persisted in
PolicyDecision.input_snapshot (changing them breaks stored policies and replay).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EvaluationInput:
    # {"id", "name", "environment", "labels": [...], "framework"}
    agent: dict[str, Any] = field(default_factory=dict)
    # {"name", "category", "provider", "server", "risk_level"}
    tool: dict[str, Any] = field(default_factory=dict)
    arguments: dict[str, Any] = field(default_factory=dict)  # REDACTED arguments
    # [{"kind": "file"|"url"|"command"|..., "id": str, "sensitive": bool, "reason": str|None}]
    resources: list[dict[str, Any]] = field(default_factory=list)
    sensitive_resources: list[str] = field(default_factory=list)
    # {"kind", "identifier", "classification", "checks": [...] } or {}
    destination: dict[str, Any] = field(default_factory=dict)
    secrets_in_arguments: list[dict[str, str]] = field(default_factory=list)  # [{"type","fingerprint"}]
    # Fingerprints in arguments that were previously seen in this session's context.
    session_secret_matches: list[dict[str, str]] = field(default_factory=list)
    # {"score", "level", "untrusted_exposure": bool, "sensitive_access": bool,
    #  "outbound_channel": bool, "trifecta": bool}
    session: dict[str, Any] = field(default_factory=dict)
    # {"lowest_trust": str, "untrusted_item_count": int, "suspicious_source_ids": [...],
    #  "injection_detected": bool, "max_detection_severity": str|None}
    context: dict[str, Any] = field(default_factory=dict)
    # Detection over the tool request itself: {"rule_ids": [...], "max_severity": str|None, "categories": [...]}
    detection: dict[str, Any] = field(default_factory=dict)
    integration: dict[str, Any] = field(default_factory=dict)  # {"kind", "supports_enforcement": bool}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationInput:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass(frozen=True)
class PolicySpec:
    id: str
    name: str
    outcome: str  # Decision
    conditions: dict[str, Any]
    version: int = 1
    enabled: bool = True
    mode: str = "enforce"  # PolicyMode
    priority: int = 100
    severity: str = "medium"
    restrictions: dict[str, Any] = field(default_factory=dict)
    description: str | None = None


@dataclass(frozen=True)
class PolicyMatch:
    policy_id: str
    name: str
    version: int
    outcome: str
    mode: str
    severity: str
    explanation: str  # which conditions matched, with the observed values

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    decision: str
    matched: list[PolicyMatch] = field(default_factory=list)  # enforce-mode matches
    monitor_matches: list[PolicyMatch] = field(default_factory=list)
    explanation: str = ""
    restrictions: dict[str, Any] = field(default_factory=dict)
    deciding_policy_id: str | None = None


def evaluate(
    inp: EvaluationInput, policies: Sequence[PolicySpec], *, default_decision: str = "ALLOW"
) -> EvaluationResult:
    raise NotImplementedError


def validate_conditions(conditions: dict[str, Any]) -> list[str]:
    raise NotImplementedError


def explain_conditions(conditions: dict[str, Any]) -> str:
    raise NotImplementedError
