"""STUB — to be implemented by the trust work package. Keep these signatures."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TrustRuleSpec:
    id: str
    name: str
    pattern: str  # glob
    trust_level: str
    capabilities: tuple[str, ...] = ()
    source_type: str | None = None
    match_field: str = "identifier"  # identifier|domain
    applies_to: str = "source"  # source|destination|both
    priority: int = 100
    enabled: bool = True


@dataclass(frozen=True)
class SourceHistory:
    observation_count: int = 0
    finding_count: int = 0
    max_finding_severity: str | None = None
    manually_classified: bool = False
    current_level: str | None = None
    current_capabilities: tuple[str, ...] = ()
    inherited_level: str | None = None  # for tool_output / agent_output: trust of what produced it


@dataclass
class TrustAssessment:
    level: str
    capabilities: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    matched_rule_id: str | None = None
    canonical_identifier: str = ""
    domain: str | None = None

    @property
    def can_instruct(self) -> bool:
        return "instruct" in self.capabilities


@dataclass
class DestinationAssessment:
    classification: str
    checks: list[dict[str, str]] = field(default_factory=list)  # {"check","result","detail"}
    reasons: list[str] = field(default_factory=list)
    matched_rule_id: str | None = None
    canonical_identifier: str = ""
    kind: str = "unknown"


def canonicalize_source(source_type: str, identifier: str) -> tuple[str, str | None]:
    raise NotImplementedError


def assess_source(
    source_type: str, identifier: str, *, rules: Sequence[TrustRuleSpec], history: SourceHistory | None = None
) -> TrustAssessment:
    raise NotImplementedError


def assess_destination(kind: str, identifier: str, *, rules: Sequence[TrustRuleSpec]) -> DestinationAssessment:
    raise NotImplementedError
