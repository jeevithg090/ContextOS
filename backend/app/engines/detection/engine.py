"""STUB — to be implemented by the detection work package. Keep these signatures."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class DetectionHit:
    rule_id: str  # stable, e.g. "PI-001-ignore-previous"
    category: str  # domain.enums.FindingCategory value
    title: str
    severity: str  # domain.enums.Severity value
    confidence: float  # 0..1
    explanation: str  # plain-language "why this matters"
    excerpt: str | None = None  # REDACTED, <= 240 chars, around the match
    span: tuple[int, int] | None = None  # offsets in the ORIGINAL text when known
    technique: str = "plain"  # plain|zero_width|homoglyph|base64|url_encoded|html_comment|hidden_text|multilingual:<lang>|leetspeak


@dataclass
class DetectionResult:
    hits: list[DetectionHit] = field(default_factory=list)
    score: float = 0.0  # 0..1 aggregate
    max_severity: str | None = None
    classifier_score: float | None = None

    @property
    def is_suspicious(self) -> bool:
        return bool(self.hits)

    def to_summary(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "max_severity": self.max_severity,
            "rule_ids": sorted({h.rule_id for h in self.hits}),
            "categories": sorted({h.category for h in self.hits}),
            "hit_count": len(self.hits),
            "classifier_score": self.classifier_score,
        }


class Classifier(Protocol):
    name: str

    def score(self, text: str) -> float: ...


def analyze_content(text: str, *, source_type: str | None = None, content_type: str | None = None) -> DetectionResult:
    raise NotImplementedError


def analyze_tool_request(
    tool_name: str, category: str, arguments: dict[str, Any], *, resources: Iterable[str] = ()
) -> DetectionResult:
    raise NotImplementedError


def register_classifier(classifier: Classifier | None) -> None:
    raise NotImplementedError


def get_classifier() -> Classifier | None:
    raise NotImplementedError
