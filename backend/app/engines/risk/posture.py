"""Agent security posture: explainable 0-100 score (higher is better) with a letter grade (pure).

Nine dimensions, each with a fixed maximum (they sum to 100). Every dimension states how its
score was derived, the evidence it used and — when points are missing — what to change. A
dimension that cannot be assessed yet (no activity) keeps its points and says so explicitly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.domain.enums import SEVERITY_RANK, ToolCategory
from app.engines.risk import policy_refs as pr
from app.engines.risk.posture_dims import (
    PostureDimension,
    approval_controls,
    detection_coverage,
    enforcement_coverage,
    permission_exposure,
    policy_coverage,
    sensitive_data_controls,
    source_trust,
    trifecta_exposure,
    unresolved_findings,
)
from app.engines.risk.tools import classify_tool

GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


@dataclass
class PostureInputs:
    agent: dict[str, Any]  # {"id","name","environment","framework","status"}
    declared_tools: list[dict[str, Any]] = field(default_factory=list)
    observed_tools: list[dict[str, Any]] = field(
        default_factory=list
    )  # [{"name","category","risk_level","count"}]
    policies: list[dict[str, Any]] = field(
        default_factory=list
    )  # enabled policies: [{"id","name","outcome","mode","conditions"}]
    trust_rule_count: int = 0
    untrusted_source_count: int = 0
    open_findings: list[dict[str, Any]] = field(default_factory=list)  # [{"id","severity","category"}]
    integration: dict[str, Any] = field(default_factory=dict)  # {"kind","supports_enforcement","status"}
    approval_policy_count: int = 0
    sessions_with_trifecta: int = 0
    total_sessions: int = 0


@dataclass
class PostureAssessment:
    score: int  # 0-100, higher is better
    grade: str  # A-F
    dimensions: list[PostureDimension] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def grade_for(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def _capabilities(inputs: PostureInputs) -> list[dict[str, Any]]:
    """Declared + observed tools with server-side categories: [{"name","category","risk_level","outbound","source"}]."""
    caps: dict[str, dict[str, Any]] = {}
    for tool in inputs.observed_tools:
        name = str(tool.get("name") or tool.get("category") or "")
        if not name:
            continue
        cls = classify_tool(
            name,
            str(tool.get("provider") or "observed"),
            category_hint=tool.get("category"),
            server=tool.get("server"),
        )
        category = str(tool.get("category") or cls.category)
        caps[name] = {
            "name": name,
            "category": category,
            "risk_level": str(tool.get("risk_level") or cls.risk_level),
            "outbound": cls.outbound or category == ToolCategory.SHELL,
            "source": "observed",
            "count": int(tool.get("count") or 0),
        }
    for tool in inputs.declared_tools:
        name = str(tool.get("name") or tool.get("category") or "")
        if not name:
            continue
        if name in caps:
            caps[name]["source"] = "declared and observed"
            continue
        cls = classify_tool(
            name,
            str(tool.get("provider") or "declared"),
            category_hint=tool.get("category"),
            server=tool.get("server"),
        )
        caps[name] = {
            "name": name,
            "category": cls.category,
            "risk_level": cls.risk_level,
            "outbound": cls.outbound or cls.category == ToolCategory.SHELL,
            "source": "declared",
            "count": 0,
        }
    return list(caps.values())


def _summary(score: int, grade: str, dims: list[PostureDimension]) -> str:
    missing = sorted(
        (d for d in dims if d.score < d.max_score), key=lambda d: (d.score / d.max_score, -d.max_score)
    )
    text = f"Posture {score}/100 (grade {grade})."
    if missing:
        weakest = ", ".join(f"{d.label.lower()} {d.score}/{d.max_score}" for d in missing[:3])
        text += f" Largest gaps: {weakest}."
    else:
        text += " No gaps found in the assessed dimensions."
    pending = [d.label.lower() for d in dims if d.explanation.startswith("Not assessed yet")]
    if pending:
        text += f" Not assessed yet (no activity): {', '.join(pending)}."
    return text


def compute_agent_posture(inputs: PostureInputs) -> PostureAssessment:
    caps = _capabilities(inputs)
    policies = [p for p in inputs.policies if pr.is_enabled(p)]
    dims = [
        permission_exposure(inputs, caps),
        source_trust(inputs),
        sensitive_data_controls(policies),
        enforcement_coverage(inputs.integration),
        policy_coverage(caps, policies),
        approval_controls(inputs, caps, policies),
        detection_coverage(policies),
        unresolved_findings(
            sorted(
                inputs.open_findings,
                key=lambda f: -SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0),
            )
        ),
        trifecta_exposure(inputs.sessions_with_trifecta, inputs.total_sessions),
    ]
    score = max(0, min(100, sum(d.score for d in dims)))
    grade = grade_for(score)
    return PostureAssessment(score=score, grade=grade, dimensions=dims, summary=_summary(score, grade, dims))
