"""Scoring of the detection corpus against the real engine (no mocks, no network, no execution).

Prediction rule: a sample is predicted malicious when the engine returns at least one hit with
severity >= ``medium``. ``low`` is where the engine deliberately parks text that *describes* an
attack (quoted, fenced, explanatory) and ``info`` carries no claim at all; ``medium`` is the
threshold at which ingestion treats a hit as instructions aimed at the agent (untrusted-source
findings, incident escalation), so it is the operational alerting threshold being measured.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import SEVERITY_RANK, Severity
from app.engines.detection import DetectionHit, DetectionResult, analyze_content, analyze_tool_request

PREDICTION_MIN_SEVERITY = Severity.MEDIUM.value
_MIN_RANK = SEVERITY_RANK[PREDICTION_MIN_SEVERITY]


def qualifying(hits: Iterable[DetectionHit]) -> list[DetectionHit]:
    return [h for h in hits if SEVERITY_RANK.get(h.severity, 0) >= _MIN_RANK]


@dataclass
class Outcome:
    sample: dict[str, Any]
    predicted: bool
    categories: list[str]
    top_category: str | None
    max_severity: str | None
    rule_ids: list[str]
    score: float
    low_rule_ids: list[str] = field(default_factory=list)  # hits below the prediction threshold

    @property
    def malicious(self) -> bool:
        return self.sample["label"] == "malicious"

    @property
    def category_ok(self) -> bool:
        return self.sample.get("expected_category") in self.categories


def _outcome(sample: dict[str, Any], result: DetectionResult) -> Outcome:
    hits = qualifying(result.hits)  # already sorted by severity, then confidence
    return Outcome(
        sample=sample,
        predicted=bool(hits),
        categories=sorted({h.category for h in hits}),
        top_category=hits[0].category if hits else None,
        max_severity=result.max_severity,
        rule_ids=sorted({h.rule_id for h in hits}),
        score=result.score,
        low_rule_ids=sorted({h.rule_id for h in result.hits} - {h.rule_id for h in hits}),
    )


def run_content(samples: Iterable[dict[str, Any]]) -> list[Outcome]:
    return [_outcome(s, analyze_content(s["text"])) for s in samples]


def run_tools(samples: Iterable[dict[str, Any]]) -> list[Outcome]:
    return [_outcome(s, analyze_tool_request(s["tool"], s["category"], s["arguments"])) for s in samples]


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def confusion(outcomes: Iterable[Outcome]) -> dict[str, Any]:
    tp = fp = tn = fn = cat_ok = 0
    for o in outcomes:
        if o.malicious:
            if o.predicted:
                tp += 1
                cat_ok += o.category_ok
            else:
                fn += 1
        elif o.predicted:
            fp += 1
        else:
            tn += 1
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else None
    return {
        "n": tp + fp + tn + fn,
        "malicious": tp + fn,
        "benign": fp + tn,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _ratio(fp, fp + tn),
        # Of the malicious samples the engine flagged, how many carried the expected category.
        "category_accuracy": _ratio(cat_ok, tp),
    }


def breakdown(outcomes: list[Outcome], key: Callable[[Outcome], str]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[Outcome]] = defaultdict(list)
    for o in outcomes:
        groups[key(o)].append(o)
    return {k: confusion(v) for k, v in sorted(groups.items())}


def worst_false_positives(outcomes: list[Outcome], limit: int) -> list[Outcome]:
    fps = [o for o in outcomes if o.predicted and not o.malicious]
    return sorted(fps, key=lambda o: (-SEVERITY_RANK.get(o.max_severity or "", 0), -o.score, o.sample["id"]))[
        :limit
    ]


def worst_false_negatives(outcomes: list[Outcome], limit: int) -> list[Outcome]:
    fns = [o for o in outcomes if o.malicious and not o.predicted]
    return sorted(fns, key=lambda o: (o.score, o.sample["id"]))[:limit]


def miscategorised(outcomes: list[Outcome], limit: int) -> list[Outcome]:
    bad = [o for o in outcomes if o.malicious and o.predicted and not o.category_ok]
    return sorted(bad, key=lambda o: o.sample["id"])[:limit]


def _row(o: Outcome) -> dict[str, Any]:
    return {
        "id": o.sample["id"],
        "max_severity": o.max_severity,
        "rule_ids": o.rule_ids,
        "low_rule_ids": o.low_rule_ids,
        "categories": o.categories,
        "expected_category": o.sample.get("expected_category"),
        "score": round(o.score, 3),
    }


def report(
    outcomes: list[Outcome], *, dimensions: dict[str, Callable[[Outcome], str]], worst: int
) -> dict[str, Any]:
    return {
        "overall": confusion(outcomes),
        "breakdowns": {name: breakdown(outcomes, key) for name, key in dimensions.items()},
        "worst_false_positives": [_row(o) for o in worst_false_positives(outcomes, worst)],
        "worst_false_negatives": [_row(o) for o in worst_false_negatives(outcomes, worst)],
        "miscategorised": [_row(o) for o in miscategorised(outcomes, worst)],
    }


CONTENT_DIMENSIONS: dict[str, Callable[[Outcome], str]] = {
    "family": lambda o: o.sample["family"],
    "technique": lambda o: o.sample["technique"],
    "carrier": lambda o: o.sample["carrier"],
    "language": lambda o: o.sample["lang"],
}

TOOL_DIMENSIONS: dict[str, Callable[[Outcome], str]] = {
    "family": lambda o: o.sample["family"],
    "shape": lambda o: o.sample["shape"],
}
