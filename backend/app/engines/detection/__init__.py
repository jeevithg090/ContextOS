"""Agent-security detection engine (pure; no database access).

CONTRACT — stable signatures used by the ingestion pipeline, simulations and the corpus evaluator:

    analyze_content(text, *, source_type=None, content_type=None) -> DetectionResult
        Prompt-injection / instruction-override / credential-seeking / exfiltration-instruction
        detection over context entering an agent. Normalises input first (NFKC, zero-width removal,
        Unicode tag decoding, homoglyph folding, leetspeak / spelt-out letters, HTML comment /
        hidden-text extraction, base64, URL-encoded and JSON \\u escape decoding, re-flowing of
        hard-wrapped lines) and records which technique revealed each hit. Descriptive context
        (code fences, quotes, explanatory phrasing) is judged in each view's own text.

    analyze_tool_request(tool_name, category, arguments, *, resources=()) -> DetectionResult
        Suspicious tool usage: credential file reads, env dumping, curl/wget piping data out,
        raw-IP destinations, reverse shells, destructive commands, encoded payloads (also matched
        on what base64 segments decode to). Destructive commands (TOOL-DESTRUCTIVE-*) report
        ``suspicious_tool_use``; ``permission_escalation`` is reserved for agent-config writes,
        persistence and reverse shells.

    Measured on the evaluation corpus: docs/DETECTION_EVALUATION.md.

    register_classifier(classifier) / get_classifier()
        Optional ML classifier hook (Protocol ``Classifier.score(text) -> float``). Never the only
        control: rule hits are always reported independently.

Every hit carries a plain-language explanation and a REDACTED excerpt.
"""

from app.engines.detection.engine import (
    Classifier,
    DetectionHit,
    DetectionResult,
    analyze_content,
    analyze_tool_request,
    get_classifier,
    register_classifier,
)

__all__ = [
    "Classifier",
    "DetectionHit",
    "DetectionResult",
    "analyze_content",
    "analyze_tool_request",
    "get_classifier",
    "register_classifier",
]
