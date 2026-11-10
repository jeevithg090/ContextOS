"""Agent-security detection engine (pure; no database access).

CONTRACT — stable signatures used by the ingestion pipeline, simulations and the corpus evaluator:

    analyze_content(text, *, source_type=None, content_type=None) -> DetectionResult
        Prompt-injection / instruction-override / credential-seeking / exfiltration-instruction
        detection over context entering an agent. Normalises input first (NFKC, zero-width removal,
        homoglyph folding, HTML comment / hidden-text extraction, base64 & URL-encoded segment
        decoding) and records which technique revealed each hit.

    analyze_tool_request(tool_name, category, arguments, *, resources=()) -> DetectionResult
        Suspicious tool usage: credential file reads, env dumping, curl/wget piping data out,
        raw-IP destinations, reverse shells, destructive commands, encoded payloads.

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
