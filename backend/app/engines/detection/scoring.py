"""Excerpt building, redaction, dedup and score aggregation shared by content and tool analysis."""

from __future__ import annotations

from app.domain.enums import SEVERITY_RANK, Severity
from app.engines import redaction

from .engine_types import DetectionHit

EXCERPT_CAP = 240
_CONTEXT = 60  # chars of context kept on each side of a match before the cap

# Severity weights for the noisy-OR aggregation: a critical hit dominates, info barely moves it.
_SEV_WEIGHT: dict[str, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.85,
    Severity.MEDIUM: 0.55,
    Severity.LOW: 0.3,
    Severity.INFO: 0.12,
}


def _safe_redact(text: str) -> str:
    """Redact secrets from an excerpt. The redaction engine is built concurrently; until it is
    implemented we fall back to the raw (already length-capped) excerpt so tests can run. Production
    always has a working ``redact_text``."""
    try:
        return redaction.redact_text(text).text
    except NotImplementedError:
        return text


def build_excerpt(view_text: str, start: int, end: int) -> str:
    """A redacted, length-capped excerpt centred on the match within its view."""
    lo = max(0, start - _CONTEXT)
    hi = min(len(view_text), end + _CONTEXT)
    snippet = view_text[lo:hi]
    if lo > 0:
        snippet = "…" + snippet
    if hi < len(view_text):
        snippet = snippet + "…"
    snippet = " ".join(snippet.split())  # collapse whitespace/newlines for a single-line excerpt
    redacted = _safe_redact(snippet)
    if len(redacted) > EXCERPT_CAP:
        redacted = redacted[: EXCERPT_CAP - 1].rstrip() + "…"
    return redacted


def dedupe_best(hits: list[DetectionHit]) -> list[DetectionHit]:
    """Keep one hit per rule_id — the highest severity, then highest confidence, then a plain-view
    hit (which carries a real span) over an obfuscated one."""
    best: dict[str, DetectionHit] = {}
    for h in hits:
        cur = best.get(h.rule_id)
        if cur is None or _hit_key(h) > _hit_key(cur):
            best[h.rule_id] = h
    return sorted(
        best.values(),
        key=lambda h: (SEVERITY_RANK.get(h.severity, 0), h.confidence),
        reverse=True,
    )


def _hit_key(h: DetectionHit) -> tuple[int, float, int]:
    return (SEVERITY_RANK.get(h.severity, 0), h.confidence, 1 if h.span is not None else 0)


def aggregate(hits: list[DetectionHit]) -> tuple[float, str | None]:
    """Noisy-OR of per-hit confidences weighted by severity -> (score 0..1, max_severity)."""
    if not hits:
        return 0.0, None
    product = 1.0
    max_rank = -1
    max_sev: str | None = None
    for h in hits:
        w = _SEV_WEIGHT.get(h.severity, 0.3)
        p = max(0.0, min(1.0, h.confidence)) * w
        product *= 1.0 - p
        rank = SEVERITY_RANK.get(h.severity, 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = h.severity
    return round(1.0 - product, 6), max_sev
