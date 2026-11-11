"""Deterministic, explainable agent-security detection engine.

``analyze_content`` normalises text into technique-tagged views, runs the rule families over every
view, dampens hits that merely *describe* an attack, redacts excerpts and aggregates a score.
``analyze_tool_request`` applies the TOOL-* rules to a tool call's arguments and resources. An
optional classifier may be registered; it never replaces the rules.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from app.domain.enums import SEVERITY_RANK, FindingCategory, Severity
from app.engines import redaction

from . import normalize
from .engine_types import Classifier, DetectionHit, DetectionResult
from .rules import ALL_CONTENT_RULES, Rule, rule_applies
from .scoring import aggregate, build_excerpt, dedupe_best
from .tool_rules import TOOL_RULES, ToolRule

__all__ = [
    "Classifier",
    "DetectionHit",
    "DetectionResult",
    "analyze_content",
    "analyze_tool_request",
    "get_classifier",
    "register_classifier",
]

# Techniques where the mere fact of concealment raises severity.
_OBFUSCATION = {"zero_width", "homoglyph", "base64", "url_encoded", "html_comment", "hidden_text", "leetspeak"}
_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

MAX_CONTENT_CHARS = 1_000_000  # hard cap to bound worst-case scan time
DESCRIBED_SUFFIX = " (described, not issued)"

_classifier: Classifier | None = None
CLASSIFIER_THRESHOLD = 0.8


def _bump(severity: str, steps: int = 1) -> str:
    try:
        idx = _SEV_ORDER.index(Severity(severity))
    except ValueError:
        return severity
    return _SEV_ORDER[min(len(_SEV_ORDER) - 1, idx + steps)].value


# --- benign-context detection -----------------------------------------------------------------

_FENCE = re.compile(r"(```|~~~).*?(?:\1|\Z)", re.S)
_INLINE_CODE = re.compile(r"`[^`\n]+`")
_DESCRIPTIVE = re.compile(
    r"(?:for\s+example|e\.g\.|such\s+as|for\s+instance|an?\s+example\s+of|a\s+common\s+(?:prompt\s+injection|attack|example)|"
    r"attackers?\s+(?:might|may|could|often|typically)|is\s+an\s+example\s+of|this\s+(?:is|shows|demonstrates)\s+(?:a|an|how)|"
    r"we\s+(?:detect|block|flag|test)|be\s+aware\s+of|do\s+not\s+(?:actually\s+)?follow|should\s+be\s+(?:ignored|rejected))",
    re.I,
)


def _benign_ranges(text: str) -> list[tuple[int, int]]:
    ranges = [m.span() for m in _FENCE.finditer(text)]
    ranges += [m.span() for m in _INLINE_CODE.finditer(text)]
    for i, line in _iter_lines(text):
        if line.lstrip().startswith(">"):
            ranges.append((i, i + len(line)))
    return ranges


def _iter_lines(text: str):
    pos = 0
    for line in text.splitlines(keepends=True):
        yield pos, line
        pos += len(line)


def _is_benign(text: str, start: int, end: int, benign_ranges: list[tuple[int, int]]) -> bool:
    for lo, hi in benign_ranges:
        if start >= lo and end <= hi:
            return True
    # Bounded window around the match (never the whole line, which may be 100 KB with no newline).
    window = text[max(0, start - 200):end + 40]
    return bool(_DESCRIPTIVE.search(window))


# --- content analysis -------------------------------------------------------------------------


def _concealed_technique(start: int, end: int, hidden_ranges: list[tuple[int, int, str]]) -> str | None:
    for lo, hi, technique in hidden_ranges:
        if start >= lo and end <= hi:
            return technique
    return None


class _ViewContext:
    """A view plus its lazily computed benign ranges. Every view — not only the original text — is
    checked for descriptive context in its own text, so an explanatory example that is also visible
    through a decoded, extracted or re-flowed view is not reported at full severity there."""

    __slots__ = ("_ranges", "view")

    def __init__(self, view: normalize.View, ranges: list[tuple[int, int]] | None = None) -> None:
        self.view = view
        self._ranges = ranges

    def is_benign(self, start: int, end: int) -> bool:
        if self._ranges is None:
            self._ranges = _benign_ranges(self.view.text)
        return _is_benign(self.view.text, start, end, self._ranges)


def _match_rule(
    rule: Rule,
    ctx: _ViewContext,
    hidden_ranges: list[tuple[int, int, str]],
) -> list[DetectionHit]:
    # One hit per rule per view is sufficient (dedup keeps the best overall). Prefer a non-benign
    # match — the highest-severity outcome for the rule — and stop scanning as soon as one is found.
    view = ctx.view
    best: tuple[bool, int, int] | None = None
    for m in rule.pattern.finditer(view.text):
        benign = ctx.is_benign(m.start(), m.end())
        if best is None or (best[0] and not benign):
            best = (benign, m.start(), m.end())
        if not benign:
            break
    if best is None:
        return []

    benign, start, end = best
    if rule.lang:
        technique = f"multilingual:{rule.lang}"
    elif view.has_offsets:
        # A plain-view match inside concealed markup is really hidden content, not visible text.
        technique = _concealed_technique(start, end, hidden_ranges) or "plain"
    else:
        technique = view.technique
    span = (start, end) if view.has_offsets else None
    severity = str(rule.severity)
    confidence = rule.confidence
    explanation = rule.explanation
    title = rule.title
    if benign:
        # Describing an attack is not committing one: keep the hit visible but at low severity.
        severity = Severity.LOW.value if SEVERITY_RANK.get(severity, 0) > 1 else severity
        confidence = round(min(confidence, 0.35), 3)
        explanation = "Appears to be describing an attack rather than issuing it (code block, quote, or " \
                      "explanatory text). Reported at low severity so it is visible but not alarming."
        title = f"{rule.title}{DESCRIBED_SUFFIX}"

    return [
        DetectionHit(
            rule_id=rule.rule_id,
            category=str(rule.category),
            title=title,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            excerpt=build_excerpt(view.text, start, end),
            span=span,
            technique=technique,
        )
    ]


def _apply_obfuscation_bump(hits: list[DetectionHit]) -> list[DetectionHit]:
    """A rule seen ONLY through an obfuscation layer (never in plain text) is elevated: hiding the
    instruction is itself evidence of intent. A hit dampened as *described, not issued* is not: an
    explanatory example inside an HTML comment or collapsed section is still an example."""
    plain_rules = {h.rule_id for h in hits if h.technique == "plain"}
    out: list[DetectionHit] = []
    for h in hits:
        if (h.rule_id not in plain_rules and h.technique in _OBFUSCATION and not h.technique.startswith("multilingual")
                and not h.title.endswith(DESCRIBED_SUFFIX)):
            out.append(
                replace(
                    h,
                    severity=_bump(h.severity),
                    confidence=round(min(1.0, h.confidence + 0.05), 3),
                    explanation=h.explanation + f" This was hidden via {h.technique.replace('_', ' ')}, which "
                    "indicates deliberate concealment rather than incidental content.",
                )
            )
        else:
            out.append(h)
    return out


def analyze_content(text: str, *, source_type: str | None = None, content_type: str | None = None) -> DetectionResult:
    if not text:
        return DetectionResult()
    truncated = text[:MAX_CONTENT_CHARS]
    views = normalize.build_views(truncated)
    benign_ranges = _benign_ranges(truncated)
    hidden_ranges = normalize.hidden_ranges(truncated)

    raw: list[DetectionHit] = []
    for view in views:
        low = view.text.lower()
        ctx = _ViewContext(view, benign_ranges if view.has_offsets else None)
        for rule in ALL_CONTENT_RULES:
            if rule_applies(rule.rule_id, low):
                raw.extend(_match_rule(rule, ctx, hidden_ranges))

    raw = _apply_obfuscation_bump(raw)
    hits = dedupe_best(raw)

    classifier_score = _run_classifier(truncated, hits)
    score, max_sev = aggregate(hits)
    return DetectionResult(hits=hits, score=score, max_severity=max_sev, classifier_score=classifier_score)


def _run_classifier(text: str, hits: list[DetectionHit]) -> float | None:
    clf = _classifier
    if clf is None:
        return None
    try:
        raw = clf.score(text)
    except Exception as exc:  # noqa: BLE001 — a classifier failure must never break deterministic detection
        # Recorded (type only, never the content) and the classifier score is reported as absent.
        logging.getLogger(__name__).warning("detection.classifier_failed",
                                            extra={"classifier": getattr(clf, "name", "model"),
                                                   "error_type": type(exc).__name__})
        return None
    cls_score = max(0.0, min(1.0, float(raw)))
    if cls_score > CLASSIFIER_THRESHOLD:
        hits.append(
            DetectionHit(
                rule_id="CLS-001",
                category=FindingCategory.PROMPT_INJECTION.value,
                title="Classifier flagged injection",
                severity=Severity.MEDIUM.value,
                confidence=round(cls_score, 3),
                explanation=f"A machine-learning classifier ({getattr(clf, 'name', 'model')}) scored this content "
                f"{cls_score:.2f} for prompt injection, above the {CLASSIFIER_THRESHOLD:.2f} reporting threshold. "
                "This supplements, and never replaces, the deterministic rules.",
                excerpt=None,
                technique="plain",
            )
        )
    return round(cls_score, 3)


# --- tool-request analysis --------------------------------------------------------------------


def _collect_strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_collect_strings(v))
    elif isinstance(value, (list, tuple)):
        for v in value:
            out.extend(_collect_strings(v))
    elif value is not None:
        out.append(str(value))
    return out


_PATH_KEYS = {"file_path", "path", "filename", "file", "notebook_path", "target_file", "dir", "directory"}
_SENSITIVE_PATH_FALLBACK = re.compile(
    r"(?:^|/)(?:\.env(?:\.[\w.-]+)?|\.ssh/(?:id_[a-z0-9]+|identity)|\.aws/credentials|\.gcp/|"
    r"\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|id_rsa|id_ed25519|\.pem|\.p12|\.pfx|"
    r"shadow|\.git-credentials|secrets?\.(?:ya?ml|json|env))(?:$|[/.])",
    re.I,
)


def _candidate_paths(arguments: dict[str, Any], resources: Iterable[str]) -> list[str]:
    paths: list[str] = [str(r) for r in resources]
    for key, val in arguments.items():
        if key in _PATH_KEYS and isinstance(val, str):
            paths.append(val)
    # Pull path-like tokens out of command strings too (e.g. Bash `cat ~/.ssh/id_rsa`).
    for s in _collect_strings(arguments):
        paths.extend(re.findall(r"(?:~|/|\.{1,2}/)[\w./~-]+", s))
    return paths


def _check_sensitive_path(path: str) -> tuple[bool, str | None]:
    try:
        return redaction.is_sensitive_path(path)
    except NotImplementedError:
        m = _SENSITIVE_PATH_FALLBACK.search(path)
        return (True, "credential_file") if m else (False, None)


def analyze_tool_request(
    tool_name: str, category: str, arguments: dict[str, Any], *, resources: Iterable[str] = ()
) -> DetectionResult:
    arguments = arguments or {}
    resources = list(resources or [])
    strings = _collect_strings(arguments)
    # Zero-width / homoglyph tricks in commands are normalised away before matching.
    plain_blob = "\n".join([tool_name or ""] + strings + resources)
    normalized = normalize.fold_homoglyphs(normalize._strip_invisible(plain_blob)[0]) if not plain_blob.isascii() else plain_blob

    views = [normalize.View("plain", plain_blob, has_offsets=True)]
    if normalized != plain_blob:
        views.append(normalize.View("homoglyph", normalized))
    # An encoded command (`echo <base64> | base64 -d | sh`) is also matched on what it decodes to.
    for segment in normalize.decode_base64_segments(normalized):
        views.append(normalize.View("base64", segment))

    raw: list[DetectionHit] = []
    for view in views:
        for rule in TOOL_RULES:
            raw.extend(_match_tool_rule(rule, view))

    # Sensitive credential-file reads, from structured paths and command tokens.
    for path in _candidate_paths(arguments, resources):
        sensitive, kind = _check_sensitive_path(path)
        if sensitive:
            raw.append(
                DetectionHit(
                    rule_id="TOOL-CRED-FILE",
                    category=FindingCategory.CREDENTIAL_ACCESS.value,
                    title="Sensitive credential file access",
                    severity=Severity.HIGH.value,
                    confidence=0.82,
                    explanation=f"The tool call touches a sensitive file ({kind or 'credential store'}). "
                    "Reading credential files (.env, SSH keys, cloud credentials) is a common precursor to "
                    "secret theft and should be reviewed.",
                    excerpt=build_excerpt(path, 0, len(path)),
                    technique="plain",
                )
            )
            break

    raw = _apply_obfuscation_bump(raw)
    hits = dedupe_best(raw)
    score, max_sev = aggregate(hits)
    return DetectionResult(hits=hits, score=score, max_severity=max_sev)


def _match_tool_rule(rule: ToolRule, view: normalize.View) -> list[DetectionHit]:
    m = rule.pattern.search(view.text)  # one hit per rule per view; dedup keeps the best
    if m is None:
        return []
    return [
        DetectionHit(
            rule_id=rule.rule_id,
            category=str(rule.category),
            title=rule.title,
            severity=str(rule.severity),
            confidence=rule.confidence,
            explanation=rule.explanation,
            excerpt=build_excerpt(view.text, m.start(), m.end()),
            span=(m.start(), m.end()) if view.has_offsets else None,
            technique=view.technique,
        )
    ]


# --- classifier hook --------------------------------------------------------------------------


def register_classifier(classifier: Classifier | None) -> None:
    global _classifier
    _classifier = classifier


def get_classifier() -> Classifier | None:
    return _classifier
