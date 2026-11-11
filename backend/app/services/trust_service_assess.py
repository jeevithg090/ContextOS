"""Trust Centre: running the trust engine over stored sources and destinations.

The ingestion pipeline classifies a source each time content from it is observed and a destination
each time a tool call targets it. This module re-runs the same engine over the stored rows when an
administrator changes trust rules, classifies a source manually or asks for a re-assessment, using
the same inputs the pipeline uses:

- Rules: the organisation's enabled trust rules (read from the database, not the pipeline cache, so
  a change made earlier in this transaction is included).
- Evidence: detection findings recorded against the source that have NOT been marked false
  positive. A finding that was resolved still shows that the source served manipulative content,
  so it keeps counting; only a false-positive verdict lifts an evidence downgrade. Findings the
  pipeline derives from other findings (``DERIVED_FINDING_RULES``) are not counted twice, matching
  how the pipeline counts. The source's ``finding_count`` / ``max_finding_severity`` are refreshed
  to these values so the pipeline's next assessment starts from the same evidence.
- Inherited trust: sub-agent output is capped at the lowest trust seen in the session that produced
  it (as recorded on its most recent item); MCP tool output is capped by its MCP server.
- Destination history: every stored destination has been seen before; a destination the
  integration only *reported* (not derivable from the call's arguments) stays at most UNKNOWN.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, TRUST_RANK, FindingStatus, SourceType, TrustLevel
from app.engines.redaction import redact_text
from app.engines.trust import (
    DestinationAssessment,
    DestinationHistory,
    SourceHistory,
    TrustAssessment,
    TrustRuleSpec,
    assess_destination,
    assess_source,
    canonicalize_source,
    registrable_domain,
)
from app.engines.trust.canonical import canonicalize
from app.engines.trust.destinations import parse_destination
from app.engines.trust.matching import domain_candidates, identifier_candidates, matching_rules
from app.models import ContextItem, ContextSource, Destination, SecurityFinding
from app.services.ingestion_entities import lowest_session_trust

SAFE_DESTINATIONS = frozenset({TrustLevel.TRUSTED.value, TrustLevel.APPROVED.value})
REPORTED_ONLY_CHECK = "reported_by_integration"
_REPORTED_ONLY = {
    "check": REPORTED_ONLY_CHECK,
    "result": "warn",
    "detail": "The integration reported this destination; ContextOS could not derive it from the call's arguments, "
              "so it cannot be treated as trusted.",
}
_CHUNK = 500
# Raised by the pipeline on top of the detection findings for the same content (see
# ingestion_context._content_findings and ingestion_handlers._record_agent_content); the pipeline
# does not count them towards a source's evidence, so neither does re-assessment.
DERIVED_FINDING_RULES = ("CTX-UNTRUSTED-INSTRUCTIONS", "CTX-CROSS-AGENT-001")


def redact_line(value: str | None, limit: int = 1000) -> str | None:
    """Redact and bound a human-readable line before it is stored or audited."""
    if value is None:
        return None
    text = redact_text(value).text
    return text if len(text) <= limit else text[: limit - 1] + "…"


def chunks(values: Sequence[str], size: int = _CHUNK) -> Iterable[Sequence[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


# ----------------------------------------------------------------------------- evidence


@dataclass
class Evidence:
    count: int = 0
    max_severity: str | None = None

    def add(self, severity: str | None, count: int) -> None:
        self.count += int(count or 0)
        if severity in SEVERITY_RANK and (
            self.max_severity is None or SEVERITY_RANK[severity] > SEVERITY_RANK[self.max_severity]
        ):
            self.max_severity = severity


def finding_evidence(db: Session, org_id: str, source_ids: Sequence[str]) -> dict[str, Evidence]:
    """Findings recorded against each source that have not been judged false positives."""
    out: dict[str, Evidence] = {}
    ids = list(dict.fromkeys(source_ids))
    for chunk in chunks(ids):
        rows = db.execute(
            select(SecurityFinding.source_id, SecurityFinding.severity, func.count(SecurityFinding.id))
            .where(
                SecurityFinding.organization_id == org_id,
                SecurityFinding.source_id.in_(chunk),
                SecurityFinding.status != FindingStatus.FALSE_POSITIVE.value,
                SecurityFinding.rule_id.not_in(DERIVED_FINDING_RULES),
            )
            .group_by(SecurityFinding.source_id, SecurityFinding.severity)
        )
        for source_id, severity, count in rows:
            out.setdefault(source_id, Evidence()).add(severity, count)
    return out


# ----------------------------------------------------------------------------- inherited trust


def inherited_level(db: Session, org_id: str, source: ContextSource) -> str | None:
    """Sub-agent output: lowest trust in the session that produced its most recent item."""
    if source.source_type != SourceType.AGENT_OUTPUT.value:
        return None
    origin = db.scalar(
        select(ContextItem.origin_session_id)
        .where(
            ContextItem.organization_id == org_id,
            ContextItem.source_id == source.id,
            ContextItem.origin_session_id.is_not(None),
        )
        .order_by(ContextItem.received_at.desc())
        .limit(1)
    )
    return lowest_session_trust(db, org_id, origin) if origin else None


def mcp_server_levels(db: Session, org_id: str) -> dict[str, str]:
    rows = db.execute(
        select(ContextSource.identifier, ContextSource.trust_level).where(
            ContextSource.organization_id == org_id, ContextSource.source_type == SourceType.MCP_SERVER.value
        )
    )
    return {identifier: level for identifier, level in rows}


def mcp_ceiling(source_type: str, identifier: str, server_levels: dict[str, str]) -> tuple[str, str] | None:
    """An MCP tool's output is never more trusted than the server that provides it."""
    if source_type != SourceType.MCP_TOOL.value or "/" not in identifier:
        return None
    server, _, _tool = identifier.partition("/")
    canonical, _ = canonicalize_source(SourceType.MCP_SERVER.value, server)
    level = server_levels.get(redact_line(canonical, 2048) or server.lower())
    if level is None:
        return None
    return level, (
        f"Capped at {level} because the MCP server '{canonical}' that provides this tool is classified {level}."
    )


def apply_ceiling(assessment: TrustAssessment, ceiling: tuple[str, str] | None) -> TrustAssessment:
    if ceiling is None:
        return assessment
    level, reason = ceiling
    if level in TRUST_RANK and TRUST_RANK[level] < TRUST_RANK.get(assessment.level, 2):
        assessment.level = level
        assessment.capabilities = [c for c in assessment.capabilities if c == "read"] if level != "BLOCKED" else []
        assessment.reasons = [*assessment.reasons, reason]
    return assessment


# ----------------------------------------------------------------------------- sources


@dataclass
class SourceContext:
    """Everything besides the rules that a source assessment depends on."""

    evidence: Evidence = field(default_factory=Evidence)
    inherited: str | None = None
    ceiling: tuple[str, str] | None = None


def source_context(
    db: Session, org_id: str, source: ContextSource, *, server_levels: dict[str, str] | None = None,
    evidence: Evidence | None = None,
) -> SourceContext:
    if evidence is None:
        evidence = finding_evidence(db, org_id, [source.id]).get(source.id, Evidence())
    if server_levels is None and source.source_type == SourceType.MCP_TOOL.value:
        server_levels = mcp_server_levels(db, org_id)
    return SourceContext(
        evidence=evidence,
        inherited=inherited_level(db, org_id, source),
        ceiling=mcp_ceiling(source.source_type, source.identifier, server_levels or {}),
    )


def assess_source_row(
    source: ContextSource,
    rules: Sequence[TrustRuleSpec],
    ctx: SourceContext,
    *,
    manual: tuple[str, Sequence[str]] | None = None,
    ignore_manual: bool = False,
    ignore_evidence: bool = False,
) -> TrustAssessment:
    """Assess a stored source. ``manual`` = (level, capabilities) to evaluate a manual classification."""
    is_manual = manual is not None or (bool(source.manually_classified) and not ignore_manual)
    level, caps = manual if manual is not None else (source.trust_level, tuple(source.trust_capabilities or ()))
    evidence = Evidence() if ignore_evidence else ctx.evidence
    history = SourceHistory(
        observation_count=source.observation_count or 0,
        finding_count=evidence.count,
        max_finding_severity=evidence.max_severity,
        manually_classified=is_manual,
        current_level=level,
        current_capabilities=tuple(str(c) for c in caps),
        inherited_level=ctx.inherited,
    )
    assessment = assess_source(source.source_type, source.identifier, rules=rules, history=history)
    return apply_ceiling(assessment, ctx.ceiling)


def store_source_assessment(source: ContextSource, assessment: TrustAssessment, ctx: SourceContext) -> str:
    """Persist an assessment (and the evidence it used) on the source. Returns the prior level."""
    prior = source.trust_level
    source.trust_level = assessment.level
    source.trust_capabilities = list(assessment.capabilities)
    source.trust_reasons = [redact_line(r) or "" for r in assessment.reasons]
    source.trust_rule_id = assessment.matched_rule_id
    source.finding_count = ctx.evidence.count
    source.max_finding_severity = ctx.evidence.max_severity
    if assessment.domain and not source.domain:
        source.domain = assessment.domain
    return prior


def source_candidates(source_type: str, identifier: str) -> tuple[list[str], list[str], str, str | None]:
    """(identifier candidates, domain candidates, canonical identifier, registrable domain) as the engine sees them."""
    canonical = canonicalize((source_type or "other").strip().lower(), identifier)
    host = canonical.host.host if canonical.host else None
    identifiers = identifier_candidates(canonical.identifier) if canonical.identifier else []
    return identifiers, domain_candidates(host, canonical.domain), canonical.identifier, canonical.domain


def matching_source_rules(rules: Sequence[TrustRuleSpec], source_type: str, identifier: str) -> list[TrustRuleSpec]:
    identifiers, domains, _canonical, _domain = source_candidates(source_type, identifier)
    return matching_rules(rules, scope="source", source_type=(source_type or "other").strip().lower(),
                          identifiers=identifiers, domains=domains)


# ----------------------------------------------------------------------------- destinations


def destination_candidates(kind: str, identifier: str) -> tuple[list[str], list[str], str, str]:
    target = parse_destination(kind, identifier)
    host = target.host.host if target.host else None
    identifiers = identifier_candidates(target.canonical) if target.canonical else []
    return identifiers, domain_candidates(host, registrable_domain(host)), target.canonical, target.kind


def matching_destination_rules(rules: Sequence[TrustRuleSpec], kind: str, identifier: str) -> list[TrustRuleSpec]:
    identifiers, domains, _canonical, _kind = destination_candidates(kind, identifier)
    return matching_rules(rules, scope="destination", identifiers=identifiers, domains=domains)


def reported_only(row: Destination) -> bool:
    return any(isinstance(c, dict) and c.get("check") == REPORTED_ONLY_CHECK for c in (row.verification or []))


def assess_destination_row(row: Destination, rules: Sequence[TrustRuleSpec]) -> DestinationAssessment:
    history = DestinationHistory(previously_seen=True, transfer_count=row.transfer_count or 0)
    assessment = assess_destination(row.kind, row.identifier, rules=rules, history=history)
    if reported_only(row):
        assessment.checks.append(dict(_REPORTED_ONLY))
        if assessment.classification in SAFE_DESTINATIONS:
            assessment.reasons.append(
                "Treated as UNKNOWN because the destination was reported, not derived from the arguments."
            )
            assessment.classification = TrustLevel.UNKNOWN.value
    return assessment


def store_destination_assessment(row: Destination, assessment: DestinationAssessment) -> str:
    prior = row.classification
    row.classification = assessment.classification
    row.trust_rule_id = assessment.matched_rule_id
    row.verification = [
        {"check": str(c.get("check")), "result": str(c.get("result")), "detail": redact_line(c.get("detail"), 500)}
        for c in assessment.checks
    ]
    return prior


def not_verified(kind: str, has_host: bool, checks: Sequence[dict[str, Any]]) -> list[str]:
    """Plain statements of what the destination checks did NOT establish."""
    items: list[str]
    if kind == "email":
        items = [
            "That the mailbox exists, or who will read the message.",
            "Which mail servers accept mail for the domain (no DNS or MX lookup was made).",
        ]
    elif kind == "agent":
        items = ["The receiving agent's identity: the name is as reported by the integration."]
    elif has_host:
        items = [
            "Who operates this destination, or who will receive the data.",
            "Where the name currently resolves (no DNS lookup was made).",
            "Whether it is reachable, what it presents (TLS certificate) or what it does with data — no connection "
            "was made.",
        ]
    else:
        items = ["Who operates this destination, or who will receive the data."]
    for check in checks:
        if isinstance(check, dict) and check.get("result") == "unknown" and check.get("detail"):
            items.append(f"Not checked: {check['detail']}")
    return items
