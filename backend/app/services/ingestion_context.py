"""Recording one piece of context that entered an agent: source upsert, trust, detection, redaction,
the signed context receipt, provenance edges and findings.

Raw text is used in memory for secret detection, hashing and prompt-injection detection only. What
is persisted: SHA-256 and length of the raw text, secret fingerprints, a redacted and truncated
preview (unless the organisation disabled previews), the detection summary and redacted excerpts.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from app.core.config import get_settings
from app.core.ids import new_id
from app.core.security import sha256_hex
from app.domain.enums import (
    SEVERITY_RANK,
    TRUST_RANK,
    FindingCategory,
    ProvenanceNodeType,
    ProvenanceRelation,
    Sensitivity,
    Severity,
)
from app.engines.detection import DetectionHit, analyze_content
from app.engines.provenance import receipt_fields, sign_receipt
from app.engines.redaction import HIGH_CONFIDENCE, classify_sensitivity, redact_text, redact_value
from app.engines.trust import SourceHistory, TrustAssessment, assess_source, canonicalize_source
from app.models import ContextItem, ContextSource
from app.services.audit import append_audit
from app.services.ingestion_entities import add_edge, upsert_source
from app.services.ingestion_findings import raise_finding
from app.services.ingestion_known_secrets import (
    as_matches,
    find_known,
    forget_session_fingerprints,
    redact_known,
    redact_session_text,
)
from app.services.ingestion_risk import INJECTION_CATEGORIES
from app.services.ingestion_state import PipelineState, bounded, preview_of, redact_str
from app.services.notify import notify

N = ProvenanceNodeType
R = ProvenanceRelation
# The operator's own prompts may instruct the agent: detections there are recorded on the item but
# do not raise findings.
OPERATOR_SOURCE_TYPES = frozenset({"user_prompt", "system"})
_TYPE_LABELS = {
    "web": "web page", "repository": "repository", "file": "file", "document": "document", "email": "email",
    "api": "API response", "mcp_server": "MCP server", "mcp_tool": "MCP tool", "browser": "browser page",
    "database": "database", "user_upload": "uploaded file", "user_prompt": "user prompt",
    "tool_output": "tool output", "agent_output": "agent output", "system": "system prompt", "other": "source",
}


@dataclass
class ContextInput:
    source_type: str
    identifier: str  # raw as reported/derived; canonicalised and redacted before storage
    raw_text: str
    display_name: str | None = None
    content_type: str = "text/plain"
    source_metadata: dict[str, Any] | None = None
    item_metadata: dict[str, Any] | None = None
    tool_invocation_id: str | None = None
    origin_agent_id: str | None = None
    origin_session_id: str | None = None
    inherited_level: str | None = None  # for agent/tool output: least trusted input it was produced from
    trust_ceiling: tuple[str, str] | None = None  # (level, reason): e.g. an MCP tool capped by its server
    extra_evidence: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # rule_id -> evidence


@dataclass
class ContextOutcome:
    item: ContextItem
    source: ContextSource
    hits: list[DetectionHit]
    finding_ids: list[str]


def label_for(source_type: str) -> str:
    return _TYPE_LABELS.get(source_type, "source")


def receipt_input(item: ContextItem, source: ContextSource) -> dict[str, Any]:
    """The mapping a context receipt is computed from (also used to verify it later)."""
    return {
        "id": item.id, "organization_id": item.organization_id,
        "source": {"type": source.source_type, "identifier": source.identifier},
        "trust_level": item.trust_level, "agent_id": item.agent_id, "session_id": item.session_id,
        "event_id": item.event_id, "collected_via": item.collected_via, "collected_at": item.collected_at,
        "received_at": item.received_at, "content_hash": item.content_hash, "content_length": item.content_length,
        "content_type": item.content_type, "sensitivity": item.sensitivity, "contains_secrets": item.contains_secrets,
        "secret_fingerprints": item.secret_fingerprints, "detection_summary": item.detection_summary,
        "tool_invocation_id": item.tool_invocation_id,
    }


def _history(source: ContextSource, inherited: str | None) -> SourceHistory:
    return SourceHistory(
        observation_count=source.observation_count or 0,
        finding_count=source.finding_count or 0,
        max_finding_severity=source.max_finding_severity,
        manually_classified=bool(source.manually_classified),
        current_level=source.trust_level,
        current_capabilities=tuple(source.trust_capabilities or ()),
        inherited_level=inherited,
    )


def _apply_ceiling(assessment: TrustAssessment, ceiling: tuple[str, str] | None) -> TrustAssessment:
    if ceiling is None:
        return assessment
    level, reason = ceiling
    if level in TRUST_RANK and TRUST_RANK[level] < TRUST_RANK.get(assessment.level, 2):
        assessment.level = level
        assessment.capabilities = [c for c in assessment.capabilities if c == "read"] if level != "BLOCKED" else []
        assessment.reasons = [*assessment.reasons, reason]
    return assessment


def _hit_dict(hit: DetectionHit) -> dict[str, Any]:
    return {"rule_id": hit.rule_id, "category": hit.category, "severity": hit.severity,
            "confidence": hit.confidence, "technique": hit.technique, "title": hit.title}


def record_context(st: PipelineState, ci: ContextInput) -> ContextOutcome:
    assert st.agent is not None and st.session is not None
    db, org = st.db, st.ctx.org_id
    settings = get_settings()

    canonical_raw, domain = canonicalize_source(ci.source_type, ci.identifier)
    canonical = (redact_session_text(st, canonical_raw or ci.identifier.strip()) or "")[:2048] or ci.source_type
    source = upsert_source(st, ci.source_type, canonical, domain, display_name=ci.display_name,
                           metadata=ci.source_metadata)

    raw = ci.raw_text or ""
    redaction = redact_text(raw)
    st.remember_secrets(raw, redaction.matches)
    known = find_known(st, redaction.text)  # secrets seen earlier in the session, in a form not recognised here
    redacted_text = redact_known(redaction.text, known)
    detection = analyze_content(raw, source_type=ci.source_type, content_type=ci.content_type)
    hits = [_scrubbed(st, h) for h in detection.hits]
    high_secrets = [m for m in redaction.matches if m.confidence >= HIGH_CONFIDENCE]
    fingerprints: dict[str, dict[str, Any]] = {}
    for m in redaction.matches:
        entry = fingerprints.setdefault(m.fingerprint, {"type": m.secret_type, "fingerprint": m.fingerprint,
                                                        "confidence": m.confidence})
        entry["confidence"] = max(entry["confidence"], m.confidence)
    for entry in as_matches(known):
        fingerprints.setdefault(entry["fingerprint"], entry)
    sensitivity = Sensitivity.SECRET.value if known else str(
        classify_sensitivity(raw, redaction.matches, identifier=ci.identifier))

    before = _apply_ceiling(assess_source(ci.source_type, canonical, rules=st.source_rules(),
                                          history=_history(source, ci.inherited_level)), ci.trust_ceiling)
    summary = detection.to_summary()
    summary["hits"] = [_hit_dict(h) for h in hits]
    item_metadata, _ = redact_value(ci.item_metadata or {})
    item_metadata = redact_known(item_metadata, find_known(st, item_metadata))
    item = ContextItem(
        id=new_id("context_item"),
        organization_id=org,
        source_id=source.id,
        agent_id=st.agent.id,
        session_id=st.session.id,
        event_id=st.event.id,
        collected_via=(redact_str(st.env.collected_via, limit=200) if st.env.collected_via
                       else f"{st.integration_kind}:{st.env.event_type}"),
        collected_at=st.env.timestamp,
        received_at=st.now,
        content_type=ci.content_type[:64],
        content_hash=sha256_hex(raw),
        content_length=len(raw),
        redacted_preview=preview_of(redacted_text, settings.preview_chars) if st.store_previews and raw else None,
        sensitivity=sensitivity,
        contains_secrets=bool(high_secrets or known),
        secret_fingerprints=list(fingerprints.values()),
        trust_level=before.level,
        trust_capabilities=list(before.capabilities),
        detection_summary=summary,
        tool_invocation_id=ci.tool_invocation_id,
        origin_agent_id=ci.origin_agent_id,
        origin_session_id=ci.origin_session_id,
        is_simulation=st.ctx.is_simulation,
        item_metadata=bounded(item_metadata) if isinstance(item_metadata, dict) else {},
    )
    db.add(item)
    if item.contains_secrets:
        forget_session_fingerprints(st)
    st.add_ref("context_item_ids", item.id)
    st.add_ref("source_ids", source.id)

    finding_ids = _content_findings(st, ci, item, source, hits, before)

    after = _apply_ceiling(assess_source(ci.source_type, canonical, rules=st.source_rules(),
                                         history=_history(source, ci.inherited_level)), ci.trust_ceiling)
    _apply_source_assessment(st, source, after, before)
    item.trust_level = after.level
    item.trust_capabilities = list(after.capabilities)
    item.receipt_signature = sign_receipt(receipt_fields(receipt_input(item, source)))

    add_edge(st, N.SOURCE, source.id, N.CONTEXT_ITEM, item.id, R.SOURCE_PRODUCED_ITEM)
    add_edge(st, N.CONTEXT_ITEM, item.id, N.SESSION, st.session.id, R.ITEM_ENTERED_SESSION)
    if ci.tool_invocation_id:
        add_edge(st, N.TOOL_INVOCATION, ci.tool_invocation_id, N.CONTEXT_ITEM, item.id, R.INVOCATION_RETURNED_ITEM)
    if ci.origin_session_id:
        add_edge(st, N.SESSION, ci.origin_session_id, N.CONTEXT_ITEM, item.id, R.AGENT_MESSAGED,
                 metadata={"origin_agent_id": ci.origin_agent_id})
    for fid in finding_ids:
        add_edge(st, N.CONTEXT_ITEM, item.id, N.FINDING, fid, R.ITEM_TRIGGERED_FINDING)
    db.flush()
    return ContextOutcome(item=item, source=source, hits=hits, finding_ids=finding_ids)


def _scrubbed(st: PipelineState, hit: DetectionHit) -> DetectionHit:
    excerpt = st.scrub(hit.excerpt)
    return hit if excerpt == hit.excerpt else replace(hit, excerpt=excerpt)


def _content_findings(
    st: PipelineState, ci: ContextInput, item: ContextItem, source: ContextSource,
    hits: list[DetectionHit], before: TrustAssessment,
) -> list[str]:
    if not hits or ci.source_type in OPERATOR_SOURCE_TYPES:
        return []
    label = f"{label_for(ci.source_type)} {source.identifier[:160]}"
    ids: list[str] = []
    new_count, worst = 0, None
    for hit in hits:
        evidence = [
            {"type": "context_item", "id": item.id, "excerpt": hit.excerpt,
             "detail": f"rule {hit.rule_id}; revealed via {hit.technique.replace('_', ' ')}; confidence {hit.confidence:.2f}"},
            {"type": "source", "id": source.id, "excerpt": None, "detail": f"{label} (trust {before.level})"},
            *ci.extra_evidence.get(hit.rule_id, []),
            {"type": "event", "id": st.event.id, "excerpt": None, "detail": f"{st.env.event_type} event"},
        ]
        finding, created = raise_finding(
            st,
            category=hit.category,
            rule_id=hit.rule_id,
            title=f"{hit.title} in {label}"[:400],
            explanation=(
                f"{hit.explanation} Observed in {label} (trust {before.level}), which entered this session of "
                f"agent '{st.agent.name if st.agent else ''}'. A detection is evidence of manipulative content, "
                "not proof the agent acted on it."
            ),
            severity=hit.severity,
            confidence=hit.confidence,
            evidence=evidence,
            source_id=source.id,
            context_item_id=item.id,
        )
        ids.append(finding.id)
        if created:
            new_count += 1
            if worst is None or SEVERITY_RANK.get(hit.severity, 0) > SEVERITY_RANK.get(worst, 0):
                worst = hit.severity
    instructions = [h for h in hits if h.category in INJECTION_CATEGORIES
                    and SEVERITY_RANK.get(h.severity, 0) >= SEVERITY_RANK[Severity.MEDIUM]]
    if instructions and not before.can_instruct:
        finding, _ = raise_finding(
            st,
            category=FindingCategory.UNTRUSTED_SOURCE.value,
            rule_id="CTX-UNTRUSTED-INSTRUCTIONS",
            title=f"Instructions in content from a source that may not instruct the agent: {label}"[:400],
            explanation=(
                f"Content from this {label_for(ci.source_type)} is classified {before.level}, which allows it to be "
                "read as data but not to direct the agent, yet it contains text addressed to the agent as "
                f"instructions ({', '.join(sorted({h.rule_id for h in instructions}))})."
            ),
            severity=Severity.LOW.value,
            confidence=0.9,
            evidence=[{"type": "context_item", "id": item.id, "excerpt": instructions[0].excerpt, "detail": None},
                      {"type": "source", "id": source.id, "excerpt": None, "detail": f"trust {before.level}"}],
            source_id=source.id,
            context_item_id=item.id,
        )
        ids.append(finding.id)
    if new_count:
        source.finding_count = (source.finding_count or 0) + new_count
        if worst and SEVERITY_RANK.get(worst, 0) > SEVERITY_RANK.get(source.max_finding_severity or "", -1):
            source.max_finding_severity = worst
    return list(dict.fromkeys(ids))


def _apply_source_assessment(
    st: PipelineState, source: ContextSource, assessment: TrustAssessment, before: TrustAssessment
) -> None:
    """Store the post-evidence classification; audit it when it differs from the prior one."""
    # A brand-new source has no prior classification of its own; compare with the assessment made
    # before this item's findings were counted.
    prior = source.trust_level if (source.observation_count or 0) > 1 else before.level
    source.trust_level = assessment.level
    source.trust_capabilities = list(assessment.capabilities)
    source.trust_reasons = [redact_str(r, limit=1000) for r in assessment.reasons]
    source.trust_rule_id = assessment.matched_rule_id
    if assessment.domain and not source.domain:
        source.domain = assessment.domain
    if prior != assessment.level:
        append_audit(
            st.db, st.ctx.org_id, action="trust.source_reclassified", actor_type="system",
            target_type="context_source", target_id=source.id,
            details={"from": prior, "to": assessment.level, "event_id": st.event.id,
                     "reason": source.trust_reasons[-1] if source.trust_reasons else None},
        )
        notify(st.db, st.ctx.org_id, "trust.updated", id=source.id)
