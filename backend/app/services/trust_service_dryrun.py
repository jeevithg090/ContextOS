"""Trust Centre dry runs: test trust rules against an identifier and verify a destination.

Nothing here writes to the database. Identifiers are redacted and canonicalised exactly as the
ingestion pipeline does before it classifies them, so a dry run gives the same answer the pipeline
would. When the identifier corresponds to a stored source or destination, the result also shows
what re-assessing that record now would produce with its recorded history (manual classification,
findings, inherited trust).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from sqlalchemy.orm import Session

from app.engines.trust import (
    DestinationHistory,
    TrustAssessment,
    TrustRuleSpec,
    assess_destination,
    assess_source,
    canonicalize_source,
)
from app.engines.trust.destinations import parse_destination
from app.models import ContextSource, Destination
from app.services.loaders import load_trust_rule_specs
from app.services.scoping import scoped
from app.services.trust_service import rule_errors
from app.services.trust_service_assess import (
    assess_destination_row,
    assess_source_row,
    matching_destination_rules,
    matching_source_rules,
    redact_line,
    source_context,
)
from app.services.trust_service_common import normalise_capabilities, rule_ref
from app.services.trust_service_destinations import destination_assessment_out
from app.services.trust_service_history import manual_details

DRAFT_ID = "draft"


def _ref(rule: TrustRuleSpec) -> dict[str, Any]:
    return rule_ref(rule, is_draft=rule.id == DRAFT_ID)


def source_assessment_out(
    assessment: TrustAssessment, rules: list[TrustRuleSpec], source_type: str, identifier: str
) -> dict[str, Any]:
    matching = matching_source_rules(rules, source_type, identifier)
    deciding = next((r for r in matching if r.id == assessment.matched_rule_id), None)
    return {
        "scope": "source",
        "level": assessment.level,
        "capabilities": list(assessment.capabilities),
        "reasons": list(assessment.reasons),
        "canonical_identifier": assessment.canonical_identifier,
        "domain": assessment.domain,
        "kind": None,
        "matched_rule": _ref(deciding) if deciding else None,
        "matching_rules": [_ref(r) for r in matching],
        "checks": [],
        "not_verified": [],
    }


def _destination_out(assessment: Any, rules: list[TrustRuleSpec], kind: str, identifier: str) -> dict[str, Any]:
    out = destination_assessment_out(assessment, rules, kind, identifier)
    out["matched_rule"] = _ref(next(r for r in rules if r.id == assessment.matched_rule_id)) \
        if assessment.matched_rule_id else None
    out["matching_rules"] = [_ref(r) for r in matching_destination_rules(rules, kind, identifier)]
    return out


def _stored_source_identifier(source_type: str, identifier: str) -> str:
    """The identifier the pipeline would store for this source (canonical, redacted, bounded)."""
    canonical, _ = canonicalize_source(source_type, identifier)
    return (redact_line(canonical or identifier.strip(), 2048) or "")[:2048] or source_type


def _existing_source(db: Session, org_id: str, source_type: str, identifier: str, rules: list[TrustRuleSpec]) -> dict[str, Any] | None:
    stored = _stored_source_identifier(source_type, identifier)
    row = db.scalar(scoped(ContextSource, org_id).where(
        ContextSource.source_type == source_type, ContextSource.identifier == stored))
    if row is None:
        return None
    ctx = source_context(db, org_id, row)
    manual = manual_details(db, org_id, row)
    intent = (manual["level"], manual["capabilities"]) if manual and manual.get("level") else None
    assessment = assess_source_row(row, rules, ctx, manual=intent)
    return {
        "type": "source", "id": row.id, "current_level": row.trust_level,
        "manually_classified": bool(row.manually_classified), "finding_count": ctx.evidence.count,
        "observation_count": row.observation_count or 0, "transfer_count": 0,
        "with_history": source_assessment_out(assessment, rules, row.source_type, row.identifier),
    }


def _find_destination(db: Session, org_id: str, kind: str, canonical: str) -> Destination | None:
    rows = list(db.scalars(scoped(Destination, org_id).where(Destination.identifier == canonical[:1024]).limit(10)))
    rows.sort(key=lambda r: r.kind != kind)
    return rows[0] if rows else None


def _destination_result(db: Session, org_id: str, kind: str, identifier: str, rules: list[TrustRuleSpec]) -> dict[str, Any]:
    ident = (redact_line(identifier, 1024) or "").strip()
    target = parse_destination(kind, ident)
    row = _find_destination(db, org_id, target.kind, target.canonical or ident)
    history = DestinationHistory(previously_seen=row is not None, transfer_count=(row.transfer_count or 0) if row else 0)
    assessment = assess_destination(kind, ident, rules=rules, history=history)
    existing = None
    if row is not None:
        stored = assess_destination_row(row, rules)
        existing = {
            "type": "destination", "id": row.id, "current_level": row.classification, "manually_classified": False,
            "finding_count": 0, "observation_count": 0, "transfer_count": row.transfer_count or 0,
            "with_history": _destination_out(stored, rules, row.kind, row.identifier),
        }
    return {"assessment": _destination_out(assessment, rules, kind, ident), "existing": existing}


def run_rule_test(db: Session, org_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Classify an identifier with the saved rules, optionally plus an unsaved draft rule."""
    rules = list(load_trust_rule_specs(db, org_id))
    replace_id = body.get("replace_rule_id")
    if replace_id:
        rules = [r for r in rules if r.id != replace_id]
    draft_errors: list[str] = []
    draft: TrustRuleSpec | None = None
    if body.get("draft"):
        d = dict(body["draft"])
        d["capabilities"] = normalise_capabilities(d.get("capabilities"), d["trust_level"], d["applies_to"])
        draft_errors = rule_errors(d)
        draft = TrustRuleSpec(
            id=DRAFT_ID, name=d["name"], pattern=d["pattern"], trust_level=d["trust_level"],
            capabilities=tuple(d["capabilities"]), source_type=d.get("source_type"), match_field=d["match_field"],
            applies_to=d["applies_to"], priority=int(d.get("priority", 100)), enabled=bool(d.get("enabled", True)),
        )
        if draft.enabled:
            rules.append(draft)

    if body.get("applies_to", "source") == "source":
        source_type = body.get("source_type") or "web"
        ident = (redact_line(body["identifier"], 2048) or "").strip()
        assessment = source_assessment_out(assess_source(source_type, ident, rules=rules), rules, source_type, ident)
        draft_matches = bool(matching_source_rules([replace(draft, enabled=True)], source_type, ident)) if draft else None
        existing = _existing_source(db, org_id, source_type, ident, rules)
    else:
        kind = body.get("kind") or "unknown"
        result = _destination_result(db, org_id, kind, body["identifier"], rules)
        assessment, existing = result["assessment"], result["existing"]
        ident = (redact_line(body["identifier"], 1024) or "").strip()
        draft_matches = bool(matching_destination_rules([replace(draft, enabled=True)], kind, ident)) if draft else None
    matched = assessment.get("matched_rule")
    return {
        "assessment": assessment,
        "draft_errors": draft_errors,
        "draft_matches": draft_matches,
        "draft_decides": bool(matched and matched.get("is_draft")) if draft else None,
        "existing": existing,
        "dry_run": True,
    }


def verify_destination(db: Session, org_id: str, kind: str, identifier: str) -> dict[str, Any]:
    """Run every destination check against the saved rules. Nothing is stored."""
    rules = list(load_trust_rule_specs(db, org_id, applies_to="destination"))
    return {**_destination_result(db, org_id, kind, identifier, rules), "dry_run": True}
