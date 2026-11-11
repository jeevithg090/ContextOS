"""Trust Centre: source inventory, manual classification and re-assessment.

Manual classification sets the level and capabilities an administrator chose and takes precedence
over trust rules, but NOT over evidence: high-severity findings recorded for the source still keep it
SUSPICIOUS (the engine explains this in the reasons). The administrator's choice is recorded in the
audit trail; re-assessing restarts from it, so marking the findings false positive and re-assessing
restores the chosen level.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import String, case, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailedError
from app.domain.enums import SEVERITY_RANK, TRUST_RANK, Severity
from app.models import Agent, ContextItem, ContextSource, SecurityFinding
from app.services.audit import append_audit
from app.services.loaders import load_trust_rule_specs
from app.services.notify import notify
from app.services.scoping import get_scoped, paginate, scoped
from app.services.trust_service_assess import (
    assess_source_row,
    redact_line,
    source_context,
    store_source_assessment,
)
from app.services.trust_service_common import (
    Actor,
    capability_errors,
    normalise_capabilities,
    rule_ref,
    rules_by_id,
)
from app.services.trust_service_history import SOURCE_TARGET, history, manual_details
from app.services.trust_service_simulation import real_source_filter

FINDINGS_SHOWN = 20
ITEMS_SHOWN = 10

_RANK_CASE = case(TRUST_RANK, value=ContextSource.trust_level, else_=2)
SORTS: dict[str, Any] = {
    "last_seen": ContextSource.last_seen_at,
    "first_seen": ContextSource.first_seen_at,
    "observations": ContextSource.observation_count,
    "findings": ContextSource.finding_count,
    "trust": _RANK_CASE,
    "identifier": ContextSource.identifier,
}


def capability_filter(capability: str) -> Any:
    """JSON-list membership that works on SQLite JSON and PostgreSQL JSONB alike."""
    return cast(ContextSource.trust_capabilities, String).like(f'%"{capability}"%')


def _like(value: str) -> str:
    escaped = value.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_sources(
    db: Session,
    org_id: str,
    *,
    trust_levels: list[str] | None = None,
    source_type: str | None = None,
    q: str | None = None,
    manual: bool | None = None,
    has_findings: bool | None = None,
    capability: str | None = None,
    include_simulated: bool = False,
    sort: str = "-last_seen",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ContextSource], int]:
    """Sources of the organisation; simulation-only sources are left out unless ``include_simulated``."""
    stmt = scoped(ContextSource, org_id)
    if not include_simulated:
        stmt = stmt.where(real_source_filter())
    if trust_levels:
        stmt = stmt.where(ContextSource.trust_level.in_(trust_levels))
    if source_type:
        stmt = stmt.where(ContextSource.source_type == source_type)
    if q and q.strip():
        needle = _like(q)
        stmt = stmt.where(or_(
            func.lower(ContextSource.identifier).like(needle, escape="\\"),
            func.lower(ContextSource.display_name).like(needle, escape="\\"),
            func.lower(ContextSource.domain).like(needle, escape="\\"),
        ))
    if manual is not None:
        stmt = stmt.where(ContextSource.manually_classified.is_(manual))
    if has_findings is not None:
        stmt = stmt.where(ContextSource.finding_count > 0 if has_findings else ContextSource.finding_count == 0)
    if capability:
        stmt = stmt.where(capability_filter(capability))
    descending = sort.startswith("-")
    column = SORTS.get(sort.lstrip("-"), ContextSource.last_seen_at)
    stmt = stmt.order_by(column.desc() if descending else column.asc(), ContextSource.id)
    return paginate(db, stmt, limit=limit, offset=offset)


def source_out(row: ContextSource, rule_names: dict[str, str]) -> dict[str, Any]:
    return {
        "id": row.id,
        "source_type": row.source_type,
        "identifier": row.identifier,
        "display_name": row.display_name,
        "domain": row.domain,
        "trust_level": row.trust_level,
        "trust_capabilities": [str(c) for c in (row.trust_capabilities or [])],
        "trust_rule_id": row.trust_rule_id,
        "trust_rule_name": rule_names.get(row.trust_rule_id or ""),
        "manually_classified": bool(row.manually_classified),
        "observation_count": row.observation_count or 0,
        "finding_count": row.finding_count or 0,
        "max_finding_severity": row.max_finding_severity,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "is_simulation": bool(row.is_simulation),
    }


def sources_out(db: Session, org_id: str, rows: list[ContextSource]) -> list[dict[str, Any]]:
    names = {k: v.name for k, v in rules_by_id(db, org_id, [r.trust_rule_id for r in rows]).items()}
    return [source_out(r, names) for r in rows]


def get_source(db: Session, org_id: str, source_id: str) -> ContextSource:
    return get_scoped(db, ContextSource, source_id, org_id, label="Source")


# ----------------------------------------------------------------------------- detail


def _manual_reason(manual: dict[str, Any]) -> str | None:
    return manual.get("reason") or (
        f"Manually classified by {manual['actor_label']}: {manual['note']}" if manual.get("note") else None
    )


def _evidence_downgrade(row: ContextSource, rules: list[Any], ctx: Any, manual: tuple[str, list[str]] | None) -> dict[str, Any] | None:
    if ctx.evidence.count == 0 or SEVERITY_RANK.get(ctx.evidence.max_severity or "", -1) < SEVERITY_RANK[Severity.HIGH]:
        return None
    with_evidence = assess_source_row(row, rules, ctx, manual=manual)
    without = assess_source_row(row, rules, ctx, manual=manual, ignore_evidence=True)
    if TRUST_RANK.get(with_evidence.level, 2) >= TRUST_RANK.get(without.level, 2):
        return None
    noun = "finding" if ctx.evidence.count == 1 else "findings"
    return {
        "level_without_evidence": without.level,
        "level": with_evidence.level,
        "finding_count": ctx.evidence.count,
        "max_severity": ctx.evidence.max_severity,
        "explanation": (
            f"{ctx.evidence.count} {noun} recorded for content from this source (highest severity: "
            f"{ctx.evidence.max_severity}) {'is' if ctx.evidence.count == 1 else 'are'} not marked false positive, so "
            f"it is treated as {with_evidence.level} instead of {without.level}. Evidence outranks rules and manual "
            "classification. Mark the findings false positive if they were wrong, then re-assess the source."
        ),
    }


def source_detail(db: Session, org_id: str, row: ContextSource) -> dict[str, Any]:
    rules = load_trust_rule_specs(db, org_id, applies_to="source")
    ctx = source_context(db, org_id, row)
    manual = manual_details(db, org_id, row)
    intent = (manual["level"], manual["capabilities"]) if manual and manual.get("level") else None
    rule = rules_by_id(db, org_id, [row.trust_rule_id]).get(row.trust_rule_id or "")
    reasons = [str(r) for r in (row.trust_reasons or [])]
    manual_reason = _manual_reason(manual) if manual else None
    if manual_reason and manual_reason not in reasons:
        reasons.insert(0, manual_reason)

    findings_q = scoped(SecurityFinding, org_id).where(SecurityFinding.source_id == row.id)
    findings = list(db.scalars(findings_q.order_by(SecurityFinding.last_seen_at.desc()).limit(FINDINGS_SHOWN)))
    findings_total = int(db.scalar(select(func.count()).select_from(findings_q.subquery())) or 0)
    items = list(db.execute(
        select(ContextItem, Agent.name)
        .outerjoin(Agent, (Agent.id == ContextItem.agent_id) & (Agent.organization_id == org_id))
        .where(ContextItem.organization_id == org_id, ContextItem.source_id == row.id)
        .order_by(ContextItem.received_at.desc())
        .limit(ITEMS_SHOWN)
    ))
    return {
        **source_out(row, {rule.id: rule.name} if rule else {}),
        "trust_reasons": reasons,
        "matched_rule": rule_ref(rule) if rule else None,
        "evidence_downgrade": _evidence_downgrade(row, rules, ctx, intent),
        "manual_classification": (
            {k: manual[k] for k in ("at", "actor_label", "level", "capabilities", "note")} if manual else None
        ),
        "history": history(db, org_id, SOURCE_TARGET, row.id),
        "findings": [finding_ref(f) for f in findings],
        "findings_total": findings_total,
        "recent_items": [
            {
                "id": item.id, "session_id": item.session_id, "agent_id": item.agent_id, "agent_name": agent_name,
                "collected_via": item.collected_via, "received_at": item.received_at, "trust_level": item.trust_level,
                "max_severity": (item.detection_summary or {}).get("max_severity"),
                "is_simulation": bool(item.is_simulation),
            }
            for item, agent_name in items
        ],
    }


def finding_ref(f: SecurityFinding) -> dict[str, Any]:
    return {
        "id": f.id, "title": f.title, "category": f.category, "severity": f.severity, "status": f.status,
        "session_id": f.session_id, "occurrence_count": f.occurrence_count or 1, "last_seen_at": f.last_seen_at,
        "is_simulation": bool(f.is_simulation),
    }


# ----------------------------------------------------------------------------- mutations


def classify_source(
    db: Session, org_id: str, actor: Actor, row: ContextSource, *, level: str,
    capabilities: list[str] | None, note: str,
) -> ContextSource:
    """Manual classification: overrides rules (not evidence), audited with the administrator's note."""
    caps = normalise_capabilities(capabilities, level, "source")
    errors = capability_errors(level, "source", caps)
    if errors:
        raise ValidationFailedError("This classification is not valid", details={"errors": errors})
    note_text = redact_line(note, 1000) or ""
    reason = redact_line(f"Manually classified by {actor.label}: {note_text}", 1000) or ""
    rules = load_trust_rule_specs(db, org_id, applies_to="source")
    ctx = source_context(db, org_id, row)
    row.manually_classified = True
    assessment = assess_source_row(row, rules, ctx, manual=(level, caps))
    assessment.reasons.insert(0, reason)
    prior = store_source_assessment(row, assessment, ctx)
    db.flush()
    append_audit(
        db, org_id, action="trust.source_classified", actor_type=actor.type, actor_id=actor.id,
        target_type=SOURCE_TARGET, target_id=row.id,
        details={"from": prior, "to": row.trust_level, "requested_level": level, "requested_capabilities": caps,
                 "capabilities": list(row.trust_capabilities or []), "note": note_text, "reason": reason,
                 "source_type": row.source_type},
    )
    notify(db, org_id, "trust.updated", id=row.id, kind="source")
    return row


def reassess_source(db: Session, org_id: str, actor: Actor, row: ContextSource, *, reset_manual: bool) -> ContextSource:
    """Re-run the engine with current rules and evidence; optionally clear the manual classification."""
    was_manual = bool(row.manually_classified)
    manual = manual_details(db, org_id, row) if was_manual and not reset_manual else None
    if reset_manual:
        row.manually_classified = False
    rules = load_trust_rule_specs(db, org_id, applies_to="source")
    ctx = source_context(db, org_id, row)
    intent = (manual["level"], manual["capabilities"]) if manual and manual.get("level") else None
    assessment = assess_source_row(row, rules, ctx, manual=intent)
    manual_reason = _manual_reason(manual) if manual else None
    if manual_reason:
        assessment.reasons.insert(0, manual_reason)
    prior = store_source_assessment(row, assessment, ctx)
    db.flush()
    append_audit(
        db, org_id, action="trust.source_reassessed", actor_type=actor.type, actor_id=actor.id,
        target_type=SOURCE_TARGET, target_id=row.id,
        details={"from": prior, "to": row.trust_level, "reset_manual": bool(reset_manual and was_manual),
                 "finding_count": ctx.evidence.count, "reason": row.trust_reasons[-1] if row.trust_reasons else None},
    )
    notify(db, org_id, "trust.updated", id=row.id, kind="source")
    return row
