"""Recording security findings (shared by ingestion, simulations and analysts).

Findings are de-duplicated by a fingerprint of (category, rule, the most specific subject), so a
README re-read 50 times produces one finding with ``occurrence_count == 50`` rather than 50 rows.
High-impact findings are escalated to incidents via ``app.services.incidents``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ids import new_id
from app.core.security import sha256_hex
from app.core.timeutil import utcnow
from app.domain.enums import SEVERITY_RANK, FindingStatus
from app.models import SecurityFinding
from app.services.notify import notify


def finding_fingerprint(
    org_id: str,
    category: str,
    rule_id: str,
    *,
    session_id: str | None,
    source_id: str | None,
    tool_invocation_id: str | None,
    destination_id: str | None,
) -> str:
    subject = tool_invocation_id or destination_id or source_id or ""
    # Scope source-level findings per session so each affected session is visible, but repeated
    # reads within one session collapse.
    return sha256_hex("|".join([org_id, category, rule_id, session_id or "", subject]))


def record_finding(
    db: Session,
    org_id: str,
    *,
    category: str,
    rule_id: str,
    title: str,
    explanation: str,
    severity: str,
    confidence: float,
    evidence: list[dict[str, Any]],
    agent_id: str | None = None,
    session_id: str | None = None,
    source_id: str | None = None,
    context_item_id: str | None = None,
    tool_invocation_id: str | None = None,
    policy_decision_id: str | None = None,
    destination_id: str | None = None,
    remediation: str | None = None,
    is_simulation: bool = False,
) -> tuple[SecurityFinding, bool]:
    """Create or bump a finding. Returns ``(finding, created)``. Evidence excerpts must be redacted."""
    fp = finding_fingerprint(
        org_id, category, rule_id,
        session_id=session_id, source_id=source_id,
        tool_invocation_id=tool_invocation_id, destination_id=destination_id,
    )
    existing = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.organization_id == org_id,
            SecurityFinding.fingerprint == fp,
            SecurityFinding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        )
    )
    now = utcnow()
    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = severity
        existing.confidence = max(existing.confidence, confidence)
        known = {(e.get("type"), e.get("id")) for e in existing.evidence or []}
        merged = list(existing.evidence or [])
        for item in evidence:
            if (item.get("type"), item.get("id")) not in known and len(merged) < 50:
                merged.append(item)
        existing.evidence = merged
        notify(db, org_id, "finding.updated", id=existing.id)
        return existing, False

    finding = SecurityFinding(
        id=new_id("finding"),
        organization_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        category=category,
        rule_id=rule_id,
        title=title[:400],
        explanation=explanation,
        severity=severity,
        confidence=round(float(confidence), 3),
        status=FindingStatus.OPEN,
        evidence=evidence[:50],
        source_id=source_id,
        context_item_id=context_item_id,
        tool_invocation_id=tool_invocation_id,
        policy_decision_id=policy_decision_id,
        destination_id=destination_id,
        fingerprint=fp,
        first_seen_at=now,
        last_seen_at=now,
        remediation=remediation,
        is_simulation=is_simulation,
    )
    db.add(finding)
    db.flush()
    notify(db, org_id, "finding.created", id=finding.id, severity=severity, category=category)
    return finding, True
