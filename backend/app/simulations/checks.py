"""Expectation factories: each returns an :class:`Expectation` that inspects what the real pipeline
recorded for ONE simulation run (only rows tied to the run's sessions or written during it)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select

from app.domain.enums import FindingStatus
from app.models import (
    Approval,
    AuditEvent,
    ContextItem,
    ContextSource,
    Destination,
    Incident,
    IngestedEvent,
    PolicyDecision,
    ProvenanceEdge,
    SecurityFinding,
    Tool,
    ToolInvocation,
)
from app.simulations.model import CheckResult, Expectation, RunView

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _findings(rv: RunView) -> list[SecurityFinding]:
    if not rv.session_ids:
        return []
    return list(rv.db.scalars(select(SecurityFinding).where(
        SecurityFinding.organization_id == rv.org_id, SecurityFinding.session_id.in_(rv.session_ids),
        SecurityFinding.status != FindingStatus.FALSE_POSITIVE.value,
    ).order_by(SecurityFinding.created_at)))


def _ev(rows: Iterable[Any], kind: str) -> list[dict[str, str]]:
    return [{"type": kind, "id": row.id} for row in rows][:10]


def _join(values: Iterable[str]) -> str:
    items = sorted(set(values))
    return ", ".join(items) if items else "none"


# -- decisions ---------------------------------------------------------------------------------------


def decision(step: str, allowed: tuple[str, ...], why: str, *, executed: bool | None = None) -> Expectation:
    """The configured policy returns one of ``allowed`` for the tool request recorded at ``step``."""
    wanted = " or ".join(allowed)

    def check(rv: RunView) -> CheckResult:
        outcome = rv.outcomes.get(step)
        if outcome is None or outcome.decision is None:
            return CheckResult(wanted, "no decision was recorded" + (f" ({outcome.error})" if outcome and outcome.error else ""),
                               False)
        actual = f"{outcome.decision} ({outcome.enforcement})"
        ok = outcome.decision in allowed and (executed is None or outcome.executed == executed)
        return CheckResult(f"{wanted} (enforced)", actual, ok and outcome.enforcement == "enforced", outcome.evidence())

    return Expectation(id=f"decision:{step}", description=why, check=check)


# -- findings ----------------------------------------------------------------------------------------


def finding(why: str, *, categories: tuple[str, ...] = (), rule_ids: tuple[str, ...] = (),
            min_severity: str = "low", eid: str | None = None) -> Expectation:
    """At least one finding in the run matches a category or rule id at ``min_severity`` or above."""
    target = " / ".join([*categories, *rule_ids])

    def check(rv: RunView) -> CheckResult:
        rows = [f for f in _findings(rv)
                if (f.category in categories or f.rule_id in rule_ids)
                and _SEVERITY_RANK.get(f.severity, 0) >= _SEVERITY_RANK[min_severity]]
        if rows:
            best = max(rows, key=lambda f: _SEVERITY_RANK.get(f.severity, 0))
            return CheckResult(f"a {target} finding (severity ≥ {min_severity})",
                               f"{len(rows)} finding(s), highest {best.severity}: {best.title}", True,
                               _ev(rows, "finding"))
        seen = _findings(rv)
        return CheckResult(f"a {target} finding (severity ≥ {min_severity})",
                           f"none; findings raised: {_join(f.category for f in seen)}", False, _ev(seen, "finding"))

    return Expectation(id=eid or f"finding:{target}", description=why, check=check)


def no_findings(why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        rows = _findings(rv)
        if not rows:
            return CheckResult("no findings", "no findings", True)
        return CheckResult("no findings", f"{len(rows)} finding(s): {_join(f.rule_id for f in rows)}", False,
                           _ev(rows, "finding"))

    return Expectation(id="no-findings", description=why, check=check)


def incident_opened(why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        ids = {f.incident_id for f in _findings(rv) if f.incident_id}
        rows = list(rv.db.scalars(select(Incident).where(Incident.organization_id == rv.org_id,
                                                         Incident.id.in_(ids)))) if ids else []
        if rows:
            return CheckResult("an incident is opened", f"incident #{rows[0].number} ({rows[0].severity})", True,
                               _ev(rows, "incident"))
        return CheckResult("an incident is opened", "no incident", False)

    return Expectation(id="incident", description=why, check=check)


# -- trust and provenance ----------------------------------------------------------------------------


def source_trust(source_type: str, identifier: str, allowed: tuple[str, ...], why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        rows = list(rv.db.scalars(
            select(ContextSource).join(ContextItem, ContextItem.source_id == ContextSource.id).where(
                ContextItem.organization_id == rv.org_id, ContextItem.session_id.in_(rv.session_ids),
                ContextSource.source_type == source_type).distinct()))
        match = [s for s in rows if s.identifier.lower() == identifier.lower() or s.identifier.endswith(identifier)]
        if not match:
            return CheckResult(" or ".join(allowed), f"no {source_type} source '{identifier}' was recorded", False)
        level = match[0].trust_level
        return CheckResult(" or ".join(allowed), level, level in allowed, _ev(match, "context_source"))

    return Expectation(id=f"trust:{source_type}:{identifier}", description=why, check=check)


def poisoned_tool(server: str, tool: str, why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        row = rv.db.scalar(select(Tool).where(Tool.organization_id == rv.org_id, Tool.name == tool,
                                              Tool.provider == f"mcp:{server.lower()}"))
        if row is None:
            return CheckResult("tool flagged as poisoned", f"tool '{tool}' was not recorded", False)
        poisoning = (row.tool_metadata or {}).get("poisoning")
        if poisoning:
            return CheckResult("tool flagged as poisoned", f"flagged by {', '.join(poisoning.get('rule_ids') or [])}",
                               True, [{"type": "tool", "id": row.id}])
        return CheckResult("tool flagged as poisoned", "not flagged", False, [{"type": "tool", "id": row.id}])

    return Expectation(id=f"poisoned:{server}/{tool}", description=why, check=check)


def delegation_recorded(why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        rows = list(rv.db.scalars(select(ProvenanceEdge).where(
            ProvenanceEdge.organization_id == rv.org_id, ProvenanceEdge.relation == "session_delegated_to",
            ProvenanceEdge.src_id.in_(rv.session_ids))))
        if rows:
            return CheckResult("delegation edge recorded", "parent → child delegation recorded", True,
                               _ev(rows, "provenance_edge"))
        return CheckResult("delegation edge recorded", "no delegation edge", False)

    return Expectation(id="delegation", description=why, check=check)


# -- data handling -----------------------------------------------------------------------------------

_SESSION_TABLES = (IngestedEvent, ContextItem, ToolInvocation, PolicyDecision, SecurityFinding, ProvenanceEdge, Approval)


def _row_text(row: Any) -> str:
    values = {c.key: getattr(row, c.key) for c in row.__mapper__.column_attrs}
    return json.dumps(values, default=str, ensure_ascii=False)


def run_rows(rv: RunView) -> list[Any]:
    """Every persisted row this run wrote that may carry agent-derived text."""
    db, org, sessions = rv.db, rv.org_id, rv.session_ids
    rows: list[Any] = []
    for model in _SESSION_TABLES:
        rows.extend(db.scalars(select(model).where(model.organization_id == org, model.session_id.in_(sessions))))
    source_ids = {r.source_id for r in rows if isinstance(r, ContextItem)}
    tool_ids = {r.tool_id for r in rows if isinstance(r, ToolInvocation)}
    dest_ids = {r.destination_id for r in rows if isinstance(r, ToolInvocation) and r.destination_id}
    for model, ids in ((ContextSource, source_ids), (Tool, tool_ids), (Destination, dest_ids)):
        if ids:
            rows.extend(db.scalars(select(model).where(model.organization_id == org, model.id.in_(ids))))
    rows.extend(db.scalars(select(Incident).where(Incident.organization_id == org,
                                                  Incident.primary_session_id.in_(sessions))))
    rows.extend(db.scalars(select(AuditEvent).where(AuditEvent.organization_id == org,
                                                    AuditEvent.seq > rv.audit_seq_before)))
    return rows


def secrets_redacted(why: str) -> Expectation:
    """None of the run's synthetic credentials appears raw in any row the run wrote."""

    def check(rv: RunView) -> CheckResult:
        rows = run_rows(rv)
        leaks = [r for r in rows if any(c in _row_text(r) for c in rv.vars.canaries())]
        if leaks:
            tables = _join(r.__tablename__ for r in leaks)
            return CheckResult("no raw secret stored", f"raw secret found in: {tables}", False,
                               [{"type": r.__tablename__, "id": r.id} for r in leaks][:10])
        return CheckResult("no raw secret stored", f"none found in {len(rows)} rows checked", True)

    return Expectation(id="redaction", description=why, check=check)


def session_matched_secret(step: str, why: str) -> Expectation:
    """The pipeline recognised a secret the session had read inside the request at ``step``."""

    def check(rv: RunView) -> CheckResult:
        outcome = rv.outcomes.get(step)
        decision_id = outcome.refs.get("policy_decision_id") if outcome else None
        row = rv.db.get(PolicyDecision, decision_id) if decision_id else None
        if row is None or row.organization_id != rv.org_id:
            return CheckResult("secret recognised by fingerprint", "no decision recorded", False)
        matches = (row.input_snapshot or {}).get("session_secret_matches") or []
        if matches:
            return CheckResult("secret recognised by fingerprint",
                               f"matched {_join(str(m.get('type')) for m in matches)} read earlier in the session", True,
                               [{"type": "policy_decision", "id": row.id}])
        return CheckResult("secret recognised by fingerprint", "no match", False, [{"type": "policy_decision", "id": row.id}])

    return Expectation(id=f"fingerprint:{step}", description=why, check=check)


def trifecta(why: str) -> Expectation:
    def check(rv: RunView) -> CheckResult:
        flagged = [o for o in rv.outcomes.values() if (o.refs.get("risk") or {}).get("trifecta")]
        if flagged:
            return CheckResult("lethal trifecta detected", f"detected at step '{flagged[0].label}'", True,
                               flagged[0].evidence())
        return CheckResult("lethal trifecta detected", "not detected", False)

    return Expectation(id="trifecta", description=why, check=check)
