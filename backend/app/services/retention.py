"""Data retention: delete recorded event data older than each organisation's retention period.

``purge_expired(db, org_id)`` deletes, for one organisation, rows whose server-side timestamps are
older than ``now - retention_days`` (``retention_days`` is the organisation's effective setting,
``CONTEXTOS_RETENTION_DAYS`` by default). It runs in the caller's transaction; the caller commits.
Operators run it with ``contextos-server purge`` (schedule it daily, e.g. from cron).

What is deleted (all server timestamps; client-reported times are never used):

=====================  ==========================================================================
ingested_events        ``received_at`` older than the cutoff
context_items          ``received_at`` older than the cutoff
tool_invocations       requested (and, when set, completed) before the cutoff
policy_decisions       ``evaluated_at`` older than the cutoff
approvals              no longer pending, requested (and decided) before the cutoff
security_findings      status ``resolved`` or ``false_positive``, last seen and last updated before
                       the cutoff (open and acknowledged findings are never purged)
provenance_edges       ``observed_at`` older than the cutoff
agent_sessions         status ``ended``, ended and last active before the cutoff, nothing newer is
                       recorded in it, and no kept session was delegated from it
=====================  ==========================================================================

What is never deleted:

- **Audit entries.** The audit trail is a keyed hash chain: each entry's hash covers the previous
  entry's hash, and ``verify_chain`` recomputes the chain from the first entry. Deleting old entries
  would make every later entry unverifiable, so audit history is kept for the organisation's lifetime.
  Each purge itself writes one ``retention.purged`` audit entry with the per-table counts.
- **Evidence of open incidents** (status open, investigating or contained): the incident's findings,
  the context items, tool calls and policy decisions they cite, every recorded row of the sessions
  the incident involves (and of the sessions those cited records belong to), and the sessions they
  were delegated from. The evidence becomes purgeable once the incident is resolved or marked a false
  positive.
- Entities and configuration: organisations, users, agents, tools, sources, destinations, policies,
  trust rules, incidents and their activity, integrations, simulation runs, Engineering Workspace
  boards, tasks and prompts (a task that referenced a purged record shows it as no longer available).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, delete, exists, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.core.timeutil import ensure_utc, isoformat, utcnow
from app.domain.enums import ApprovalStatus, FindingStatus
from app.models import (
    AgentSession,
    Approval,
    ContextItem,
    Incident,
    IngestedEvent,
    Organization,
    PolicyDecision,
    ProvenanceEdge,
    SecurityFinding,
    ToolInvocation,
)
from app.schemas.admin import RETENTION_DAYS_RANGE
from app.services.audit import append_audit
from app.services.bootstrap import effective_org_settings
from app.services.incidents import ACTIVE_STATUSES
from app.services.incidents_query import involvement
from app.services.notify import notify

log = get_logger(__name__)

BATCH = 500
MAX_SESSION_DEPTH = 64
# Deletion order: rows that cite other rows first, sessions (the FK parent of items/invocations) last.
TABLES = ("provenance_edges", "approvals", "policy_decisions", "security_findings", "context_items",
          "tool_invocations", "ingested_events", "agent_sessions")
PURGEABLE_FINDING_STATUSES = (FindingStatus.RESOLVED.value, FindingStatus.FALSE_POSITIVE.value)


@dataclass
class Protected:
    """Ids kept regardless of age because an open incident relies on them."""

    incidents: set[str] = field(default_factory=set)
    sessions: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)
    context_items: set[str] = field(default_factory=set)
    tool_invocations: set[str] = field(default_factory=set)
    policy_decisions: set[str] = field(default_factory=set)
    events: set[str] = field(default_factory=set)

    def record_ids(self) -> set[str]:
        return (self.sessions | self.findings | self.context_items | self.tool_invocations
                | self.policy_decisions | self.events)


@dataclass
class PurgeResult:
    org_id: str
    retention_days: int
    cutoff: datetime
    dry_run: bool
    counts: dict[str, int]
    protected_incidents: int

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def as_dict(self) -> dict[str, Any]:
        return {"org_id": self.org_id, "retention_days": self.retention_days, "cutoff": isoformat(self.cutoff),
                "dry_run": self.dry_run, "counts": dict(self.counts), "total": self.total,
                "protected_incidents": self.protected_incidents}


def retention_days(org: Organization) -> int:
    value = effective_org_settings(org).get("retention_days")
    low, high = RETENTION_DAYS_RANGE
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValidationFailedError(f"Organisation {org.slug} has an invalid retention_days setting ({value!r}); "
                                    f"set it to a whole number of days between {low} and {high}.")
    return value


# ----------------------------------------------------------------------------- protection


def _chunks(values: Iterable[str], size: int = BATCH) -> Iterable[list[str]]:
    items = list(values)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _sessions_of(db: Session, org_id: str, model: Any, ids: set[str]) -> set[str]:
    found: set[str] = set()
    for chunk in _chunks(ids):
        found.update(s for (s,) in db.execute(select(model.session_id).where(
            model.organization_id == org_id, model.id.in_(chunk))) if s)
    return found


def _with_ancestors(db: Session, org_id: str, sessions: set[str]) -> set[str]:
    result, frontier = set(sessions), set(sessions)
    for _ in range(MAX_SESSION_DEPTH):
        parents: set[str] = set()
        for chunk in _chunks(frontier):
            parents.update(p for (p,) in db.execute(select(AgentSession.parent_session_id).where(
                AgentSession.organization_id == org_id, AgentSession.id.in_(chunk),
                AgentSession.parent_session_id.is_not(None))) if p)
        frontier = parents - result
        if not frontier:
            break
        result |= frontier
    return result


def protected_records(db: Session, org_id: str) -> Protected:
    """Everything an open incident of ``org_id`` relies on (see the module docstring)."""
    keep = Protected()
    for incident in db.scalars(select(Incident).where(Incident.organization_id == org_id,
                                                      Incident.status.in_(ACTIVE_STATUSES))):
        inv = involvement(db, org_id, incident)
        keep.incidents.add(incident.id)
        keep.findings.update(f.id for f in inv.findings)
        keep.sessions.update(inv.sessions)
        keep.context_items |= inv.context_items
        keep.tool_invocations |= inv.tool_invocations
        keep.policy_decisions |= inv.policy_decisions
        for finding in inv.findings:
            keep.events.update(str(ev["id"]) for ev in finding.evidence or []
                               if isinstance(ev, dict) and ev.get("type") == "event" and ev.get("id"))
    # A cited record keeps its whole session (deleting the session would cascade to the record), and a
    # kept session keeps the sessions it was delegated from.
    for model, ids in ((ContextItem, keep.context_items), (ToolInvocation, keep.tool_invocations),
                       (PolicyDecision, keep.policy_decisions), (IngestedEvent, keep.events)):
        keep.sessions |= _sessions_of(db, org_id, model, ids)
    keep.sessions = _with_ancestors(db, org_id, keep.sessions)
    return keep


# ----------------------------------------------------------------------------- purge


def _purge_rows(db: Session, org_id: str, model: Any, conditions: list[ColumnElement[bool]],
                columns: list[Any], is_protected: Callable[[Any], bool], *, dry_run: bool) -> int:
    """Delete (or count) rows matching ``conditions`` in id-ordered batches, skipping protected ones."""
    count, last = 0, ""
    while True:
        rows = db.execute(select(model.id, *columns).where(model.organization_id == org_id, model.id > last,
                                                           *conditions).order_by(model.id).limit(BATCH)).all()
        if not rows:
            return count
        last = rows[-1][0]
        doomed = [row[0] for row in rows if not is_protected(row)]
        if doomed and not dry_run:
            db.execute(delete(model).where(model.organization_id == org_id, model.id.in_(doomed))
                       .execution_options(synchronize_session=False))
        count += len(doomed)


def _purgeable_sessions(db: Session, org_id: str, cutoff: datetime, keep: Protected) -> list[str]:
    newer = [
        exists().where(ContextItem.organization_id == org_id, ContextItem.session_id == AgentSession.id,
                       ContextItem.received_at >= cutoff),
        exists().where(ToolInvocation.organization_id == org_id, ToolInvocation.session_id == AgentSession.id,
                       or_(ToolInvocation.requested_at >= cutoff, ToolInvocation.completed_at >= cutoff)),
        exists().where(IngestedEvent.organization_id == org_id, IngestedEvent.session_id == AgentSession.id,
                       IngestedEvent.received_at >= cutoff),
    ]
    candidates = {sid for (sid,) in db.execute(select(AgentSession.id).where(
        AgentSession.organization_id == org_id, AgentSession.status == "ended",
        AgentSession.ended_at.is_not(None), AgentSession.ended_at < cutoff,
        or_(AgentSession.last_event_at.is_(None), AgentSession.last_event_at < cutoff),
        *[~clause for clause in newer],
    ))} - keep.sessions
    # A session stays while any session delegated from it stays (its parent link would be lost).
    while candidates:
        kept_parents: set[str] = set()
        for chunk in _chunks(candidates):
            for child, parent in db.execute(select(AgentSession.id, AgentSession.parent_session_id).where(
                    AgentSession.organization_id == org_id, AgentSession.parent_session_id.in_(chunk))):
                if child not in candidates:
                    kept_parents.add(parent)
        if not kept_parents:
            break
        candidates -= kept_parents
    return sorted(candidates)


def _delete_sessions(db: Session, org_id: str, ids: list[str], *, dry_run: bool) -> int:
    if not dry_run:
        for chunk in _chunks(ids):
            db.execute(delete(AgentSession).where(AgentSession.organization_id == org_id, AgentSession.id.in_(chunk))
                       .execution_options(synchronize_session=False))
    return len(ids)


def purge_expired(db: Session, org_id: str, *, now: datetime | None = None, dry_run: bool = False) -> PurgeResult:
    """Delete ``org_id``'s recorded event data older than its retention period. Returns per-table counts.

    ``dry_run`` counts what would be deleted, deletes nothing and writes no audit entry. Otherwise one
    ``retention.purged`` audit entry records the counts (also when nothing was old enough).
    """
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    if org is None:
        raise NotFoundError("Organization not found")
    days = retention_days(org)
    cutoff = ensure_utc(now or utcnow()) - timedelta(days=days)
    keep = protected_records(db, org_id)
    record_ids = keep.record_ids()
    sessions = keep.sessions

    counts: dict[str, int] = {}
    counts["provenance_edges"] = _purge_rows(
        db, org_id, ProvenanceEdge, [ProvenanceEdge.observed_at < cutoff],
        [ProvenanceEdge.session_id, ProvenanceEdge.src_id, ProvenanceEdge.dst_id],
        lambda r: r.session_id in sessions or r.src_id in record_ids or r.dst_id in record_ids, dry_run=dry_run)
    counts["approvals"] = _purge_rows(
        db, org_id, Approval,
        [Approval.status != ApprovalStatus.PENDING.value, Approval.requested_at < cutoff,
         or_(Approval.decided_at.is_(None), Approval.decided_at < cutoff)],
        [Approval.session_id, Approval.policy_decision_id],
        lambda r: r.session_id in sessions or r.policy_decision_id in keep.policy_decisions, dry_run=dry_run)
    counts["policy_decisions"] = _purge_rows(
        db, org_id, PolicyDecision, [PolicyDecision.evaluated_at < cutoff], [PolicyDecision.session_id],
        lambda r: r.session_id in sessions or r.id in keep.policy_decisions, dry_run=dry_run)
    counts["security_findings"] = _purge_rows(
        db, org_id, SecurityFinding,
        [SecurityFinding.status.in_(PURGEABLE_FINDING_STATUSES), SecurityFinding.last_seen_at < cutoff,
         SecurityFinding.updated_at < cutoff],
        [SecurityFinding.incident_id],
        lambda r: r.id in keep.findings or (r.incident_id is not None and r.incident_id in keep.incidents),
        dry_run=dry_run)
    counts["context_items"] = _purge_rows(
        db, org_id, ContextItem, [ContextItem.received_at < cutoff], [ContextItem.session_id],
        lambda r: r.session_id in sessions or r.id in keep.context_items, dry_run=dry_run)
    counts["tool_invocations"] = _purge_rows(
        db, org_id, ToolInvocation,
        [ToolInvocation.requested_at < cutoff,
         or_(ToolInvocation.completed_at.is_(None), ToolInvocation.completed_at < cutoff)],
        [ToolInvocation.session_id],
        lambda r: r.session_id in sessions or r.id in keep.tool_invocations, dry_run=dry_run)
    counts["ingested_events"] = _purge_rows(
        db, org_id, IngestedEvent, [IngestedEvent.received_at < cutoff], [IngestedEvent.session_id],
        lambda r: (r.session_id is not None and r.session_id in sessions) or r.id in keep.events, dry_run=dry_run)
    counts["agent_sessions"] = _delete_sessions(db, org_id, _purgeable_sessions(db, org_id, cutoff, keep),
                                                dry_run=dry_run)

    result = PurgeResult(org_id=org_id, retention_days=days, cutoff=cutoff, dry_run=dry_run,
                         counts={t: counts[t] for t in TABLES}, protected_incidents=len(keep.incidents))
    if not dry_run:
        db.flush()
        append_audit(db, org_id, action="retention.purged", actor_type="system", target_type="organization",
                     target_id=org_id, details={k: v for k, v in result.as_dict().items() if k != "org_id"})
        if result.total:
            notify(db, org_id, "retention.purged", id=org_id)
    log.info("retention.purge", extra={"org_id": org_id, "dry_run": dry_run, "total": result.total,
                                       "retention_days": days})
    return result


def purge_all(db: Session, *, now: datetime | None = None, dry_run: bool = False) -> list[PurgeResult]:
    """Run :func:`purge_expired` for every organisation (in the caller's transaction)."""
    org_ids = list(db.scalars(select(Organization.id).order_by(Organization.created_at, Organization.id)))
    return [purge_expired(db, org_id, now=now, dry_run=dry_run) for org_id in org_ids]
