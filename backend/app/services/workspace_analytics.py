"""Engineering analytics and the security-remediation pipeline, computed from persisted rows only.

Definitions (the UI repeats them next to each number):
- *Open task*: not archived and not in a done column. *Done*: in a column with ``is_done_column``.
  Archived tasks are ignored everywhere.
- *Resolution time*: ``completed_at - created_at`` for tasks completed inside the window that are still
  done. Reopening a task clears ``completed_at``; it counts again when it completes again.
- A finding is *linked* to a task through ``Task.related_finding_id`` or a ``finding`` context reference.
- Remediation state of a finding: ``task_open`` while any linked task is not done; otherwise ``verified``
  when a done linked task has passed verification (``verification_status == "passed"``),
  ``task_done_unverified`` when the done tasks have no passed verification, ``no_task`` when nothing is
  linked. A fix attempt marked ``claimed_complete`` never makes anything verified.
- Finding metrics always cover the whole organisation (findings do not belong to boards); ``board_id``
  narrows the task metrics only.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailedError
from app.core.timeutil import ensure_utc, utcnow
from app.domain.enums import SEVERITY_RANK, TaskType
from app.models import Agent, Board, BoardColumn, SecurityFinding, Task, VerificationRun
from app.models import TaskContextReference as Ref
from app.schemas.workspace_analytics import (
    CountOut,
    CriticalItemOut,
    CycleBucketOut,
    EngineeringAnalyticsOut,
    FindingBacklogOut,
    OutstandingCriticalOut,
    RatioOut,
    RemediationCountsOut,
    RemediationFindingOut,
    RemediationPageOut,
    ReopenedOut,
    SeriesPointOut,
)
from app.schemas.workspace_boards import TaskCardOut
from app.services.scoping import get_scoped
from app.services.workspace_tasks_common import task_key
from app.services.workspace_views import task_cards
from app.workspace.templates import STATUS_KEYS

WINDOW_MAX_DAYS = 365
DAILY_SERIES_MAX_DAYS = 31
CRITICAL_LIST_LIMIT = 50
OPEN_FINDING_STATUSES = ("open", "acknowledged")
PRIORITIES = ("urgent", "high", "medium", "low", "none")
TASK_TYPES = tuple(t.value for t in TaskType)
STATES = ("no_task", "task_open", "task_done_unverified", "verified")
CYCLE_BUCKETS: tuple[tuple[str, str, float, float | None], ...] = (
    ("lt_4h", "Under 4 hours", 0, 4),
    ("4h_1d", "4–24 hours", 4, 24),
    ("1d_3d", "1–3 days", 24, 72),
    ("3d_7d", "3–7 days", 72, 168),
    ("1w_2w", "1–2 weeks", 168, 336),
    ("2w_4w", "2–4 weeks", 336, 672),
    ("gt_4w", "Over 4 weeks", 672, None),
)

Link = tuple[Task, BoardColumn]


# ----------------------------------------------------------------------------- small helpers


def parse_window(window: str) -> int:
    """``"30d"`` -> 30. Raises 422 outside 1..365 days."""
    raw = window.strip().lower()
    if not raw.endswith("d") or not raw[:-1].isdigit():
        raise ValidationFailedError("window must be a number of days such as '30d'.")
    days = int(raw[:-1])
    if not 1 <= days <= WINDOW_MAX_DAYS:
        raise ValidationFailedError(f"window must be between 1d and {WINDOW_MAX_DAYS}d.")
    return days


def _hours(start: datetime, end: datetime) -> float:
    return max(0.0, (ensure_utc(end) - ensure_utc(start)).total_seconds() / 3600)  # type: ignore[operator]


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 1)


def _percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile of a non-empty list (None for an empty one)."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))]


def _ratio(numerator: int, denominator: int) -> RatioOut:
    return RatioOut(numerator=numerator, denominator=denominator,
                    rate=round(numerator / denominator, 4) if denominator else None)


def _day(value: datetime) -> datetime:
    return ensure_utc(value).replace(hour=0, minute=0, second=0, microsecond=0)  # type: ignore[union-attr]


def _week(value: datetime) -> datetime:
    day = _day(value)
    return day - timedelta(days=day.weekday())


def _series(start: datetime, now: datetime, created: list[datetime], completed: list[datetime],
            weekly: bool) -> list[SeriesPointOut]:
    floor = _week if weekly else _day
    step = timedelta(days=7 if weekly else 1)
    buckets: dict[datetime, list[int]] = {}
    cursor, last = floor(start), floor(now)
    while cursor <= last:
        buckets[cursor] = [0, 0]
        cursor += step
    for index, values in ((0, created), (1, completed)):
        for value in values:
            bucket = buckets.get(floor(value))
            if bucket is not None:
                bucket[index] += 1
    return [SeriesPointOut(start=k, created=v[0], completed=v[1]) for k, v in buckets.items()]


def _cycle_buckets(durations: list[float]) -> list[CycleBucketOut]:
    out = []
    for key, label, low, high in CYCLE_BUCKETS:
        count = sum(1 for d in durations if d >= low and (high is None or d < high))
        out.append(CycleBucketOut(key=key, label=label, min_hours=low, max_hours=high, count=count))
    return out


def _agent_names(db: Session, org_id: str, ids: set[str | None]) -> dict[str, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return dict(db.execute(select(Agent.id, Agent.name).where(Agent.organization_id == org_id,
                                                              Agent.id.in_(wanted))).all())


def _cards(db: Session, org_id: str, tasks: list[Task]) -> dict[str, TaskCardOut]:
    unique = list({t.id: t for t in tasks}.values())
    return {card.id: card for card in task_cards(db, org_id, unique)}


# ----------------------------------------------------------------------------- finding ↔ task links


def finding_links(db: Session, org_id: str) -> dict[str, list[Link]]:
    """Every non-archived task linked to each finding (direct field or ``finding`` reference)."""
    direct = select(Task.related_finding_id, Task, BoardColumn).join(
        BoardColumn, BoardColumn.id == Task.column_id
    ).where(Task.organization_id == org_id, Task.archived_at.is_(None), Task.related_finding_id.is_not(None))
    via_ref = select(Ref.ref_id, Task, BoardColumn).select_from(Ref).join(Task, Task.id == Ref.task_id).join(
        BoardColumn, BoardColumn.id == Task.column_id
    ).where(Ref.organization_id == org_id, Ref.ref_type == "finding", Task.organization_id == org_id,
            Task.archived_at.is_(None))
    links: dict[str, dict[str, Link]] = defaultdict(dict)
    for query in (direct, via_ref):
        for finding_id, task, column in db.execute(query).all():
            links[finding_id][task.id] = (task, column)
    return {fid: list(by_task.values()) for fid, by_task in links.items()}


@dataclass
class Remediation:
    state: str
    primary: Link | None
    linked: int


def remediation_of(links: list[Link]) -> Remediation:
    if not links:
        return Remediation("no_task", None, 0)
    open_links = [link for link in links if not link[1].is_done_column]
    if open_links:
        return Remediation("task_open", min(open_links, key=lambda lk: (lk[0].created_at, lk[0].number)), len(links))
    recent = sorted(links, key=lambda lk: lk[0].completed_at or lk[0].updated_at, reverse=True)
    verified = [link for link in recent if link[0].verification_status == "passed"]
    if verified:
        return Remediation("verified", verified[0], len(links))
    return Remediation("task_done_unverified", recent[0], len(links))


def state_reason(rem: Remediation, card: TaskCardOut | None) -> str:
    if rem.primary is None:
        return "No remediation task tracks this finding yet."
    task, column = rem.primary
    key = task_key(task)
    others = f" {rem.linked - 1} other linked task{'s' if rem.linked > 2 else ''} also reference it." \
        if rem.linked > 1 else ""
    if rem.state == "task_open":
        names = [a.name for a in card.assignees if a.role == "assignee"] if card else []
        who = f"assigned to {', '.join(names)}" if names else "not assigned to anyone"
        passed = " Verification has passed; the task still has to reach a done column." \
            if task.verification_status == "passed" else ""
        return f"{key} is in '{column.name}', {who}.{passed}{others}"
    if rem.state == "task_done_unverified":
        return (f"{key} is in '{column.name}' (done) without a passed verification run, so the fix is claimed but "
                f"not proven.{others}")
    return f"{key} is done and a passed verification run proves the fix. The finding can now be resolved.{others}"


def _open_findings(db: Session, org_id: str, *, include_simulated: bool, severity: str | None = None,
                   q: str | None = None) -> list[Any]:
    query = select(SecurityFinding.id, SecurityFinding.severity, SecurityFinding.first_seen_at,
                   SecurityFinding.last_seen_at).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.status.in_(OPEN_FINDING_STATUSES))
    if not include_simulated:
        query = query.where(SecurityFinding.is_simulation.is_(False))
    if severity:
        query = query.where(SecurityFinding.severity == severity)
    if q and q.strip():
        query = query.where(func.lower(SecurityFinding.title).like(f"%{q.strip().lower()}%"))
    return list(db.execute(query).all())


def _completion_rate(db: Session, org_id: str, links: dict[str, list[Link]], include_simulated: bool) -> RatioOut:
    ids = list(links)
    existing: set[str] = set()
    for start in range(0, len(ids), 500):
        query = select(SecurityFinding.id).where(SecurityFinding.organization_id == org_id,
                                                 SecurityFinding.id.in_(ids[start:start + 500]))
        if not include_simulated:
            query = query.where(SecurityFinding.is_simulation.is_(False))
        existing.update(db.scalars(query))
    done = sum(1 for fid in existing if any(column.is_done_column for _, column in links[fid]))
    return _ratio(done, len(existing))


# ----------------------------------------------------------------------------- remediation pipeline


def remediation_pipeline(
    db: Session, org_id: str, *, state: str | None = None, severity: str | None = None, q: str | None = None,
    include_simulated: bool = False, limit: int = 50, offset: int = 0,
) -> RemediationPageOut:
    """Open findings, most severe first (then most recently seen), each with its remediation state."""
    links = finding_links(db, org_id)
    rows = _open_findings(db, org_id, include_simulated=include_simulated, severity=severity, q=q)
    states = {row.id: remediation_of(links.get(row.id, [])) for row in rows}
    counts = Counter(rem.state for rem in states.values())
    matching = [row for row in rows if state is None or states[row.id].state == state]
    matching.sort(key=lambda r: (-SEVERITY_RANK.get(r.severity, -1), -ensure_utc(r.last_seen_at).timestamp(), r.id))
    page_ids = [row.id for row in matching[offset:offset + limit]]
    findings = {f.id: f for f in db.scalars(select(SecurityFinding).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(page_ids or [""])))}
    cards = _cards(db, org_id, [states[fid].primary[0] for fid in page_ids if states[fid].primary])
    agents = _agent_names(db, org_id, {findings[fid].agent_id for fid in page_ids})
    items = []
    for fid in page_ids:
        finding, rem = findings[fid], states[fid]
        card = cards.get(rem.primary[0].id) if rem.primary else None
        items.append(RemediationFindingOut(
            finding_id=finding.id, title=finding.title, category=finding.category, severity=finding.severity,
            status=finding.status, confidence=finding.confidence, occurrence_count=finding.occurrence_count,
            first_seen_at=finding.first_seen_at, last_seen_at=finding.last_seen_at,
            is_simulation=finding.is_simulation, agent_id=finding.agent_id,
            agent_name=agents.get(finding.agent_id or ""), session_id=finding.session_id,
            incident_id=finding.incident_id, state=rem.state, state_reason=state_reason(rem, card),  # type: ignore[arg-type]
            linked_task_count=rem.linked, task=card,
        ))
    return RemediationPageOut(items=items, total=len(matching), limit=limit, offset=offset,
                              counts=RemediationCountsOut(**{s: counts.get(s, 0) for s in STATES}))


# ----------------------------------------------------------------------------- engineering analytics


def _task_base(org_id: str, board_id: str | None, *columns: Any) -> Any:
    query = select(*columns).select_from(Task).join(BoardColumn, BoardColumn.id == Task.column_id).where(
        Task.organization_id == org_id, Task.archived_at.is_(None))
    return query.where(Task.board_id == board_id) if board_id else query


def _outstanding_critical(
    db: Session, org_id: str, board_id: str | None, open_rows: list[Any], states: dict[str, Remediation],
    links: dict[str, list[Link]],
) -> OutstandingCriticalOut:
    critical_ids = [r.id for r in sorted(open_rows, key=lambda r: ensure_utc(r.first_seen_at))
                    if r.severity == "critical" and states[r.id].state in ("no_task", "task_open")]
    tracked = {task.id for fid in critical_ids for task, column in links.get(fid, []) if not column.is_done_column}
    open_critical = _task_base(org_id, board_id, Task.id).where(
        BoardColumn.is_done_column.is_(False), Task.severity == "critical")
    task_ids = list(db.scalars(open_critical.order_by(Task.created_at, Task.number)))
    extra_ids = [tid for tid in task_ids if tid not in tracked]

    shown_findings = critical_ids[:CRITICAL_LIST_LIMIT]
    shown_tasks = extra_ids[:max(0, CRITICAL_LIST_LIMIT - len(shown_findings))]
    findings = {f.id: f for f in db.scalars(select(SecurityFinding).where(
        SecurityFinding.organization_id == org_id, SecurityFinding.id.in_(shown_findings or [""])))}
    tasks = {t.id: t for t in db.scalars(select(Task).where(Task.organization_id == org_id,
                                                            Task.id.in_(shown_tasks or [""])))}
    primaries = [states[fid].primary[0] for fid in shown_findings if states[fid].primary]
    cards = _cards(db, org_id, [*primaries, *tasks.values()])
    agents = _agent_names(db, org_id, {f.agent_id for f in findings.values()} | {t.related_agent_id for t in tasks.values()})
    items = []
    for fid in shown_findings:
        finding, rem = findings[fid], states[fid]
        items.append(CriticalItemOut(
            kind="finding", id=finding.id, title=finding.title, severity=finding.severity, since=finding.first_seen_at,
            state=rem.state, is_simulation=finding.is_simulation, agent_id=finding.agent_id,  # type: ignore[arg-type]
            agent_name=agents.get(finding.agent_id or ""), task=cards.get(rem.primary[0].id) if rem.primary else None,
        ))
    for tid in shown_tasks:
        task = tasks[tid]
        items.append(CriticalItemOut(
            kind="task", id=task.id, title=task.title, severity="critical", since=task.created_at, state="task_open",
            is_simulation=False, agent_id=task.related_agent_id, agent_name=agents.get(task.related_agent_id or ""),
            task=cards.get(task.id),
        ))
    return OutstandingCriticalOut(total=len(critical_ids) + len(extra_ids), findings=len(critical_ids),
                                  tasks=len(task_ids), items=items)


def engineering_analytics(
    db: Session, org_id: str, *, board_id: str | None = None, window_days: int = 30, include_simulated: bool = False,
    now: datetime | None = None,
) -> EngineeringAnalyticsOut:
    if board_id:
        get_scoped(db, Board, board_id, org_id, label="Board")
    moment = now or utcnow()
    start = moment - timedelta(days=window_days)

    open_rows = db.execute(_task_base(org_id, board_id, Task.priority, Task.task_type, BoardColumn.status_key,
                                      Task.due_date).where(BoardColumn.is_done_column.is_(False))).all()
    by_priority, by_type = Counter(r.priority for r in open_rows), Counter(r.task_type for r in open_rows)
    by_status = Counter(r.status_key for r in open_rows)
    overdue = sum(1 for r in open_rows if r.due_date is not None and ensure_utc(r.due_date) < moment)  # type: ignore[operator]
    known_types = [t for t in TASK_TYPES if by_type.get(t)] + sorted(t for t in by_type if t not in TASK_TYPES)

    completed = db.execute(_task_base(org_id, board_id, Task.created_at, Task.completed_at).where(
        BoardColumn.is_done_column.is_(True), Task.completed_at.is_not(None), Task.completed_at >= start)).all()
    durations = [_hours(r.created_at, r.completed_at) for r in completed]
    completed_at = [ensure_utc(r.completed_at) for r in completed]
    created_at = [ensure_utc(c) for c in db.scalars(_task_base(org_id, board_id, Task.created_at).where(
        Task.created_at >= start))]

    reopen_sum, reopened_tasks = db.execute(_task_base(
        org_id, board_id, func.coalesce(func.sum(Task.reopened_count), 0),
        func.coalesce(func.sum(case((Task.reopened_count > 0, 1), else_=0)), 0))).one()

    runs_query = select(VerificationRun.status, func.count(VerificationRun.id)).join(
        Task, Task.id == VerificationRun.task_id).where(
        VerificationRun.organization_id == org_id, Task.organization_id == org_id, Task.archived_at.is_(None),
        VerificationRun.created_at >= start)
    if board_id:
        runs_query = runs_query.where(Task.board_id == board_id)
    runs = dict(db.execute(runs_query.group_by(VerificationRun.status)).all())

    links = finding_links(db, org_id)
    findings = _open_findings(db, org_id, include_simulated=include_simulated)
    states = {row.id: remediation_of(links.get(row.id, [])) for row in findings}
    finding_counts = Counter(rem.state for rem in states.values())

    return EngineeringAnalyticsOut(
        generated_at=moment, window_days=window_days, window_start=start, board_id=board_id,
        include_simulated=include_simulated, open_tasks=len(open_rows), overdue=overdue,
        by_priority=[CountOut(key=p, count=by_priority.get(p, 0)) for p in PRIORITIES],
        by_type=[CountOut(key=t, count=by_type[t]) for t in known_types],
        by_status_key=[CountOut(key=s, count=by_status.get(s, 0)) for s in STATUS_KEYS if s != "done"],
        completed_in_window=len(durations),
        avg_resolution_hours=_round(statistics.fmean(durations)) if durations else None,
        median_resolution_hours=_round(statistics.median(durations)) if durations else None,
        p90_resolution_hours=_round(_percentile(durations, 0.9)),
        findings_awaiting_remediation=FindingBacklogOut(
            total=finding_counts["no_task"] + finding_counts["task_open"], no_task=finding_counts["no_task"],
            task_open=finding_counts["task_open"], open_findings=len(findings)),
        remediation_completion_rate=_completion_rate(db, org_id, links, include_simulated),
        reopened_issues=ReopenedOut(reopen_events=int(reopen_sum or 0), tasks_reopened=int(reopened_tasks or 0)),
        failed_verification_runs=_ratio(int(runs.get("failed", 0)), int(sum(runs.values()))),
        outstanding_critical=_outstanding_critical(db, org_id, board_id, findings, states, links),
        series_granularity="day" if window_days <= DAILY_SERIES_MAX_DAYS else "week",
        created_vs_completed=_series(start, moment, created_at, completed_at, weekly=window_days > DAILY_SERIES_MAX_DAYS),
        throughput=_series(start, moment, created_at, completed_at, weekly=True),
        cycle_time=_cycle_buckets(durations),
    )
