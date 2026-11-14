"""Security regression suites: groups of Simulation Lab runs that share a ``suite_run_id``.

There is no suite table — a suite is the set of runs started together. Comparing two suites shows
how the same synthetic attacks were handled before and after a change (agent version, policies,
trust rules): checks that newly fail (regressions), checks that newly pass, decision changes per
step, new finding categories and the policy changes between the two snapshots.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models import AgentSession, SecurityFinding, SimulationRun


def list_suites(db: Session, org_id: str, *, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
    grouped = (
        select(
            SimulationRun.suite_run_id.label("suite_run_id"),
            func.count(SimulationRun.id).label("run_count"),
            func.sum(case((SimulationRun.passed.is_(True), 1), else_=0)).label("passed_count"),
            func.min(SimulationRun.started_at).label("started_at"),
            func.max(SimulationRun.completed_at).label("completed_at"),
            func.max(SimulationRun.agent_id).label("agent_id"),
            func.max(SimulationRun.agent_version).label("agent_version"),
        )
        .where(SimulationRun.organization_id == org_id, SimulationRun.suite_run_id.is_not(None))
        .group_by(SimulationRun.suite_run_id)
    )
    total = db.scalar(select(func.count()).select_from(grouped.subquery())) or 0
    rows = db.execute(
        grouped.order_by(func.min(SimulationRun.started_at).desc()).limit(limit).offset(offset)
    ).all()
    return [_summary_row(r) for r in rows], int(total)


def _summary_row(r: Any) -> dict[str, Any]:
    passed = int(r.passed_count or 0)
    return {
        "suite_run_id": r.suite_run_id,
        "run_count": int(r.run_count),
        "passed_count": passed,
        "failed_count": int(r.run_count) - passed,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "agent_id": r.agent_id,
        "agent_version": r.agent_version,
    }


def suite_runs(db: Session, org_id: str, suite_run_id: str) -> list[SimulationRun]:
    runs = list(
        db.scalars(
            select(SimulationRun)
            .where(
                SimulationRun.organization_id == org_id,
                SimulationRun.suite_run_id == suite_run_id,
            )
            .order_by(SimulationRun.started_at, SimulationRun.id)
        )
    )
    if not runs:
        raise NotFoundError(f"Simulation suite '{suite_run_id}' not found")
    return runs


def suite_summary(runs: list[SimulationRun]) -> dict[str, Any]:
    passed = sum(1 for r in runs if r.passed)
    return {
        "suite_run_id": runs[0].suite_run_id,
        "run_count": len(runs),
        "passed_count": passed,
        "failed_count": len(runs) - passed,
        "started_at": min(r.started_at for r in runs),
        "completed_at": max((r.completed_at for r in runs if r.completed_at), default=None),
        "agent_id": runs[0].agent_id,
        "agent_version": runs[0].agent_version,
    }


def _checks(run: SimulationRun) -> dict[str, dict[str, Any]]:
    return {r["step"]: r for r in (run.results or []) if r.get("kind") == "expectation"}


def _decisions(run: SimulationRun) -> dict[str, str | None]:
    return {r["step"]: r.get("decision") for r in (run.results or []) if r.get("kind") == "observation"}


def _finding_categories(db: Session, org_id: str, run: SimulationRun | None) -> set[str]:
    """Finding categories raised in every session of a run (the main session and any delegated child)."""
    if run is None:
        return set()
    sessions = list(
        db.scalars(
            select(AgentSession.id).where(
                AgentSession.organization_id == org_id, AgentSession.simulation_run_id == run.id
            )
        )
    )
    if not sessions:
        return set()
    return set(
        db.scalars(
            select(SecurityFinding.category).where(
                SecurityFinding.organization_id == org_id, SecurityFinding.session_id.in_(sessions)
            )
        )
    )


def _scenario_diff(
    db: Session, org_id: str, sid: str, base: SimulationRun | None, head: SimulationRun | None
) -> dict[str, Any]:
    if base is None or head is None:
        status = "added" if base is None else "removed"
    elif base.passed and not head.passed:
        status = "regressed"
    elif not base.passed and head.passed:
        status = "fixed"
    else:
        status = "unchanged_pass" if head.passed else "unchanged_fail"
    check_changes: list[dict[str, Any]] = []
    decision_changes: list[dict[str, Any]] = []
    if base is not None and head is not None:
        bc, hc = _checks(base), _checks(head)
        for key in [k for k in hc if k in bc]:
            if bool(bc[key]["passed"]) != bool(hc[key]["passed"]):
                check_changes.append(
                    {
                        "check": key,
                        "expectation": hc[key]["expectation"],
                        "base_passed": bc[key]["passed"],
                        "head_passed": hc[key]["passed"],
                        "base_actual": bc[key]["actual"],
                        "head_actual": hc[key]["actual"],
                    }
                )
        bd, hd = _decisions(base), _decisions(head)
        for step in [s for s in hd if s in bd]:
            if bd[step] != hd[step]:
                decision_changes.append({"step": step, "base": bd[step], "head": hd[step]})
    base_cats, head_cats = _finding_categories(db, org_id, base), _finding_categories(db, org_id, head)
    name = (head or base).scenario_name if (head or base) else sid
    return {
        "scenario_id": sid,
        "scenario_name": name,
        "status": status,
        "base_run_id": base.id if base else None,
        "head_run_id": head.id if head else None,
        "base_passed": base.passed if base else None,
        "head_passed": head.passed if head else None,
        "check_changes": check_changes,
        "decision_changes": decision_changes,
        "new_finding_categories": sorted(head_cats - base_cats),
        "resolved_finding_categories": sorted(base_cats - head_cats),
    }


def _policy_changes(base: list[dict[str, Any]], head: list[dict[str, Any]]) -> list[dict[str, Any]]:
    b = {p["policy_id"]: p for p in base}
    h = {p["policy_id"]: p for p in head}
    out: list[dict[str, Any]] = []
    for pid in sorted(set(b) | set(h)):
        old, new = b.get(pid), h.get(pid)
        if old is None or new is None:
            ref = new or old
            assert ref is not None
            out.append(
                {"policy_id": pid, "name": ref.get("name"), "change": "added" if old is None else "removed"}
            )
            continue
        changes = [
            f"{k}: {old.get(k)} → {new.get(k)}"
            for k in ("enabled", "mode", "version", "outcome")
            if old.get(k) != new.get(k)
        ]
        if changes:
            out.append({"policy_id": pid, "name": new.get("name"), "change": "; ".join(changes)})
    return out


def compare_suites(db: Session, org_id: str, base_id: str, head_id: str) -> dict[str, Any]:
    """Regression diff between two suite runs (``base`` = before, ``head`` = after)."""
    base_runs, head_runs = suite_runs(db, org_id, base_id), suite_runs(db, org_id, head_id)
    b = {r.scenario_id: r for r in base_runs}
    h = {r.scenario_id: r for r in head_runs}
    scenarios = [_scenario_diff(db, org_id, sid, b.get(sid), h.get(sid)) for sid in sorted(set(b) | set(h))]
    counts: dict[str, int] = {}
    for s in scenarios:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    return {
        "base": suite_summary(base_runs),
        "head": suite_summary(head_runs),
        "scenarios": scenarios,
        "counts": counts,
        "regressions": counts.get("regressed", 0),
        "policy_changes": _policy_changes(
            base_runs[0].policy_snapshot or [], head_runs[0].policy_snapshot or []
        ),
        "note": "Both suites ran the same synthetic scenarios through the real pipeline; differences reflect "
        "configuration or agent changes between the runs, not proof of causation.",
    }
