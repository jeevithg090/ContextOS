"""Task evidence: attachments, code links, fix attempts and verification runs.

Honesty rules enforced here:
- ``claimed_complete`` on a fix attempt is recorded as a claim. It never verifies, resolves or moves the
  task. A fix attempt becomes ``verified`` only when a passed verification run references it.
- A task's ``verification_status`` changes only through verification runs. ``simulation`` runs take their
  status from the recorded Simulation Lab run, never from the client. A failed run after a pass
  regresses the task to ``failed`` (recorded as ``verification_regressed``). An ``error`` run proves
  nothing either way and leaves the status unchanged.
- Attachments are redacted before storage and capped at 100 KB.
"""

from __future__ import annotations

import importlib
import re
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import (
    AppError,
    ConflictError,
    NotFoundError,
    PayloadTooLargeError,
    ValidationFailedError,
)
from app.core.ids import new_id
from app.core.timeutil import isoformat, utcnow
from app.models import FixAttempt, GeneratedPrompt, SimulationRun, Task, TaskAttachment, VerificationRun
from app.schemas.workspace_evidence import ATTACHMENT_MAX_BYTES
from app.services.scoping import get_scoped
from app.services.workspace_tasks import fire_automation
from app.services.workspace_tasks_common import (
    Actor,
    as_actor,
    audit_task,
    clean_json,
    clean_optional,
    clean_text,
    get_task,
    record_activity,
)

LINK_KEYS = {"branch": "branches", "commit": "commits", "pull_request": "pull_requests", "deployment": "deployments"}
PR_STATES = ("open", "draft", "merged", "closed")
TERMINAL_FIX = ("claimed_complete", "verified", "failed", "abandoned")
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
MAX_LINKS_PER_KIND = 50


class SimulationUnavailableError(AppError):
    status_code = 503
    code = "simulation_unavailable"


def _http_url(url: str | None, field: str = "url") -> str | None:
    if url is None or not url.strip():
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValidationFailedError(f"{field} must be an http(s) URL.")
    return clean_text(url.strip(), 2048)


def _require_active(task: Task) -> None:
    if task.archived_at is not None:
        raise ConflictError("This task is archived. Restore it before adding evidence.")


# ----------------------------------------------------------------------------- attachments


def add_attachment(db: Session, who: Any, task: Task, *, name: str, kind: str, url: str | None,
                   content: str | None) -> TaskAttachment:
    actor = as_actor(who)
    _require_active(task)
    if content is not None and len(content.encode("utf-8")) > ATTACHMENT_MAX_BYTES:
        raise PayloadTooLargeError(f"Attachments are limited to {ATTACHMENT_MAX_BYTES // 1024} KB of text.")
    clean_url = _http_url(url)
    text = clean_text(content, ATTACHMENT_MAX_BYTES) if content else None
    if kind == "link" and not clean_url:
        raise ValidationFailedError("A link attachment needs a URL.")
    if kind != "link" and not (text or clean_url):
        raise ValidationFailedError("An attachment needs text content or a URL.")
    row = TaskAttachment(
        id=new_id("task_attachment"), organization_id=task.organization_id, task_id=task.id,
        name=clean_text(name, 400) or "attachment", kind=kind, url=clean_url, content=text,
        size=len(text.encode("utf-8")) if text else 0, created_by=actor.user_id, created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    record_activity(db, task, actor.user_id, "attachment_added", to_value=row.name,
                    details={"attachment_id": row.id, "kind": kind, "size": row.size})
    audit_task(db, actor, task, "attachment_added", {"attachment_id": row.id, "kind": kind, "size": row.size})
    return row


def delete_attachment(db: Session, who: Any, attachment_id: str) -> None:
    actor = as_actor(who)
    row = get_scoped(db, TaskAttachment, attachment_id, actor.org_id, label="Attachment")
    task = get_task(db, actor.org_id, row.task_id)
    db.delete(row)
    record_activity(db, task, actor.user_id, "attachment_removed", from_value=row.name,
                    details={"attachment_id": row.id})
    db.flush()
    audit_task(db, actor, task, "attachment_removed", {"attachment_id": row.id})


# ----------------------------------------------------------------------------- links


def link_items(task: Task) -> dict[str, list[dict[str, Any]]]:
    """Links grouped by kind, each with its index (used to address it for deletion)."""
    links = task.links or {}
    return {kind: [{**item, "index": i, "kind": kind} for i, item in enumerate(links.get(key) or [])]
            for kind, key in LINK_KEYS.items()}


def _link_record(kind: str, url: str | None, title: str | None, ref: str | None, state: str | None) -> dict[str, Any]:
    clean_url = _http_url(url)
    clean_ref = clean_optional(ref, 300)
    if kind == "pull_request" and not clean_url:
        raise ValidationFailedError("A pull request link needs its URL.")
    if kind == "branch" and not clean_ref:
        raise ValidationFailedError("A branch link needs the branch name in 'ref'.")
    if kind == "commit" and not (clean_ref and _SHA.match(clean_ref)):
        raise ValidationFailedError("A commit link needs the commit SHA (7-64 hex characters) in 'ref'.")
    if kind == "deployment" and not (clean_url or clean_ref):
        raise ValidationFailedError("A deployment link needs a URL or an environment name in 'ref'.")
    if state is not None and kind != "pull_request":
        raise ValidationFailedError("'state' applies to pull requests only.")
    if state is not None and state not in PR_STATES:
        raise ValidationFailedError(f"Pull request state must be one of: {', '.join(PR_STATES)}.")
    return {"url": clean_url, "title": clean_optional(title, 400), "ref": clean_ref,
            "state": state or ("open" if kind == "pull_request" else None)}


def _append_link(task: Task, kind: str, record: dict[str, Any], user_id: str | None) -> bool:
    key = LINK_KEYS[kind]
    links = {k: list(v) for k, v in (task.links or {}).items()}
    items = links.setdefault(key, [])
    if any((i.get("url"), i.get("ref")) == (record["url"], record["ref"]) for i in items):
        return False
    if len(items) >= MAX_LINKS_PER_KIND:
        raise ValidationFailedError(f"A task can have at most {MAX_LINKS_PER_KIND} {kind.replace('_', ' ')} links.")
    items.append({**record, "added_at": isoformat(utcnow()), "added_by": user_id})
    task.links = links  # new object so the JSON column change is detected
    return True


def add_link(db: Session, who: Any, task: Task, *, kind: str, url: str | None = None, title: str | None = None,
             ref: str | None = None, state: str | None = None) -> dict[str, list[dict[str, Any]]]:
    actor = as_actor(who)
    _require_active(task)
    record = _link_record(kind, url, title, ref, state)
    if not _append_link(task, kind, record, actor.user_id):
        raise ConflictError(f"This {kind.replace('_', ' ')} is already linked to the task.")
    record_activity(db, task, actor.user_id, "linked", to_value=record["url"] or record["ref"],
                    details={"kind": kind, "state": record["state"]})
    db.flush()
    audit_task(db, actor, task, "linked", {"kind": kind})
    if kind == "pull_request":
        fire_automation(db, task, "pr_linked", {"url": record["url"]})
    return link_items(task)


def remove_link(db: Session, who: Any, task: Task, kind: str, index: int) -> dict[str, list[dict[str, Any]]]:
    actor = as_actor(who)
    if kind not in LINK_KEYS:
        raise NotFoundError(f"Unknown link kind '{kind}'")
    links = {k: list(v) for k, v in (task.links or {}).items()}
    items = links.get(LINK_KEYS[kind]) or []
    if index < 0 or index >= len(items):
        raise NotFoundError(f"No {kind.replace('_', ' ')} link at index {index}")
    removed = items.pop(index)
    links[LINK_KEYS[kind]] = items
    task.links = links
    record_activity(db, task, actor.user_id, "unlinked", from_value=removed.get("url") or removed.get("ref"),
                    details={"kind": kind})
    db.flush()
    audit_task(db, actor, task, "unlinked", {"kind": kind})
    return link_items(task)


# ----------------------------------------------------------------------------- fix attempts


def _fix_status_effects(attempt: FixAttempt, status: str) -> None:
    now = utcnow()
    if status == "in_progress" and attempt.started_at is None:
        attempt.started_at = now
    if status in TERMINAL_FIX:
        attempt.completed_at = attempt.completed_at or now
        attempt.started_at = attempt.started_at or now
    else:
        attempt.completed_at = None


def _no_direct_verify(status: str | None) -> None:
    if status == "verified":
        raise ConflictError(
            "A fix attempt becomes verified only through a passed verification run that references it. "
            "Record a verification run with this fix_attempt_id instead.",
            details={"reason": "verification_required"},
        )


def _claim_note(status: str) -> dict[str, Any]:
    if status != "claimed_complete":
        return {}
    return {"note": "Claim only: the task is not verified or resolved until a verification run passes."}


def _check_prompt(db: Session, task: Task, prompt_id: str | None) -> None:
    if prompt_id:
        prompt = get_scoped(db, GeneratedPrompt, prompt_id, task.organization_id, label="Generated prompt")
        if prompt.task_id not in (None, task.id):
            raise ValidationFailedError("That generated prompt belongs to a different task.")


def _mirror_pr(db: Session, task: Task, pr_url: str | None, user_id: str | None) -> bool:
    if not pr_url:
        return False
    return _append_link(task, "pull_request", _link_record("pull_request", pr_url, None, None, None), user_id)


def create_fix_attempt(db: Session, who: Any, task: Task, data: dict[str, Any]) -> FixAttempt:
    actor = as_actor(who)
    _require_active(task)
    status = data.get("status") or "planned"
    _no_direct_verify(status)
    _check_prompt(db, task, data.get("generated_prompt_id"))
    attempt = FixAttempt(
        id=new_id("fix_attempt"), organization_id=task.organization_id, task_id=task.id,
        generated_prompt_id=data.get("generated_prompt_id"), agent_tool=data.get("agent_tool") or "claude_code",
        status=status, branch=clean_optional(data.get("branch"), 300), commit_sha=clean_optional(data.get("commit_sha"), 64),
        pr_url=_http_url(data.get("pr_url"), "pr_url"), notes=clean_optional(data.get("notes"), 20_000),
        created_by=actor.user_id,
    )
    _fix_status_effects(attempt, status)
    db.add(attempt)
    db.flush()
    record_activity(db, task, actor.user_id, "fix_attempt_created", to_value=status,
                    details={"fix_attempt_id": attempt.id, "agent_tool": attempt.agent_tool, **_claim_note(status)})
    pr_added = _mirror_pr(db, task, attempt.pr_url, actor.user_id)
    db.flush()
    audit_task(db, actor, task, "fix_attempt_created", {"fix_attempt_id": attempt.id, "status": status})
    if status == "in_progress":
        fire_automation(db, task, "fix_attempt_started", {"fix_attempt_id": attempt.id})
    if pr_added:
        fire_automation(db, task, "pr_linked", {"fix_attempt_id": attempt.id})
    return attempt


def update_fix_attempt(db: Session, who: Any, attempt_id: str, changes: dict[str, Any]) -> FixAttempt:
    actor = as_actor(who)
    attempt = get_scoped(db, FixAttempt, attempt_id, actor.org_id, label="Fix attempt")
    task = get_task(db, actor.org_id, attempt.task_id)
    _require_active(task)
    status = changes.get("status")
    if status is not None and status != attempt.status:
        _no_direct_verify(status)
    changed: list[str] = []
    previous = attempt.status
    if status is not None and status != attempt.status:
        attempt.status = status
        _fix_status_effects(attempt, status)
        changed.append("status")
    cleaners = {"branch": lambda v: clean_optional(v, 300), "commit_sha": lambda v: clean_optional(v, 64),
                "pr_url": lambda v: _http_url(v, "pr_url"), "notes": lambda v: clean_optional(v, 20_000)}
    for field, cleaner in cleaners.items():
        if field in changes:
            value = cleaner(changes[field])
            if value != getattr(attempt, field):
                setattr(attempt, field, value)
                changed.append(field)
    if not changed:
        return attempt
    record_activity(db, task, actor.user_id, "fix_attempt_updated", from_value=previous, to_value=attempt.status,
                    details={"fix_attempt_id": attempt.id, "fields": changed, **_claim_note(attempt.status)})
    pr_added = "pr_url" in changed and _mirror_pr(db, task, attempt.pr_url, actor.user_id)
    db.flush()
    audit_task(db, actor, task, "fix_attempt_updated", {"fix_attempt_id": attempt.id, "fields": changed,
                                                        "status": attempt.status})
    if "status" in changed and attempt.status == "in_progress":
        fire_automation(db, task, "fix_attempt_started", {"fix_attempt_id": attempt.id})
    if pr_added:
        fire_automation(db, task, "pr_linked", {"fix_attempt_id": attempt.id})
    return attempt


# ----------------------------------------------------------------------------- verification


def _apply_result(db: Session, actor: Actor, task: Task, run: VerificationRun) -> str | None:
    """Update the task (and linked fix attempt) from a run. Returns the automation trigger to fire, if any."""
    before = task.verification_status
    trigger = None
    if run.status == "passed":
        task.verification_status, task.verified_at, trigger = "passed", utcnow(), "verification_passed"
    elif run.status == "failed":
        task.verification_status, task.verified_at, trigger = "failed", None, "verification_failed"
    elif run.status == "pending" and before != "passed":
        task.verification_status = "pending"
    record_activity(db, task, actor.user_id, "verification", from_value=before, to_value=task.verification_status,
                    details={"verification_run_id": run.id, "kind": run.kind, "run_status": run.status})
    if before == "passed" and run.status == "failed":
        record_activity(db, task, actor.user_id, "verification_regressed", from_value="passed", to_value="failed",
                        details={"verification_run_id": run.id, "kind": run.kind,
                                 "note": "A verification run failed after an earlier pass."})
    if run.fix_attempt_id:
        attempt = db.get(FixAttempt, run.fix_attempt_id)
        if attempt is not None and run.status in ("passed", "failed"):
            new_status = "verified" if run.status == "passed" else "failed"
            if attempt.status != new_status:
                attempt.status = new_status
                _fix_status_effects(attempt, new_status)
    return trigger


def _simulation_status(run: Any) -> str:
    passed = _attr(run, "passed")
    status = _attr(run, "status")
    if passed is True:
        return "passed"
    if passed is False:
        return "failed"
    return "pending" if status in (None, "running") else "error"


def _attr(run: Any, name: str) -> Any:
    return run.get(name) if isinstance(run, dict) else getattr(run, name, None)


def record_verification(db: Session, who: Any, task: Task, data: dict[str, Any]) -> VerificationRun:
    actor = as_actor(who)
    _require_active(task)
    kind, status = data["kind"], data.get("status")
    sim_run: SimulationRun | None = None
    if kind == "simulation":
        if not data.get("simulation_run_id"):
            raise ValidationFailedError("A simulation verification needs simulation_run_id (or use verify-with-simulation).")
        if status is not None:
            raise ValidationFailedError("The status of a simulation verification is taken from the recorded run; omit it.")
        sim_run = get_scoped(db, SimulationRun, data["simulation_run_id"], task.organization_id, label="Simulation run")
        status = _simulation_status(sim_run)
    else:
        if data.get("simulation_run_id"):
            raise ValidationFailedError("simulation_run_id applies to simulation verifications only.")
        if status is None:
            raise ValidationFailedError(f"A {kind.replace('_', ' ')} verification needs a status.")
    attempt_id = data.get("fix_attempt_id")
    if attempt_id:
        attempt = get_scoped(db, FixAttempt, attempt_id, task.organization_id, label="Fix attempt")
        if attempt.task_id != task.id:
            raise ValidationFailedError("That fix attempt belongs to a different task.")
    evidence = clean_json(dict(data.get("evidence") or {}))
    if sim_run is not None:
        evidence = {**evidence, "scenario_id": sim_run.scenario_id, "scenario_name": sim_run.scenario_name,
                    "run_status": sim_run.status, "results_total": len(sim_run.results or []),
                    "results_passed": sum(1 for r in sim_run.results or [] if isinstance(r, dict) and r.get("passed"))}
    run = VerificationRun(
        id=new_id("verification_run"), organization_id=task.organization_id, task_id=task.id,
        fix_attempt_id=attempt_id, kind=kind, status=status,
        summary=clean_text(data.get("summary") or (sim_run.summary if sim_run else ""), 20_000),
        command=clean_optional(data.get("command"), 4000),
        evidence_url=_http_url(data.get("evidence_url"), "evidence_url"),
        evidence=evidence, simulation_run_id=sim_run.id if sim_run else None,
        created_by=actor.user_id, created_at=utcnow(),
    )
    db.add(run)
    db.flush()
    trigger = _apply_result(db, actor, task, run)
    db.flush()
    audit_task(db, actor, task, "verification_recorded",
               {"verification_run_id": run.id, "kind": kind, "status": status,
                "verification_status": task.verification_status})
    if trigger:
        fire_automation(db, task, trigger, {"verification_run_id": run.id})
    return run


def verify_with_simulation(db: Session, who: Any, task: Task, scenario_id: str,
                           fix_attempt_id: str | None = None) -> VerificationRun:
    """Run a Simulation Lab scenario through the real pipeline and record it as verification evidence."""
    actor = as_actor(who)
    _require_active(task)
    try:
        simulations = importlib.import_module("app.services.simulations")
    except ModuleNotFoundError as exc:
        if exc.name != "app.services.simulations":
            raise
        raise SimulationUnavailableError("The Simulation Lab is not available in this build.") from exc
    run_scenario = getattr(simulations, "run_scenario", None)
    if run_scenario is None:
        raise SimulationUnavailableError("The Simulation Lab does not provide run_scenario().")
    result = run_scenario(db, task.organization_id, scenario_id)
    run_id = _attr(result, "id")
    sim_run = db.scalar(select(SimulationRun).where(
        SimulationRun.organization_id == task.organization_id, SimulationRun.id == run_id
    )) if run_id else None
    if sim_run is None:
        raise SimulationUnavailableError("The simulation finished without a recorded run, so it cannot be used as evidence.")
    if sim_run.triggered_by_user_id is None and actor.user_id:
        sim_run.triggered_by_user_id = actor.user_id
    db.flush()
    return record_verification(db, actor, task, {
        "kind": "simulation", "simulation_run_id": sim_run.id, "fix_attempt_id": fix_attempt_id,
        "summary": sim_run.summary or f"Simulation scenario '{sim_run.scenario_name}' {sim_run.status}.",
        "evidence_url": None,
    })


def verification_rows(db: Session, task: Task) -> list[VerificationRun]:
    return list(db.scalars(select(VerificationRun).where(
        VerificationRun.organization_id == task.organization_id, VerificationRun.task_id == task.id
    ).order_by(VerificationRun.created_at.desc())))


def fix_attempt_rows(db: Session, task: Task) -> list[FixAttempt]:
    return list(db.scalars(select(FixAttempt).where(
        FixAttempt.organization_id == task.organization_id, FixAttempt.task_id == task.id
    ).order_by(FixAttempt.created_at.desc())))
