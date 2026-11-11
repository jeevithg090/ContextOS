"""Context packs for Engineering Workspace tasks: build, persist, toggle items, delete.

A pack is built by :func:`app.workspace.context_pack.build_context_pack` from the task's related files
(plus any extra paths the user asked for), the linked ContextOS records and, when
``settings.workspace_repo_root`` (``CONTEXTOS_WORKSPACE_REPO_ROOT``, server-side configuration only — never
taken from a request) points at a readable repository, project documents, related tests and Git history. Without a repository root the pack holds only database records, the task's paths marked as
unverified, and a note saying repository files could not be verified.

Toggling: an included item can be excluded and re-included; an item left out because of the token
budget can be included manually (files are re-read with the same safety checks, records are re-derived
from the database). Sensitive, rejected, missing or unverified items can never be included.

Export: :func:`export_pack` returns the pack as a JSON document (redacted again, audited as
``context_pack.exported``).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import isoformat, utcnow
from app.engines.redaction import redact_value
from app.models import ContextPack, Task
from app.schemas.workspace_ai import (
    ContextPackItemOut,
    ContextPackOut,
    ContextPackSummaryOut,
    ModesOut,
    PackCountsOut,
)
from app.services.audit import append_audit
from app.services.scoping import get_scoped
from app.services.workspace_ai_input import TaskBundle, collect, pack_records
from app.services.workspace_tasks_common import Actor, audit_task, clean_text, record_activity, task_key
from app.workspace import repo_files as rf
from app.workspace.context_pack import ITEM_OVERHEAD_TOKENS, PROFILES, build_context_pack, get_profile
from app.workspace.fix_input import SECURITY_TASK_TYPES
from app.workspace.modes import PromptMode
from app.workspace.text import clean, estimate_tokens, truncate_lines

NO_ROOT_TITLE = "No repository root configured"
NO_ROOT_REASON = ("No repository root configured — repository files could not be verified. Set "
                  "CONTEXTOS_WORKSPACE_REPO_ROOT on the server to the repository path to include project documents, "
                  "source files and related tests.")
EXPORTED_BY = "ContextOS context-pack builder (deterministic; no external AI provider involved)"
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
FILE_KINDS = ("doc", "source_file", "test_file")
RECORD_KINDS = ("record", "policy")
EXTRA_PATH_REASON = "Requested when this context pack was built."
MANUAL_REASON = "Included manually although it exceeds the profile's token budget."


def default_profile(task: Task, mode: str) -> str:
    """Profile used when a prompt is generated without an explicit context pack."""
    if mode == PromptMode.SECURITY_HARDEN or task.task_type in SECURITY_TASK_TYPES or task.related_finding_id:
        return "security_critical"
    if mode == PromptMode.FULL_AUTONOMOUS_REMEDIATION:
        return "deep"
    return "standard"


def suggested_profiles(task: Task) -> dict[str, str]:
    """``{mode: profile}`` — :func:`default_profile` for every prompt mode (the UI shows it as "suggested")."""
    return {mode.value: default_profile(task, mode.value) for mode in PromptMode}


def with_suggestions(catalogue: ModesOut, task: Task, mode: str) -> ModesOut:
    """``catalogue`` plus the profile suggested for ``task`` in ``mode`` and in every mode."""
    return catalogue.model_copy(update={"task_id": task.id, "mode": mode, "suggested_profile": default_profile(task, mode),
                                        "suggested_profiles": suggested_profiles(task)})


def _workspace_root() -> str | None:
    """The configured repository root (server settings only)."""
    root = get_settings().workspace_repo_root
    return root.strip() if isinstance(root, str) and root.strip() else None


def _normal(path: str) -> str:
    text = path.strip().strip("\"'`").replace("\\", "/")
    return os.path.normpath(text).replace("\\", "/") if text else ""


def build_items(task: Task, bundle: TaskBundle, profile: str, extra_paths: list[str] | None = None,
                ) -> tuple[list[dict[str, Any]], int]:
    """Build pack items for ``task``. Returns ``(items, token_estimate_of_included_items)``."""
    get_profile(profile)
    task_files = [p for p in task.related_files or [] if isinstance(p, str)]
    extras = [clean_text(p, 500) for p in extra_paths or [] if isinstance(p, str) and p.strip()]
    root = _workspace_root()
    items, total = build_context_pack(repo_root=root, related_files=[*task_files, *extras], profile=profile,
                                      records=pack_records(bundle))
    own = {_normal(p) for p in task_files}
    for item in items:
        if item["kind"] == "note" and item["ref"] == "repository" and root is None:
            item.update(title=NO_ROOT_TITLE, reason=NO_ROOT_REASON)
        elif item.get("origin") == "related_file" and _normal(str(item["ref"])) not in own:
            # Keep origin "related_file" (the generator lists unverified ones by it); only the reason differs.
            item["reason"] = str(item["reason"]).replace("Listed as a related file on the task.", EXTRA_PATH_REASON)
    return items, total


def create_pack(db: Session, actor: Actor, task: Task, profile: str, extra_paths: list[str] | None = None,
                *, bundle: TaskBundle | None = None, quiet: bool = False) -> ContextPack:
    """Build and persist a pack. ``quiet`` skips the task activity (used when a prompt save creates it)."""
    try:
        items, total = build_items(task, bundle or collect(db, task, with_provenance=False), profile, extra_paths)
    except ValueError as exc:
        raise ValidationFailedError(str(exc)) from exc
    pack = ContextPack(id=new_id("context_pack"), organization_id=task.organization_id, task_id=task.id,
                       profile=profile, items=items, token_estimate=total, created_by=actor.user_id,
                       created_at=utcnow())
    db.add(pack)
    db.flush()
    details = {"context_pack_id": pack.id, "profile": profile, "items": len(items), "token_estimate": total}
    if not quiet:
        record_activity(db, task, actor.user_id, "context_pack_created", to_value=PROFILES[profile].label,
                        details=details)
    audit_task(db, actor, task, "context_pack_created", details)
    return pack


def get_pack(db: Session, org_id: str, pack_id: str) -> ContextPack:
    return get_scoped(db, ContextPack, pack_id, org_id, label="Context pack")


def pack_task(db: Session, pack: ContextPack) -> Task | None:
    if not pack.task_id:
        return None
    return db.scalar(select(Task).where(Task.organization_id == pack.organization_id, Task.id == pack.task_id))


# ----------------------------------------------------------------------------- output


def note_text(item: dict[str, Any]) -> str:
    title, reason = str(item.get("title") or ""), str(item.get("reason") or "")
    return reason if not title or reason.startswith(title) else f"{title}: {reason}"


def can_include(item: dict[str, Any]) -> bool:
    status = item.get("status")
    if item.get("included"):
        return True
    if status == "excluded_by_user" and item.get("excerpt"):
        return True
    if status != "over_budget":
        return False
    return item.get("kind") in RECORD_KINDS or (item.get("kind") in FILE_KINDS and item.get("verified") is True)


def _counts(items: list[dict[str, Any]]) -> PackCountsOut:
    content = [i for i in items if i.get("kind") != "note"]
    return PackCountsOut(
        total=len(content), included=sum(1 for i in content if i.get("included")),
        verified=sum(1 for i in content if i.get("verified")),
        unverified=sum(1 for i in content if not i.get("verified") and i.get("status") != "excluded_sensitive"),
        excluded_sensitive=sum(1 for i in content if i.get("status") == "excluded_sensitive"),
        over_budget=sum(1 for i in content if i.get("status") == "over_budget"),
    )


def _summary_fields(pack: ContextPack, task: Task | None) -> dict[str, Any]:
    spec = PROFILES.get(pack.profile) or get_profile("standard")
    items = [i for i in pack.items or [] if isinstance(i, dict)]
    return {
        "id": pack.id, "task_id": pack.task_id, "task_key": task_key(task) if task else None,
        "profile": pack.profile, "profile_label": spec.label, "token_budget": spec.token_budget,
        "token_estimate": pack.token_estimate, "over_budget": pack.token_estimate > spec.token_budget,
        "counts": _counts(items),
        "repository_verified": not any(i.get("kind") == "note" and i.get("ref") == "repository" for i in items),
        "created_by": pack.created_by, "created_at": pack.created_at,
    }


def pack_summary(pack: ContextPack, task: Task | None) -> ContextPackSummaryOut:
    return ContextPackSummaryOut(**_summary_fields(pack, task))


def pack_out(pack: ContextPack, task: Task | None) -> ContextPackOut:
    items = [i for i in pack.items or [] if isinstance(i, dict)]
    out = []
    for item in items:
        out.append(ContextPackItemOut(
            key=str(item.get("key")), kind=item.get("kind") or "note", ref=str(item.get("ref") or ""),
            title=str(item.get("title") or ""), category=str(item.get("category") or "fact"),
            reason=str(item.get("reason") or ""), verified=bool(item.get("verified")),
            included=bool(item.get("included")), token_estimate=int(item.get("token_estimate") or 0),
            excerpt=str(item.get("excerpt") or ""), status=str(item.get("status") or ""),
            origin=str(item.get("origin") or ""), can_include=can_include(item),
        ))
    notes = [note_text(i) for i in items if i.get("kind") == "note"]
    return ContextPackOut(**_summary_fields(pack, task), items=out, notes=notes)


# ----------------------------------------------------------------------------- toggling


def _reread_file(item: dict[str, Any], profile: str) -> str:
    root_text = _workspace_root()
    if root_text is None:
        raise ConflictError(f"'{item.get('ref')}' cannot be included: {NO_ROOT_REASON}")
    try:
        root = Path(root_text).resolve(strict=True)
    except (OSError, RuntimeError):
        root = None
    if root is None or not root.is_dir():
        raise ConflictError(f"'{item.get('ref')}' cannot be included: the configured repository root is not "
                            "accessible.")
    res = rf.resolve_repo_path(root, item.get("ref"))
    if res.status != "ok" or res.abs_path is None:
        raise ConflictError(f"'{item.get('ref')}' cannot be included: {res.reason or 'it is no longer a readable file.'}")
    status, text = rf.read_text_file(res.abs_path)
    if status != "ok" or text is None:
        raise ConflictError(f"'{item.get('ref')}' cannot be included: the file could not be read ({status}).")
    excerpt, truncated = truncate_lines(clean(text, limit=len(text) + 1), get_profile(profile).max_item_tokens)
    if truncated:
        item["reason"] = MANUAL_REASON + " Excerpt truncated to the profile's per-item limit."
    return excerpt


def _rederive_record(db: Session, task: Task | None, item: dict[str, Any]) -> str:
    if task is None:
        raise ConflictError(f"'{item.get('ref')}' cannot be included: the task this pack was built for no longer "
                            "exists.")
    record = next((r for r in pack_records(collect(db, task, with_provenance=False)) if r["ref"] == item.get("ref")),
                  None)
    if record is None:
        raise ConflictError(f"'{item.get('ref')}' cannot be included: the record is no longer linked to the task.")
    return clean(record.get("summary") or "", limit=4000)


def _include(db: Session, pack: ContextPack, task: Task | None, item: dict[str, Any]) -> None:
    if item.get("included"):
        return
    if not can_include(item):
        raise ValidationFailedError(
            f"'{item.get('ref')}' cannot be included: {item.get('reason') or 'it was not verified or is sensitive.'}",
            details={"errors": [f"{item.get('key')}: not includable ({item.get('status')})"]},
        )
    if item.get("status") == "over_budget":
        item["reason"] = MANUAL_REASON
        excerpt = _reread_file(item, pack.profile) if item.get("kind") in FILE_KINDS else _rederive_record(db, task, item)
        if not excerpt:
            raise ConflictError(f"'{item.get('ref')}' cannot be included: it has no content.")
        item["excerpt"] = excerpt
        item["token_estimate"] = estimate_tokens(excerpt) + ITEM_OVERHEAD_TOKENS
    else:
        item["reason"] = str(item.get("reason") or "").replace(" Excluded manually.", "")
    item["included"], item["status"] = True, "included"


def _exclude(item: dict[str, Any]) -> None:
    if not item.get("included"):
        return
    item["included"], item["status"] = False, "excluded_by_user"
    item["reason"] = f"{item.get('reason') or ''} Excluded manually.".strip()


def toggle_items(db: Session, actor: Actor, pack: ContextPack, toggles: list[tuple[str, bool]]) -> list[str]:
    """Apply ``(key, included)`` toggles; returns the keys whose state changed. Recomputes the token estimate."""
    items = [dict(i) for i in pack.items or [] if isinstance(i, dict)]
    by_key = {str(i.get("key")): i for i in items}
    unknown = [k for k, _ in toggles if k not in by_key]
    if unknown:
        raise ValidationFailedError("Unknown context pack item(s): " + ", ".join(unknown[:10]),
                                    details={"errors": [f"{k}: not in this pack" for k in unknown[:50]]})
    task = pack_task(db, pack)
    changed: list[str] = []
    for key, included in toggles:
        item = by_key[key]
        before = bool(item.get("included"))
        if included:
            _include(db, pack, task, item)
        else:
            _exclude(item)
        if bool(item.get("included")) != before:
            changed.append(key)
    if not changed:
        return []
    pack.items = items
    pack.token_estimate = sum(int(i.get("token_estimate") or 0) for i in items if i.get("included"))
    db.flush()
    if task is not None:
        audit_task(db, actor, task, "context_pack_updated",
                   {"context_pack_id": pack.id, "changed": len(changed), "token_estimate": pack.token_estimate})
    return changed


def delete_pack(db: Session, actor: Actor, pack: ContextPack) -> None:
    task = pack_task(db, pack)
    pack_id = pack.id
    db.delete(pack)
    db.flush()
    if task is not None:
        record_activity(db, task, actor.user_id, "context_pack_deleted", details={"context_pack_id": pack_id})
        audit_task(db, actor, task, "context_pack_deleted", {"context_pack_id": pack_id})


# ----------------------------------------------------------------------------- export


def export_pack(db: Session, actor: Actor, pack: ContextPack) -> tuple[str, str]:
    """``(json_body, filename)`` for a download. Audited; excerpts are redacted again (defence in depth)."""
    task = pack_task(db, pack)
    out = pack_out(pack, task)
    doc: dict[str, Any] = {
        "context_pack": out.model_dump(mode="json"),
        "task": {"id": task.id, "key": task_key(task), "title": task.title} if task else None,
        "exported_at": isoformat(utcnow()),
        "generated_by": EXPORTED_BY,
        "external_transfer": False,
    }
    redacted, _ = redact_value(doc)
    append_audit(db, pack.organization_id, action="context_pack.exported", actor_type=actor.type, actor_id=actor.id,
                 target_type="context_pack", target_id=pack.id,
                 details={"task_id": pack.task_id, "profile": pack.profile, "format": "json",
                          "items": out.counts.total, "included": out.counts.included})
    stem = f"context-pack-{task_key(task) if task else pack.id}-{pack.profile}"
    return json.dumps(redacted, indent=2, ensure_ascii=False), _FILENAME_SAFE.sub("_", stem) + ".json"

