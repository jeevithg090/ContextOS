"""Fix-context prompts for Engineering Workspace tasks: generate, save, edit, regenerate, export.

Everything is deterministic and runs on the ContextOS server: the pure generator in
:mod:`app.workspace.fix_context` turns org-scoped records (assembled by ``workspace_ai_input``) and a
context pack (``workspace_ai_packs``) into ordered, typed sections and a rendered prompt. Nothing is
sent to an external AI provider.

- ``generate(db, actor, request)`` — sections + rendered prompt; with ``save=True`` the prompt is stored as
  a ``GeneratedPrompt`` (version 1) together with the context pack it used, and the task gets activity.
- ``update_prompt`` — apply section edits/removals and option changes, re-render, ``version += 1``. Edited
  sections are marked ``edited``; when options change, sections the user has not edited are rebuilt from
  current records so they reflect the new options.
- ``regenerate_section`` — rebuild one section from fresh records (it becomes un-edited again).
- ``export_prompt`` — Markdown text, or a JSON document with sections, options and the context pack.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import new_id
from app.core.timeutil import isoformat, utcnow
from app.models import ContextPack, GeneratedPrompt, Task
from app.schemas.workspace_ai import FixContextRequest, PromptOut, PromptPatch, PromptSummaryOut, SectionOut
from app.services.audit import append_audit
from app.services.scoping import find_scoped, get_scoped
from app.services.workspace_ai_input import TaskBundle, collect, to_input
from app.services.workspace_ai_packs import build_items, create_pack, default_profile, note_text, pack_out
from app.services.workspace_ai_templates import (
    TemplateSpec,
    find_template,
    normalise_options,
    resolve_template,
)
from app.services.workspace_tasks_common import Actor, audit_task, get_task, record_activity, task_key
from app.workspace.fix_context import (
    generate_sections,
    regenerate_section,
    render_json,
    render_markdown,
    validate_sections,
)
from app.workspace.modes import SECTION_KEYS, GenerationOptions, get_mode, get_preset, may_modify_files
from app.workspace.section import SECTION_TITLES, Section
from app.workspace.text import clean, estimate_tokens

DEFAULT_MODE = "implement_fix"
DEFAULT_PRESET = "generic"
EXPORTED_BY = "ContextOS fix-context generator (deterministic; no external AI provider involved)"
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class Generation:
    task: Task
    mode: str
    preset: str
    options: GenerationOptions
    template: TemplateSpec | None
    profile: str
    pack: ContextPack | None
    sections: list[Section]
    content: str
    notes: list[str] = field(default_factory=list)
    prompt: GeneratedPrompt | None = None


def _invalid(exc: Exception) -> ValidationFailedError:
    return ValidationFailedError(str(exc), details={"errors": [str(exc)]})


def prompt_title(task: Task | None) -> str | None:
    return f"{task_key(task)}: {task.title}" if task is not None else None


def _pack_notes(items: list[dict[str, Any]]) -> list[str]:
    return [note_text(i) for i in items if isinstance(i, dict) and i.get("kind") == "note"]


def _options(template: TemplateSpec | None, requested: dict[str, Any] | None) -> GenerationOptions:
    merged = {**(template.options if template else {}), **(requested or {})}
    return GenerationOptions.from_dict(normalise_options(merged))


# ----------------------------------------------------------------------------- generate


def _resolve_pack(db: Session, actor: Actor, task: Task, bundle: TaskBundle, body: FixContextRequest, mode: str,
                  ) -> tuple[ContextPack | None, list[dict[str, Any]], str]:
    if body.context_pack_id:
        pack = get_scoped(db, ContextPack, body.context_pack_id, actor.org_id, label="Context pack")
        if pack.task_id != task.id:
            raise ValidationFailedError(f"Context pack '{pack.id}' was built for a different task.",
                                        details={"errors": ["context_pack_id: belongs to another task"]})
        return pack, list(pack.items or []), pack.profile
    profile = body.profile or default_profile(task, mode)
    if body.save:
        pack = create_pack(db, actor, task, profile, bundle=bundle, quiet=True)
        return pack, list(pack.items or []), profile
    try:
        items, _ = build_items(task, bundle, profile)
    except ValueError as exc:
        raise _invalid(exc) from exc
    return None, items, profile


def generate(db: Session, actor: Actor, body: FixContextRequest) -> Generation:
    task = get_task(db, actor.org_id, body.task_id)
    template = resolve_template(db, actor.org_id, body.template_id) if body.template_id else None
    mode = body.mode or (template.mode if template else DEFAULT_MODE)
    preset = body.preset or (template.preset if template else DEFAULT_PRESET)
    options = _options(template, body.options)
    bundle = collect(db, task)
    pack, items, profile = _resolve_pack(db, actor, task, bundle, body, mode)
    try:
        sections = generate_sections(to_input(bundle, items), mode, preset, options,
                                     section_overrides=template.section_overrides if template else None)
    except ValueError as exc:
        raise _invalid(exc) from exc
    content = render_markdown(sections, mode, preset, options, title=prompt_title(task))
    result = Generation(task=task, mode=mode, preset=preset, options=options, template=template, profile=profile,
                        pack=pack, sections=sections, content=content, notes=[*bundle.notes, *_pack_notes(items)])
    if body.save:
        result.prompt = _save(db, actor, result)
    return result


def _save(db: Session, actor: Actor, gen: Generation) -> GeneratedPrompt:
    now = utcnow()
    prompt = GeneratedPrompt(
        id=new_id("generated_prompt"), organization_id=actor.org_id, task_id=gen.task.id, mode=gen.mode,
        preset=gen.preset, options=gen.options.to_dict(), sections=[s.to_dict() for s in gen.sections],
        content=gen.content, context_pack_id=gen.pack.id if gen.pack else None,
        template_id=gen.template.id if gen.template else None, version=1, created_by=actor.user_id,
        created_at=now, updated_at=now,
    )
    db.add(prompt)
    db.flush()
    details = {"prompt_id": prompt.id, "mode": gen.mode, "preset": gen.preset, "version": 1,
               "context_pack_id": prompt.context_pack_id, "template_id": prompt.template_id}
    record_activity(db, gen.task, actor.user_id, "prompt_generated", to_value=f"{get_mode(gen.mode).label} prompt",
                    details=details)
    audit_task(db, actor, gen.task, "prompt_generated", details)
    return prompt


# ----------------------------------------------------------------------------- read models


def section_out(section: Section | dict[str, Any]) -> SectionOut:
    data = section.to_dict() if isinstance(section, Section) else Section.from_dict(section).to_dict()
    return SectionOut(**data)


def _sections(prompt: GeneratedPrompt) -> list[Section]:
    return [Section.from_dict(s) for s in prompt.sections or [] if isinstance(s, dict)]


def _summary_fields(prompt: GeneratedPrompt, task: Task | None) -> dict[str, Any]:
    sections = [s for s in prompt.sections or [] if isinstance(s, dict)]
    return {
        "id": prompt.id, "task_id": prompt.task_id, "task_key": task_key(task) if task else None,
        "task_title": task.title if task else None, "mode": prompt.mode, "mode_label": get_mode(prompt.mode).label,
        "preset": prompt.preset, "preset_label": get_preset(prompt.preset).label, "version": prompt.version,
        "template_id": prompt.template_id, "context_pack_id": prompt.context_pack_id,
        "section_count": len(sections), "edited_sections": [str(s.get("key")) for s in sections if s.get("edited")],
        "token_estimate": estimate_tokens(prompt.content), "created_by": prompt.created_by,
        "created_at": prompt.created_at, "updated_at": prompt.updated_at,
    }


def prompt_summary(prompt: GeneratedPrompt, task: Task | None) -> PromptSummaryOut:
    return PromptSummaryOut(**_summary_fields(prompt, task))


def prompt_out(prompt: GeneratedPrompt, task: Task | None, notes: list[str] | None = None) -> PromptOut:
    sections = _sections(prompt)
    options = GenerationOptions.from_dict(prompt.options or {})
    return PromptOut(
        **_summary_fields(prompt, task), may_modify_files=may_modify_files(get_mode(prompt.mode), options),
        options=options.to_dict(), sections=[section_out(s) for s in sections], content=prompt.content,
        sources=list(dict.fromkeys(src for s in sections for src in s.sources)),
        problems=validate_sections(sections, prompt.mode), notes=list(notes or []),
    )


def get_prompt(db: Session, org_id: str, prompt_id: str) -> GeneratedPrompt:
    return get_scoped(db, GeneratedPrompt, prompt_id, org_id, label="Prompt")


def prompt_task(db: Session, prompt: GeneratedPrompt) -> Task | None:
    return find_scoped(db, Task, prompt.task_id, prompt.organization_id)


def tasks_by_id(db: Session, org_id: str, ids: set[str | None]) -> dict[str, Task]:
    wanted = [i for i in ids if i]
    if not wanted:
        return {}
    return {t.id: t for t in db.scalars(select(Task).where(Task.organization_id == org_id, Task.id.in_(wanted)))}


def prompt_query(org_id: str, task_id: str | None):
    query = select(GeneratedPrompt).where(GeneratedPrompt.organization_id == org_id)
    if task_id:
        query = query.where(GeneratedPrompt.task_id == task_id)
    return query.order_by(GeneratedPrompt.updated_at.desc(), GeneratedPrompt.id.desc())


# ----------------------------------------------------------------------------- edit & regenerate


def _fresh_input(db: Session, prompt: GeneratedPrompt, task: Task | None):
    """Current records + the prompt's context pack (or a fresh, unsaved one) and template overrides."""
    if task is None:
        raise ConflictError("The task this prompt was generated for no longer exists, so its sections cannot be "
                            "rebuilt from records. Edit the sections directly instead.")
    bundle = collect(db, task)
    notes = list(bundle.notes)
    pack = find_scoped(db, ContextPack, prompt.context_pack_id, prompt.organization_id)
    if pack is not None:
        items = list(pack.items or [])
    else:
        profile = default_profile(task, prompt.mode)
        items, _ = build_items(task, bundle, profile)
        notes.append(f"The context pack this prompt was built from is no longer available; a fresh '{profile}' pack "
                     "was used for rebuilt sections and was not saved.")
    notes.extend(_pack_notes(items))
    overrides: dict[str, str] = {}
    if prompt.template_id:
        template = find_template(db, prompt.organization_id, prompt.template_id)
        if template is None:
            notes.append("The template this prompt used has been deleted; its extra section instructions were not "
                         "applied to rebuilt sections.")
        else:
            overrides = template.section_overrides
    return to_input(bundle, items), notes, overrides


def _store(db: Session, actor: Actor, prompt: GeneratedPrompt, task: Task | None, sections: list[Section],
           options: GenerationOptions, kind: str, details: dict[str, Any]) -> None:
    prompt.sections = [s.to_dict() for s in sections]
    prompt.options = options.to_dict()
    prompt.content = render_markdown(sections, prompt.mode, prompt.preset, options, title=prompt_title(task))
    prompt.version = (prompt.version or 1) + 1
    prompt.updated_at = utcnow()
    db.flush()
    if task is not None:
        info = {"prompt_id": prompt.id, "version": prompt.version, **details}
        record_activity(db, task, actor.user_id, kind, to_value=f"v{prompt.version}", details=info)
        audit_task(db, actor, task, kind, info)


def _apply_edits(sections: list[Section], edits: list[Any]) -> tuple[list[str], list[str]]:
    by_key = {s.key: s for s in sections}
    seen: set[str] = set()
    edited: list[str] = []
    removed: list[str] = []
    for edit in edits:
        if edit.key not in SECTION_TITLES:
            raise _invalid(ValueError(f"Unknown section '{edit.key}'."))
        if edit.key in seen:
            raise _invalid(ValueError(f"Section '{edit.key}' is listed more than once."))
        seen.add(edit.key)
        section = by_key.get(edit.key)
        if section is None:
            if edit.removed:
                continue
            raise _invalid(ValueError(f"Section '{SECTION_TITLES[edit.key]}' is not part of this prompt; regenerate "
                                      "it to add it back."))
        if edit.removed:
            sections.remove(section)
            removed.append(edit.key)
        elif edit.content is not None:
            text = clean(edit.content, limit=len(edit.content) + 1)
            if text != section.content:
                section.content, section.edited = text, True
                edited.append(edit.key)
    return edited, removed


def update_prompt(db: Session, actor: Actor, prompt: GeneratedPrompt, patch: PromptPatch) -> list[str]:
    """Apply edits; returns plain-language notes. Raises 422 when the result is not a valid prompt."""
    task = prompt_task(db, prompt)
    old = GenerationOptions.from_dict(prompt.options or {})
    requested = {**old.to_dict(), **(patch.options or {})}
    if patch.extra_instructions is not None:
        requested["extra_instructions"] = clean(patch.extra_instructions, limit=4000)
    new = GenerationOptions.from_dict(normalise_options(requested))
    sections = _sections(prompt)
    notes: list[str] = []
    refreshed: list[str] = []
    if new.to_dict() != old.to_dict():
        data, fresh_notes, overrides = _fresh_input(db, prompt, task)
        fresh = {s.key: s for s in generate_sections(data, prompt.mode, prompt.preset, new,
                                                     section_overrides=overrides)}
        for index, section in enumerate(sections):
            if not section.edited and section.key in fresh:
                sections[index] = fresh[section.key]
                refreshed.append(section.key)
        notes.extend(fresh_notes)
        notes.append("Options changed: sections you have not edited were rebuilt from current records.")
    edited, removed = _apply_edits(sections, patch.sections or [])
    problems = validate_sections(sections, prompt.mode)
    if problems:
        raise ValidationFailedError("The edited prompt is not valid: " + " ".join(problems),
                                    details={"errors": problems})
    if not (edited or removed or new.to_dict() != old.to_dict()):
        return notes
    _store(db, actor, prompt, task, sections, new, "prompt_edited",
           {"edited": edited, "removed": removed, "refreshed": refreshed,
            "options_changed": new.to_dict() != old.to_dict()})
    return notes


def regenerate_prompt_section(db: Session, actor: Actor, prompt: GeneratedPrompt, key: str) -> list[str]:
    if key not in SECTION_TITLES:
        raise _invalid(ValueError(f"Unknown section '{key}'; expected one of: {', '.join(SECTION_KEYS)}"))
    task = prompt_task(db, prompt)
    options = GenerationOptions.from_dict(prompt.options or {})
    data, notes, overrides = _fresh_input(db, prompt, task)
    fresh = regenerate_section(data, key, prompt.mode, prompt.preset, options, section_overrides=overrides)
    sections = [s for s in _sections(prompt) if s.key != key]
    order = {k: i for i, k in enumerate(SECTION_KEYS)}
    position = next((i for i, s in enumerate(sections) if order.get(s.key, 99) > order[key]), len(sections))
    sections.insert(position, fresh)
    _store(db, actor, prompt, task, sections, options, "prompt_section_regenerated", {"section": key})
    return notes


# ----------------------------------------------------------------------------- export


def _filename(prompt: GeneratedPrompt, task: Task | None, ext: str) -> str:
    stem = f"{task_key(task) if task else 'prompt'}-{prompt.mode}-v{prompt.version}"
    return _FILENAME_SAFE.sub("_", stem) + f".{ext}"


def export_prompt(db: Session, actor: Actor, prompt: GeneratedPrompt, fmt: str) -> tuple[str, str, str]:
    """``(body, media_type, filename)``. The export is audited; the stored content is already redacted."""
    if fmt not in ("markdown", "json"):
        raise NotFoundError(f"Unknown export format '{fmt}'")
    task = prompt_task(db, prompt)
    append_audit(db, prompt.organization_id, action="prompt.exported", actor_type=actor.type, actor_id=actor.id,
                 target_type="generated_prompt", target_id=prompt.id,
                 details={"format": fmt, "task_id": prompt.task_id, "version": prompt.version})
    if fmt == "markdown":
        return prompt.content, "text/markdown; charset=utf-8", _filename(prompt, task, "md")
    sections = _sections(prompt)
    options = GenerationOptions.from_dict(prompt.options or {})
    doc = render_json(sections, prompt.mode, prompt.preset, options, title=prompt_title(task))
    doc["content"] = prompt.content
    pack = find_scoped(db, ContextPack, prompt.context_pack_id, prompt.organization_id)
    doc.update({
        "prompt": {"id": prompt.id, "version": prompt.version, "template_id": prompt.template_id,
                   "created_at": isoformat(prompt.created_at), "updated_at": isoformat(prompt.updated_at)},
        "task": {"id": task.id, "key": task_key(task), "title": task.title} if task else None,
        "context_pack": pack_out(pack, task).model_dump(mode="json") if pack is not None else None,
        "problems": validate_sections(sections, prompt.mode),
        "generated_by": EXPORTED_BY,
        "external_transfer": False,
    })
    return json.dumps(doc, indent=2, ensure_ascii=False), "application/json", _filename(prompt, task, "json")
