"""Engineering Workspace AI: context packs, fix-context prompts, prompt templates and task breakdown.

Authorisation: ``read`` for GET, ``write`` for every mutation. Every id resolves inside the caller's
organisation (404 otherwise). Generation is deterministic and runs on this server — no record, file
excerpt or prompt is sent to an external AI provider; responses say so with ``external_transfer: false``.
Mutations write task activity (where a task is involved), an audit entry and a live notification.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import Principal, require, require_org_wide
from app.database.session import get_db
from app.domain.enums import Permission
from app.models import ContextPack
from app.schemas.common import Page
from app.schemas.workspace_ai import (
    BreakdownApplyIn,
    BreakdownApplyOut,
    BreakdownIn,
    BreakdownOut,
    ContextPackCreate,
    ContextPackOut,
    ContextPackPatch,
    ContextPackSummaryOut,
    CreatedDependencyOut,
    ExportFormatName,
    FixContextOut,
    FixContextRequest,
    ModesOut,
    PromptModeName,
    PromptOut,
    PromptPatch,
    PromptSummaryOut,
    RegenerateSectionIn,
    SubtaskDraftOut,
    TemplateCreate,
    TemplateOut,
    TemplatePatch,
)
from app.services import workspace_ai as ai
from app.services import workspace_ai_breakdown as breakdown
from app.services import workspace_ai_packs as packs
from app.services import workspace_ai_templates as templates
from app.services.scoping import paginate, scoped
from app.services.workspace_tasks_common import as_actor, get_task, task_key
from app.services.workspace_views import task_cards
from app.workspace.breakdown import PLAN_KEYS
from app.workspace.modes import get_mode, get_preset, may_modify_files
from app.workspace.text import estimate_tokens

router = APIRouter(prefix="/workspace/ai", tags=["workspace"])

READ = Depends(require_org_wide(Permission.READ.value))  # bound API keys: 403
WRITE = Depends(require(Permission.WRITE.value))


# ----------------------------------------------------------------------------- catalogue


@router.get("/modes", response_model=ModesOut)
def modes(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    task_id: str | None = Query(None, description="Also return the context-pack profile suggested for this task."),
    mode: PromptModeName | None = Query(None, description="Mode for suggested_profile (default implement_fix)."),
) -> ModesOut:
    catalogue = templates.catalogue()
    if task_id is None:
        return catalogue
    task = get_task(db, principal.org_id, task_id)
    return packs.with_suggestions(catalogue, task, mode or ai.DEFAULT_MODE)


# ----------------------------------------------------------------------------- context packs


@router.post("/context-packs", response_model=ContextPackOut, status_code=201)
def create_context_pack(body: ContextPackCreate, principal: Principal = WRITE,
                        db: Session = Depends(get_db)) -> ContextPackOut:
    task = get_task(db, principal.org_id, body.task_id)
    pack = packs.create_pack(db, as_actor(principal), task, body.profile, body.extra_paths)
    return packs.pack_out(pack, task)


@router.get("/context-packs", response_model=Page[ContextPackSummaryOut])
def list_context_packs(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    task_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ContextPackSummaryOut]:
    query = scoped(ContextPack, principal.org_id)
    if task_id:
        query = query.where(ContextPack.task_id == get_task(db, principal.org_id, task_id).id)
    rows, total = paginate(db, query.order_by(ContextPack.created_at.desc(), ContextPack.id.desc()),
                           limit=limit, offset=offset)
    tasks = ai.tasks_by_id(db, principal.org_id, {r.task_id for r in rows})
    return Page(items=[packs.pack_summary(r, tasks.get(r.task_id or "")) for r in rows], total=total, limit=limit,
                offset=offset)


@router.get("/context-packs/{pack_id}", response_model=ContextPackOut)
def get_context_pack(pack_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> ContextPackOut:
    pack = packs.get_pack(db, principal.org_id, pack_id)
    return packs.pack_out(pack, packs.pack_task(db, pack))


@router.get("/context-packs/{pack_id}/export")
def export_context_pack(pack_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> Response:
    """The pack as a JSON download (redacted again). Audited as ``context_pack.exported``."""
    pack = packs.get_pack(db, principal.org_id, pack_id)
    body, filename = packs.export_pack(db, as_actor(principal), pack)
    return Response(content=body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})


@router.patch("/context-packs/{pack_id}", response_model=ContextPackOut)
def update_context_pack(pack_id: str, body: ContextPackPatch, principal: Principal = WRITE,
                        db: Session = Depends(get_db)) -> ContextPackOut:
    pack = packs.get_pack(db, principal.org_id, pack_id)
    packs.toggle_items(db, as_actor(principal), pack, [(i.key, i.included) for i in body.items])
    return packs.pack_out(pack, packs.pack_task(db, pack))


@router.delete("/context-packs/{pack_id}", status_code=204)
def delete_context_pack(pack_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    packs.delete_pack(db, as_actor(principal), packs.get_pack(db, principal.org_id, pack_id))
    return Response(status_code=204)


# ----------------------------------------------------------------------------- fix context


@router.post("/fix-context", response_model=FixContextOut)
def fix_context(body: FixContextRequest, response: Response, principal: Principal = READ,
                db: Session = Depends(get_db)) -> FixContextOut:
    """Generate a fix-context prompt. ``save=true`` needs ``write`` and answers 201 with the stored prompt id."""
    if body.save:
        principal.require(Permission.WRITE.value)
    gen = ai.generate(db, as_actor(principal), body)
    response.status_code = 201 if gen.prompt is not None else 200
    sections = [ai.section_out(s) for s in gen.sections]
    return FixContextOut(
        prompt_id=gen.prompt.id if gen.prompt else None, saved=gen.prompt is not None,
        version=gen.prompt.version if gen.prompt else None, task_id=gen.task.id, task_key=task_key(gen.task),
        mode=gen.mode, mode_label=get_mode(gen.mode).label, preset=gen.preset,
        preset_label=get_preset(gen.preset).label, may_modify_files=may_modify_files(get_mode(gen.mode), gen.options),
        options=gen.options.to_dict(), template_id=gen.template.id if gen.template else None, sections=sections,
        content=gen.content, token_estimate=estimate_tokens(gen.content),
        sources=list(dict.fromkeys(src for s in sections for src in s.sources)),
        context_pack=packs.pack_summary(gen.pack, gen.task) if gen.pack is not None else None,
        context_pack_profile=gen.profile, notes=gen.notes,
        problems=ai.validate_sections(gen.sections, gen.mode),
    )


# ----------------------------------------------------------------------------- saved prompts


@router.get("/prompts", response_model=Page[PromptSummaryOut])
def list_prompts(
    principal: Principal = READ,
    db: Session = Depends(get_db),
    task_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[PromptSummaryOut]:
    if task_id:
        task_id = get_task(db, principal.org_id, task_id).id
    rows, total = paginate(db, ai.prompt_query(principal.org_id, task_id), limit=limit, offset=offset)
    tasks = ai.tasks_by_id(db, principal.org_id, {r.task_id for r in rows})
    return Page(items=[ai.prompt_summary(r, tasks.get(r.task_id or "")) for r in rows], total=total, limit=limit,
                offset=offset)


@router.get("/prompts/{prompt_id}", response_model=PromptOut)
def get_prompt(prompt_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> PromptOut:
    prompt = ai.get_prompt(db, principal.org_id, prompt_id)
    return ai.prompt_out(prompt, ai.prompt_task(db, prompt))


@router.patch("/prompts/{prompt_id}", response_model=PromptOut)
def update_prompt(prompt_id: str, body: PromptPatch, principal: Principal = WRITE,
                  db: Session = Depends(get_db)) -> PromptOut:
    prompt = ai.get_prompt(db, principal.org_id, prompt_id)
    notes = ai.update_prompt(db, as_actor(principal), prompt, body)
    return ai.prompt_out(prompt, ai.prompt_task(db, prompt), notes)


@router.post("/prompts/{prompt_id}/regenerate-section", response_model=PromptOut)
def regenerate_section(prompt_id: str, body: RegenerateSectionIn, principal: Principal = WRITE,
                       db: Session = Depends(get_db)) -> PromptOut:
    prompt = ai.get_prompt(db, principal.org_id, prompt_id)
    notes = ai.regenerate_prompt_section(db, as_actor(principal), prompt, body.section_key)
    return ai.prompt_out(prompt, ai.prompt_task(db, prompt), notes)


@router.get("/prompts/{prompt_id}/export")
def export_prompt(prompt_id: str, format: ExportFormatName = Query("markdown"), principal: Principal = READ,
                  db: Session = Depends(get_db)) -> Response:
    prompt = ai.get_prompt(db, principal.org_id, prompt_id)
    body, media_type, filename = ai.export_prompt(db, as_actor(principal), prompt, format)
    return Response(content=body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "X-Content-Type-Options": "nosniff"})


# ----------------------------------------------------------------------------- templates


@router.get("/templates", response_model=list[TemplateOut])
def list_templates(principal: Principal = READ, db: Session = Depends(get_db)) -> list[TemplateOut]:
    return [templates.template_out(t) for t in templates.list_templates(db, principal.org_id)]


@router.post("/templates", response_model=TemplateOut, status_code=201)
def create_template(body: TemplateCreate, principal: Principal = WRITE, db: Session = Depends(get_db)) -> TemplateOut:
    return templates.template_out(templates.create_template(db, as_actor(principal), body.model_dump()))


@router.get("/templates/{template_id}", response_model=TemplateOut)
def get_template(template_id: str, principal: Principal = READ, db: Session = Depends(get_db)) -> TemplateOut:
    return templates.template_out(templates.resolve_template(db, principal.org_id, template_id))


@router.patch("/templates/{template_id}", response_model=TemplateOut)
def update_template(template_id: str, body: TemplatePatch, principal: Principal = WRITE,
                    db: Session = Depends(get_db)) -> TemplateOut:
    spec = templates.update_template(db, as_actor(principal), template_id, body.model_dump(exclude_unset=True))
    return templates.template_out(spec)


@router.delete("/templates/{template_id}", status_code=204)
def delete_template(template_id: str, principal: Principal = WRITE, db: Session = Depends(get_db)) -> Response:
    templates.delete_template(db, as_actor(principal), template_id)
    return Response(status_code=204)


# ----------------------------------------------------------------------------- breakdown


@router.post("/breakdown", response_model=BreakdownOut)
def draft_breakdown(body: BreakdownIn, principal: Principal = READ, db: Session = Depends(get_db)) -> BreakdownOut:
    task, plan, drafts = breakdown.draft_breakdown(db, principal.org_id, body.task_id, body.plan)
    return BreakdownOut(task_id=task.id, task_key=task_key(task), plan=plan, plans=list(PLAN_KEYS),
                        drafts=[SubtaskDraftOut(**d.to_dict()) for d in drafts],
                        existing_subtasks=breakdown.existing_subtasks(db, task), note=breakdown.BREAKDOWN_NOTE)


@router.post("/breakdown/apply", response_model=BreakdownApplyOut, status_code=201)
def apply_breakdown(body: BreakdownApplyIn, principal: Principal = WRITE,
                    db: Session = Depends(get_db)) -> BreakdownApplyOut:
    result = breakdown.apply_breakdown(db, as_actor(principal), body.task_id, body.drafts, priority=body.priority,
                                       override_wip=body.override_wip)
    return BreakdownApplyOut(
        parent_task_id=result.parent.id, created=task_cards(db, principal.org_id, result.created),
        dependencies=[CreatedDependencyOut(task_id=a, depends_on_task_id=b) for a, b in result.dependencies],
    )
