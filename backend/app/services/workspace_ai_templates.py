"""Prompt templates: built-in templates derived from the prompt modes, plus organisation templates.

Built-in templates (``builtin:<mode>``) are read-only: one per prompt mode, with option defaults tuned for
that mode. Organisation templates are ``PromptTemplate`` rows; their options are validated with
:class:`~app.workspace.modes.GenerationOptions` and stored normalised, and ``section_overrides`` (extra
instructions appended to a section) may only name known sections. Free text is redacted before storage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import new_id
from app.models import PromptTemplate
from app.schemas.workspace_ai import ModesOut, OptionSpecOut, TemplateOut
from app.services.audit import append_audit
from app.services.notify import notify
from app.services.scoping import get_scoped
from app.services.workspace_tasks_common import Actor, clean_optional, clean_text
from app.workspace.breakdown import PLAN_KEYS
from app.workspace.context_pack import describe_profiles
from app.workspace.modes import (
    MODES,
    SECTION_KEYS,
    Autonomy,
    GenerationOptions,
    OutputFormat,
    PromptMode,
    RequiredTesting,
    SecurityLevel,
    TechnicalDepth,
    describe_modes,
    describe_presets,
    get_mode,
    get_preset,
)
from app.workspace.section import SECTION_TITLES

BUILTIN_PREFIX = "builtin:"
OVERRIDE_MAX = 2000

# Option defaults per built-in template (everything else uses GenerationOptions defaults).
_BUILTIN_OPTIONS: dict[PromptMode, dict[str, Any]] = {
    PromptMode.INVESTIGATE_ONLY: {"technical_depth": "standard"},
    PromptMode.ROOT_CAUSE_ANALYSIS: {"technical_depth": "deep"},
    PromptMode.IMPLEMENTATION_PLAN: {"technical_depth": "deep", "testing_requirements": "unit_integration"},
    PromptMode.IMPLEMENT_FIX: {"testing_requirements": "unit_integration"},
    PromptMode.SECURITY_HARDEN: {"security_requirements": "strict", "testing_requirements": "unit_integration"},
    PromptMode.REFACTOR: {"testing_requirements": "full_regression"},
    PromptMode.TEST_AND_VERIFY: {"testing_requirements": "unit_integration"},
    PromptMode.FULL_AUTONOMOUS_REMEDIATION: {
        "autonomy": "autonomous_with_checkpoints", "security_requirements": "strict",
        "testing_requirements": "full_regression", "technical_depth": "deep",
    },
}


@dataclass
class TemplateSpec:
    id: str
    name: str
    description: str | None
    mode: str
    preset: str
    options: dict[str, Any]
    section_overrides: dict[str, str] = field(default_factory=dict)
    is_builtin: bool = False
    created_by: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


def builtin_templates() -> list[TemplateSpec]:
    return [
        TemplateSpec(id=f"{BUILTIN_PREFIX}{spec.key.value}", name=spec.label, description=spec.description,
                     mode=spec.key.value, preset="generic",
                     options=GenerationOptions.from_dict(_BUILTIN_OPTIONS.get(spec.key, {})).to_dict(),
                     is_builtin=True)
        for spec in MODES.values()
    ]


def _spec(row: PromptTemplate) -> TemplateSpec:
    return TemplateSpec(id=row.id, name=row.name, description=row.description, mode=row.mode, preset=row.preset,
                        options=dict(row.options or {}),
                        section_overrides={k: v for k, v in (row.section_overrides or {}).items()
                                           if k in SECTION_KEYS and isinstance(v, str)},
                        is_builtin=False, created_by=row.created_by, created_at=row.created_at,
                        updated_at=row.updated_at)


def template_out(spec: TemplateSpec) -> TemplateOut:
    return TemplateOut(id=spec.id, name=spec.name, description=spec.description, mode=spec.mode,
                       mode_label=get_mode(spec.mode).label, preset=spec.preset,
                       preset_label=get_preset(spec.preset).label, options=spec.options,
                       section_overrides=spec.section_overrides, is_builtin=spec.is_builtin,
                       created_by=spec.created_by, created_at=spec.created_at, updated_at=spec.updated_at)


def list_templates(db: Session, org_id: str) -> list[TemplateSpec]:
    rows = db.scalars(select(PromptTemplate).where(PromptTemplate.organization_id == org_id)
                      .order_by(func.lower(PromptTemplate.name), PromptTemplate.created_at))
    return [*builtin_templates(), *(_spec(r) for r in rows)]


def find_template(db: Session, org_id: str, template_id: str) -> TemplateSpec | None:
    if template_id.startswith(BUILTIN_PREFIX):
        return next((t for t in builtin_templates() if t.id == template_id), None)
    row = db.scalar(select(PromptTemplate).where(PromptTemplate.organization_id == org_id,
                                                 PromptTemplate.id == template_id))
    return _spec(row) if row is not None else None


def resolve_template(db: Session, org_id: str, template_id: str) -> TemplateSpec:
    spec = find_template(db, org_id, template_id)
    if spec is None:
        raise NotFoundError(f"Prompt template '{template_id}' not found")
    return spec


# ----------------------------------------------------------------------------- validation


def normalise_options(options: dict[str, Any] | None) -> dict[str, Any]:
    try:
        return GenerationOptions.from_dict(options or {}).to_dict()
    except (TypeError, ValueError) as exc:
        raise ValidationFailedError(str(exc), details={"errors": [str(exc)]}) from exc


def _overrides(raw: dict[str, str]) -> dict[str, str]:
    unknown = sorted(set(raw) - set(SECTION_KEYS))
    if unknown:
        message = f"Unknown section key(s) in section_overrides: {', '.join(unknown)}"
        raise ValidationFailedError(message, details={"errors": [message]})
    out = {}
    for key in SECTION_KEYS:
        text = clean_text(raw.get(key), OVERRIDE_MAX + 1)
        if len(text) > OVERRIDE_MAX:
            message = f"Extra instructions for '{key}' must be at most {OVERRIDE_MAX} characters"
            raise ValidationFailedError(message, details={"errors": [message]})
        if text:
            out[key] = text
    return out


def _check_name(db: Session, org_id: str, name: str, exclude_id: str | None = None) -> str:
    clean_name = clean_text(name, 200)
    if not clean_name:
        raise ValidationFailedError("A template needs a name.", details={"errors": ["name: required"]})
    if clean_name.lower() in {t.name.lower() for t in builtin_templates()}:
        raise ConflictError(f"'{clean_name}' is the name of a built-in template; choose another name.")
    query = select(PromptTemplate.id).where(PromptTemplate.organization_id == org_id,
                                            func.lower(PromptTemplate.name) == clean_name.lower())
    if exclude_id:
        query = query.where(PromptTemplate.id != exclude_id)
    if db.scalar(query) is not None:
        raise ConflictError(f"A prompt template named '{clean_name}' already exists.")
    return clean_name


def _audit(db: Session, actor: Actor, action: str, template_id: str, details: dict[str, Any]) -> None:
    append_audit(db, actor.org_id, action=f"prompt_template.{action}", actor_type=actor.type, actor_id=actor.id,
                 target_type="prompt_template", target_id=template_id, details=details)
    notify(db, actor.org_id, "task.updated", template_id=template_id)


def _org_row(db: Session, org_id: str, template_id: str) -> PromptTemplate:
    if template_id.startswith(BUILTIN_PREFIX):
        if find_template(db, org_id, template_id) is None:
            raise NotFoundError(f"Prompt template '{template_id}' not found")
        raise ConflictError("Built-in templates are read-only. Create an organisation template with the settings "
                            "you want instead.")
    return get_scoped(db, PromptTemplate, template_id, org_id, label="Prompt template")


# ----------------------------------------------------------------------------- mutations


def create_template(db: Session, actor: Actor, data: dict[str, Any]) -> TemplateSpec:
    row = PromptTemplate(
        id=new_id("prompt_template"), organization_id=actor.org_id, name=_check_name(db, actor.org_id, data["name"]),
        description=clean_optional(data.get("description"), 2000), mode=get_mode(data["mode"]).key.value,
        preset=get_preset(data.get("preset") or "generic").key.value,
        options=normalise_options(data.get("options")), section_overrides=_overrides(data.get("section_overrides") or {}),
        is_builtin=False, created_by=actor.user_id,
    )
    db.add(row)
    db.flush()
    _audit(db, actor, "created", row.id, {"name": row.name, "mode": row.mode, "preset": row.preset})
    return _spec(row)


def update_template(db: Session, actor: Actor, template_id: str, changes: dict[str, Any]) -> TemplateSpec:
    row = _org_row(db, actor.org_id, template_id)
    changed: list[str] = []
    for key, value in changes.items():
        if key == "name" and value is not None:
            new: Any = _check_name(db, actor.org_id, value, exclude_id=row.id)
        elif key == "description":
            new = clean_optional(value, 2000)
        elif key == "mode" and value is not None:
            new = get_mode(value).key.value
        elif key == "preset" and value is not None:
            new = get_preset(value).key.value
        elif key == "options" and value is not None:
            new = normalise_options(value)
        elif key == "section_overrides" and value is not None:
            new = _overrides(value)
        else:
            continue
        if getattr(row, key) != new:
            setattr(row, key, new)
            changed.append(key)
    if changed:
        db.flush()
        _audit(db, actor, "updated", row.id, {"fields": changed})
    return _spec(row)


def delete_template(db: Session, actor: Actor, template_id: str) -> None:
    row = _org_row(db, actor.org_id, template_id)
    name = row.name
    db.delete(row)
    db.flush()
    _audit(db, actor, "deleted", template_id, {"name": name})


# ----------------------------------------------------------------------------- catalogue

_OPTION_TEXT: dict[str, tuple[str, str]] = {
    "technical_depth": ("Technical depth", "How much evidence the prompt includes and how much reasoning it asks for."),
    "autonomy": ("Autonomy", "How independently the agent may change files. Only applies to modes that allow changes."),
    "testing_requirements": ("Required testing", "Which tests the agent must add or run before reporting."),
    "security_requirements": ("Security requirements", "Strict adds adversarial testing and fail-closed rules."),
    "output_format": ("Output format", "Plain Markdown, or Markdown wrapped in <section> tags for agents that parse them."),
    "constraints": ("Constraints", "Extra rules the agent must follow, one per line."),
    "allow_code_changes": ("Allow code changes", "Turn off to make any mode read-only: the agent proposes a diff instead."),
    "allow_architecture_changes": ("Allow architecture changes", "Whether the agent may change module boundaries, "
                                                                 "schemas or public interfaces."),
    "extra_instructions": ("Extra instructions", "Free-text instructions added to the Constraints section."),
}
_ENUMS = {"technical_depth": TechnicalDepth, "autonomy": Autonomy, "testing_requirements": RequiredTesting,
          "security_requirements": SecurityLevel, "output_format": OutputFormat}


def _option_specs() -> list[OptionSpecOut]:
    defaults = GenerationOptions().to_dict()
    specs = []
    for key, (label, description) in _OPTION_TEXT.items():
        if key in _ENUMS:
            kind, values = "enum", [m.value for m in _ENUMS[key]]
        elif isinstance(defaults[key], bool):
            kind, values = "boolean", []
        elif isinstance(defaults[key], list):
            kind, values = "list", []
        else:
            kind, values = "text", []
        specs.append(OptionSpecOut(key=key, label=label, type=kind, values=values, default=defaults[key],
                                   description=description))
    return specs


def catalogue() -> ModesOut:
    """Modes, agent presets, context-pack profiles, options and sections for the generator UI."""
    return ModesOut(
        modes=describe_modes(), presets=describe_presets(), profiles=describe_profiles(), options=_option_specs(),
        sections=[{"key": k, "title": SECTION_TITLES[k]} for k in SECTION_KEYS], breakdown_plans=list(PLAN_KEYS),
        repository_configured=bool((get_settings().workspace_repo_root or "").strip()),
    )
