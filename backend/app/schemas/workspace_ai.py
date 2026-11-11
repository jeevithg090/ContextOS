"""Engineering Workspace AI: context packs, fix-context prompts, prompt templates and task breakdown.

Mirrored by ``frontend/src/features/workspace/ai/types.ts``. Everything here is generated on the
ContextOS server from org-scoped records; nothing is sent to an external AI provider, which every
response states with ``external_transfer: false``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.workspace import PriorityName, Strict, TaskTypeName
from app.schemas.workspace_boards import TaskCardOut

# == app.workspace.modes.PromptMode
PromptModeName = Literal[
    "investigate_only", "root_cause_analysis", "implementation_plan", "implement_fix", "security_harden",
    "refactor", "test_and_verify", "full_autonomous_remediation",
]
PresetName = Literal["claude_code", "codex", "cursor", "generic"]  # == app.workspace.modes.Preset
ProfileName = Literal["minimal", "standard", "deep", "security_critical", "full"]  # == context_pack.PROFILES
SectionKindName = Literal["fact", "evidence", "assumption", "hypothesis", "recommendation", "instruction"]
PackItemKindName = Literal["doc", "source_file", "test_file", "record", "policy", "note", "git_history"]
ExportFormatName = Literal["markdown", "json"]

PRIVACY_NOTE = (
    "Generated on the ContextOS server from records in your organisation. Nothing is sent to an external AI "
    "provider; copy or export the prompt to use it with your coding agent."
)

MAX_EXTRA_PATHS = 50
MAX_DRAFTS = 20


# ----------------------------------------------------------------------------- context packs


class ContextPackCreate(Strict):
    task_id: str
    profile: ProfileName = "standard"
    extra_paths: list[str] = Field(default_factory=list, max_length=MAX_EXTRA_PATHS,
                                   description="Additional repository-relative paths to verify and include.")


class PackItemToggle(Strict):
    key: str = Field(min_length=1, max_length=2200)
    included: bool


class ContextPackPatch(Strict):
    items: list[PackItemToggle] = Field(min_length=1, max_length=500)


class ContextPackItemOut(BaseModel):
    key: str
    kind: PackItemKindName
    ref: str
    title: str
    category: str
    reason: str
    verified: bool
    included: bool
    token_estimate: int
    excerpt: str
    # included|over_budget|excluded_by_user|excluded_sensitive|rejected|missing|unverified|skipped|reference|note
    status: str
    origin: str  # profile|related_file|discovered|record|git|system
    can_include: bool  # whether PATCH may set included=true for this item


class PackCountsOut(BaseModel):
    total: int
    included: int
    verified: int
    unverified: int
    excluded_sensitive: int
    over_budget: int


class ContextPackSummaryOut(BaseModel):
    id: str
    task_id: str | None
    task_key: str | None
    profile: ProfileName
    profile_label: str
    token_budget: int
    token_estimate: int
    over_budget: bool
    counts: PackCountsOut
    repository_verified: bool  # False when no repository was readable when the pack was built
    created_by: str | None
    created_at: datetime
    external_transfer: Literal[False] = False


class ContextPackOut(ContextPackSummaryOut):
    items: list[ContextPackItemOut]
    notes: list[str]


# ----------------------------------------------------------------------------- fix context & prompts


class SectionOut(BaseModel):
    key: str
    title: str
    content: str
    kind: SectionKindName
    kinds: list[SectionKindName]
    sources: list[str]
    required: bool
    edited: bool


class FixContextRequest(Strict):
    task_id: str
    mode: PromptModeName | None = Field(None, description="Defaults to the template's mode, else implement_fix.")
    preset: PresetName | None = Field(None, description="Defaults to the template's preset, else generic.")
    options: dict[str, Any] = Field(default_factory=dict, description="GenerationOptions; overrides the template's.")
    context_pack_id: str | None = None
    profile: ProfileName | None = Field(None, description="Profile for a fresh pack when no context_pack_id is given.")
    template_id: str | None = None
    save: bool = False


class FixContextOut(BaseModel):
    prompt_id: str | None
    saved: bool
    version: int | None
    task_id: str
    task_key: str
    mode: PromptModeName
    mode_label: str
    preset: PresetName
    preset_label: str
    may_modify_files: bool
    options: dict[str, Any]
    template_id: str | None
    sections: list[SectionOut]
    content: str
    token_estimate: int
    sources: list[str]
    context_pack: ContextPackSummaryOut | None  # None only when the pack was not persisted (save=false)
    context_pack_profile: ProfileName
    notes: list[str]
    problems: list[str]
    external_transfer: Literal[False] = False
    privacy_note: str = PRIVACY_NOTE


class PromptSummaryOut(BaseModel):
    id: str
    task_id: str | None
    task_key: str | None
    task_title: str | None
    mode: PromptModeName
    mode_label: str
    preset: PresetName
    preset_label: str
    version: int
    template_id: str | None
    context_pack_id: str | None
    section_count: int
    edited_sections: list[str]
    token_estimate: int
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    external_transfer: Literal[False] = False


class PromptOut(PromptSummaryOut):
    may_modify_files: bool
    options: dict[str, Any]
    sections: list[SectionOut]
    content: str
    sources: list[str]
    problems: list[str]
    notes: list[str] = Field(default_factory=list)
    privacy_note: str = PRIVACY_NOTE


class SectionEdit(Strict):
    key: str = Field(min_length=1, max_length=64)
    content: str | None = Field(None, max_length=200_000)
    removed: bool = False


class PromptPatch(Strict):
    sections: list[SectionEdit] | None = Field(None, max_length=30)
    extra_instructions: str | None = Field(None, max_length=4000)
    options: dict[str, Any] | None = None


class RegenerateSectionIn(Strict):
    section_key: str = Field(min_length=1, max_length=64)


# ----------------------------------------------------------------------------- templates


class TemplateOut(BaseModel):
    id: str
    name: str
    description: str | None
    mode: PromptModeName
    mode_label: str
    preset: PresetName
    preset_label: str
    options: dict[str, Any]
    section_overrides: dict[str, str]
    is_builtin: bool
    created_by: str | None
    created_at: datetime | None
    updated_at: datetime | None


class TemplateCreate(Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    mode: PromptModeName
    preset: PresetName = "generic"
    options: dict[str, Any] = Field(default_factory=dict)
    section_overrides: dict[str, str] = Field(default_factory=dict)


class TemplatePatch(Strict):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    mode: PromptModeName | None = None
    preset: PresetName | None = None
    options: dict[str, Any] | None = None
    section_overrides: dict[str, str] | None = None


# ----------------------------------------------------------------------------- breakdown


class BreakdownIn(Strict):
    task_id: str
    plan: str | None = Field(None, max_length=48, description="Override the automatically chosen plan.")


class SubtaskDraftIn(Strict):
    title: str = Field(min_length=1, max_length=400)
    description: str = Field("", max_length=20_000)
    task_type: TaskTypeName = "task"
    acceptance_criteria: list[str] = Field(default_factory=list, max_length=30)
    testing_requirements: list[str] = Field(default_factory=list, max_length=30)
    depends_on: list[int] = Field(default_factory=list, max_length=MAX_DRAFTS)


class SubtaskDraftOut(BaseModel):
    title: str
    description: str
    task_type: TaskTypeName
    acceptance_criteria: list[str]
    testing_requirements: list[str]
    depends_on: list[int]


class BreakdownOut(BaseModel):
    task_id: str
    task_key: str
    plan: str
    plans: list[str]
    drafts: list[SubtaskDraftOut]
    existing_subtasks: int
    note: str
    external_transfer: Literal[False] = False


class BreakdownApplyIn(Strict):
    task_id: str
    drafts: list[SubtaskDraftIn] = Field(min_length=1, max_length=MAX_DRAFTS)
    priority: PriorityName | None = Field(None, description="Priority for the subtasks; defaults to the parent's.")
    override_wip: bool = False


class CreatedDependencyOut(BaseModel):
    task_id: str
    depends_on_task_id: str


class BreakdownApplyOut(BaseModel):
    parent_task_id: str
    created: list[TaskCardOut]
    dependencies: list[CreatedDependencyOut]


# ----------------------------------------------------------------------------- catalogue


class OptionSpecOut(BaseModel):
    key: str
    label: str
    type: Literal["enum", "boolean", "text", "list"]
    values: list[str] = Field(default_factory=list)
    default: Any
    description: str


class ModesOut(BaseModel):
    modes: list[dict[str, Any]]
    presets: list[dict[str, Any]]
    profiles: list[dict[str, Any]]
    options: list[OptionSpecOut]
    sections: list[dict[str, str]]
    breakdown_plans: list[str]
    repository_configured: bool
    external_transfer: Literal[False] = False
    privacy_note: str = PRIVACY_NOTE
    # Set when the catalogue is requested for a task (``?task_id=``): the context-pack profile the server
    # would pick for that task in the requested mode (default implement_fix), and for every mode.
    task_id: str | None = None
    mode: PromptModeName | None = None
    suggested_profile: ProfileName | None = None
    suggested_profiles: dict[str, ProfileName] = Field(default_factory=dict)
