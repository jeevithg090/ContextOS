/**
 * Engineering Workspace AI types — context packs, fix-context prompts, prompt templates, breakdown.
 *
 * Mirrors backend/app/schemas/workspace_ai.py. Field names and literal unions are the contract.
 *
 * Honesty rules the types carry:
 * - Everything is generated on the ContextOS server; `external_transfer` is always `false` and the UI
 *   must say that nothing was sent to an external AI provider (`privacy_note`).
 * - Only context-pack items with `verified: true` were confirmed to exist in the repository. Sensitive
 *   files appear with status `excluded_sensitive`, an empty excerpt and `can_include: false`.
 * - Section `kind` separates facts and evidence from assumptions, hypotheses and instructions.
 */
import type { TaskCard, TaskPriority, TaskType } from "../types";

// ---------------------------------------------------------------------------- vocabulary

export const PROMPT_MODES = [
  "investigate_only",
  "root_cause_analysis",
  "implementation_plan",
  "implement_fix",
  "security_harden",
  "refactor",
  "test_and_verify",
  "full_autonomous_remediation",
] as const;
export type PromptMode = (typeof PROMPT_MODES)[number];

export const AGENT_PRESETS = ["claude_code", "codex", "cursor", "generic"] as const;
export type AgentPreset = (typeof AGENT_PRESETS)[number];

export const PACK_PROFILES = ["minimal", "standard", "deep", "security_critical", "full"] as const;
export type PackProfile = (typeof PACK_PROFILES)[number];

export type SectionKind = "fact" | "evidence" | "assumption" | "hypothesis" | "recommendation" | "instruction";
export type PackItemKind = "doc" | "source_file" | "test_file" | "record" | "policy" | "note" | "git_history";
export type PackItemStatus =
  | "included"
  | "over_budget"
  | "excluded_by_user"
  | "excluded_sensitive"
  | "rejected"
  | "missing"
  | "unverified"
  | "skipped"
  | "reference"
  | "note";
export type ExportFormat = "markdown" | "json";

export type TechnicalDepth = "brief" | "standard" | "deep";
export type Autonomy = "ask_before_changes" | "autonomous_with_checkpoints" | "fully_autonomous";
export type RequiredTesting = "none" | "unit" | "unit_integration" | "full_regression";
export type SecurityLevel = "standard" | "strict";
export type OutputFormat = "markdown" | "xml_tagged";

/** Normalised generation options as stored on prompts and templates (server fills every field). */
export interface GenerationOptions {
  technical_depth: TechnicalDepth;
  autonomy: Autonomy;
  testing_requirements: RequiredTesting;
  security_requirements: SecurityLevel;
  output_format: OutputFormat;
  constraints: string[];
  allow_code_changes: boolean;
  allow_architecture_changes: boolean;
  extra_instructions: string;
}

// ---------------------------------------------------------------------------- catalogue (GET /modes)

export interface ModeInfo {
  key: PromptMode;
  label: string;
  description: string;
  may_modify_files: boolean;
  required_sections: string[];
  instructions: string[];
  deliverable: string;
}

export interface PresetInfo {
  key: AgentPreset;
  label: string;
  instruction_file: string | null;
  notes: string[];
}

export interface ProfileInfo {
  key: PackProfile;
  label: string;
  description: string;
  token_budget: number;
  documents: string[];
  includes_tests: boolean;
  includes_git_history: boolean;
}

export interface OptionSpec {
  key: keyof GenerationOptions;
  label: string;
  type: "enum" | "boolean" | "text" | "list";
  values: string[];
  default: unknown;
  description: string;
}

export interface SectionInfo {
  key: string;
  title: string;
}

export interface AiCatalogue {
  modes: ModeInfo[];
  presets: PresetInfo[];
  profiles: ProfileInfo[];
  options: OptionSpec[];
  sections: SectionInfo[];
  breakdown_plans: string[];
  /** Whether the server has a repository root to verify file references against. */
  repository_configured: boolean;
  external_transfer: false;
  privacy_note: string;
  /** Set when the catalogue was requested for a task (`GET /modes?task_id=`). */
  task_id?: string | null;
  /** The mode `suggested_profile` was computed for (implement_fix unless `?mode=` was sent). */
  mode?: PromptMode | null;
  /** The context-pack profile the server would pick for that task in `mode`. */
  suggested_profile?: PackProfile | null;
  /** The profile the server would pick for that task in every mode. */
  suggested_profiles?: Partial<Record<PromptMode, PackProfile>>;
}

/** The server's profile suggestions for one task (from the task-scoped catalogue). */
export type ProfileSuggestions = Pick<AiCatalogue, "mode" | "suggested_profile" | "suggested_profiles">;

// ---------------------------------------------------------------------------- context packs

export interface ContextPackItem {
  key: string;
  kind: PackItemKind;
  ref: string;
  title: string;
  category: string;
  reason: string;
  verified: boolean;
  included: boolean;
  token_estimate: number;
  excerpt: string;
  status: PackItemStatus | string;
  origin: "profile" | "related_file" | "discovered" | "record" | "git" | "system" | string;
  /** Whether PATCH may set `included: true` (never for sensitive, rejected, missing or unverified items). */
  can_include: boolean;
}

export interface PackCounts {
  total: number;
  included: number;
  verified: number;
  unverified: number;
  excluded_sensitive: number;
  over_budget: number;
}

export interface ContextPackSummary {
  id: string;
  task_id: string | null;
  task_key: string | null;
  profile: PackProfile;
  profile_label: string;
  token_budget: number;
  token_estimate: number;
  over_budget: boolean;
  counts: PackCounts;
  /** False when no repository was readable when the pack was built (only records are verified). */
  repository_verified: boolean;
  created_by: string | null;
  created_at: string;
  external_transfer: false;
}

export interface ContextPack extends ContextPackSummary {
  items: ContextPackItem[];
  notes: string[];
}

export interface ContextPackCreateInput {
  task_id: string;
  profile?: PackProfile;
  extra_paths?: string[];
}

export interface PackItemToggle {
  key: string;
  included: boolean;
}

// ---------------------------------------------------------------------------- prompts

export interface PromptSection {
  key: string;
  title: string;
  content: string;
  kind: SectionKind;
  kinds: SectionKind[];
  sources: string[];
  required: boolean;
  edited: boolean;
}

export interface FixContextInput {
  task_id: string;
  mode?: PromptMode;
  preset?: AgentPreset;
  options?: Partial<GenerationOptions>;
  context_pack_id?: string;
  /** Profile for a fresh pack when no `context_pack_id` is given. */
  profile?: PackProfile;
  template_id?: string;
  /** Store the prompt (and the pack it used). Requires `write`; the server answers 201. */
  save?: boolean;
}

export interface FixContextResult {
  prompt_id: string | null;
  saved: boolean;
  version: number | null;
  task_id: string;
  task_key: string;
  mode: PromptMode;
  mode_label: string;
  preset: AgentPreset;
  preset_label: string;
  may_modify_files: boolean;
  options: GenerationOptions;
  template_id: string | null;
  sections: PromptSection[];
  content: string;
  token_estimate: number;
  sources: string[];
  /** Null when the prompt was not saved (the pack used was not persisted). */
  context_pack: ContextPackSummary | null;
  context_pack_profile: PackProfile;
  notes: string[];
  problems: string[];
  external_transfer: false;
  privacy_note: string;
}

export interface PromptSummary {
  id: string;
  task_id: string | null;
  task_key: string | null;
  task_title: string | null;
  mode: PromptMode;
  mode_label: string;
  preset: AgentPreset;
  preset_label: string;
  version: number;
  template_id: string | null;
  context_pack_id: string | null;
  section_count: number;
  edited_sections: string[];
  token_estimate: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  external_transfer: false;
}

export interface SavedPrompt extends PromptSummary {
  may_modify_files: boolean;
  options: GenerationOptions;
  sections: PromptSection[];
  content: string;
  sources: string[];
  problems: string[];
  /** Plain-language notes from the last edit/regeneration (e.g. deleted template or pack). */
  notes: string[];
  privacy_note: string;
}

export interface SectionEdit {
  key: string;
  content?: string;
  removed?: boolean;
}

export interface PromptPatch {
  sections?: SectionEdit[];
  extra_instructions?: string;
  options?: Partial<GenerationOptions>;
}

// ---------------------------------------------------------------------------- templates

export interface PromptTemplate {
  /** `builtin:<mode>` for built-in templates. */
  id: string;
  name: string;
  description: string | null;
  mode: PromptMode;
  mode_label: string;
  preset: AgentPreset;
  preset_label: string;
  options: GenerationOptions;
  /** Extra instructions appended to a section, keyed by section key. */
  section_overrides: Record<string, string>;
  is_builtin: boolean;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface TemplateInput {
  name: string;
  description?: string | null;
  mode: PromptMode;
  preset?: AgentPreset;
  options?: Partial<GenerationOptions>;
  section_overrides?: Record<string, string>;
}

export type TemplatePatch = Partial<TemplateInput>;

// ---------------------------------------------------------------------------- breakdown

export interface SubtaskDraft {
  title: string;
  description: string;
  task_type: TaskType;
  acceptance_criteria: string[];
  testing_requirements: string[];
  /** Indexes of other drafts this one depends on ("blocks"). Must form an acyclic graph. */
  depends_on: number[];
}

export interface BreakdownResult {
  task_id: string;
  task_key: string;
  plan: string;
  plans: string[];
  drafts: SubtaskDraft[];
  existing_subtasks: number;
  note: string;
  external_transfer: false;
}

export interface BreakdownApplyInput {
  task_id: string;
  drafts: SubtaskDraft[];
  priority?: TaskPriority;
  override_wip?: boolean;
}

export interface BreakdownApplyResult {
  parent_task_id: string;
  created: TaskCard[];
  dependencies: Array<{ task_id: string; depends_on_task_id: string }>;
}
