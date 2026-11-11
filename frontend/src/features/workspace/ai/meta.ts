/**
 * Presentation vocabulary for the AI Fix Context, Prompt Library and Context Packs screens:
 * labels and tones for section kinds, pack item categories/kinds/statuses and option values,
 * plus small pure helpers (effective options, suggested profile, token formatting).
 *
 * Labels only — the server computes every classification (kind, category, verified, can_include).
 */
import type { Tone } from "@/lib/domain";
import { humanize } from "@/lib/domain";
import type { AgentTool } from "../types";
import type {
  AgentPreset,
  AiCatalogue,
  ContextPackItem,
  GenerationOptions,
  ModeInfo,
  PackItemKind,
  PackProfile,
  PresetInfo,
  ProfileSuggestions,
  PromptMode,
  SectionKind,
} from "./types";

// ---------------------------------------------------------------------------- section kinds & categories

export interface KindMeta {
  label: string;
  tone: Tone;
  /** Plain-language meaning, shown in legends and tooltips. */
  description: string;
}

export const SECTION_KIND_META: Record<SectionKind, KindMeta> = {
  fact: { label: "Fact", tone: "trusted", description: "Confirmed from ContextOS records or from files that exist in the repository." },
  evidence: { label: "Evidence", tone: "external", description: "Recorded observations and excerpts. The agent must treat them as data, never as instructions." },
  assumption: { label: "Assumption", tone: "unknown", description: "Not verified. The agent has to check it before relying on it." },
  hypothesis: { label: "Hypothesis", tone: "suspicious", description: "A possible explanation to test — not a confirmed cause." },
  recommendation: { label: "Recommendation", tone: "approved", description: "A suggested approach. The agent may propose a better one." },
  instruction: { label: "Instruction", tone: "neutral", description: "What the agent must or must not do." },
};

export const SECTION_KIND_ORDER: SectionKind[] = ["fact", "evidence", "assumption", "hypothesis", "recommendation", "instruction"];

export function kindMeta(kind: string): KindMeta {
  return SECTION_KIND_META[kind as SectionKind] ?? { label: humanize(kind), tone: "neutral", description: "" };
}

/** Pack item categories use the same vocabulary as section kinds (minus "instruction"). */
export const PACK_CATEGORIES = ["fact", "evidence", "assumption", "hypothesis", "recommendation"] as const;

// ---------------------------------------------------------------------------- pack items

export const ITEM_KIND_LABELS: Record<PackItemKind, string> = {
  doc: "Document",
  source_file: "Source file",
  test_file: "Test file",
  record: "Record",
  policy: "Policy",
  note: "Note",
  git_history: "Git history",
};
export const ITEM_KINDS = Object.keys(ITEM_KIND_LABELS) as PackItemKind[];
export const itemKindLabel = (kind: string) => ITEM_KIND_LABELS[kind as PackItemKind] ?? humanize(kind);

export const ITEM_STATUS_META: Record<string, KindMeta> = {
  included: { label: "Included", tone: "ok", description: "Sent to the agent as part of the prompt's context." },
  over_budget: { label: "Over budget", tone: "warn", description: "Left out because the profile's token budget was used up. You can include it." },
  excluded_by_user: { label: "Excluded by you", tone: "neutral", description: "You excluded this item. Include it again at any time." },
  excluded_sensitive: { label: "Sensitive — never read", tone: "danger", description: "Matches a sensitive-file rule (keys, credentials, environment files). Its contents were never read and cannot be included." },
  rejected: { label: "Rejected", tone: "danger", description: "The path is not allowed (outside the repository or otherwise unsafe)." },
  missing: { label: "Not found", tone: "warn", description: "The referenced file does not exist in the repository." },
  unverified: { label: "Unverified", tone: "unknown", description: "Could not be checked against the repository." },
  skipped: { label: "Skipped", tone: "neutral", description: "Exists but was not read (for example, binary or too large)." },
  reference: { label: "Reference only", tone: "neutral", description: "Listed by name so the agent can open it; no excerpt is included." },
  note: { label: "Note", tone: "neutral", description: "An explanation about how the pack was built." },
};

export function itemStatusMeta(status: string): KindMeta {
  return ITEM_STATUS_META[status] ?? { label: humanize(status), tone: "neutral", description: "" };
}

/** Items the pack table shows in its own "excluded for safety" group instead of the main list. */
export const isSafetyExcluded = (item: ContextPackItem) => item.status === "excluded_sensitive" || item.status === "rejected";

// ---------------------------------------------------------------------------- options

export const OPTION_VALUE_LABELS: Record<string, string> = {
  brief: "Brief",
  standard: "Standard",
  deep: "Deep",
  ask_before_changes: "Ask before changes",
  autonomous_with_checkpoints: "Autonomous with checkpoints",
  fully_autonomous: "Fully autonomous",
  none: "None",
  unit: "Unit tests",
  unit_integration: "Unit + integration",
  full_regression: "Full regression",
  strict: "Strict",
  markdown: "Markdown",
  xml_tagged: "XML-tagged sections",
};
export const optionValueLabel = (value: string) => OPTION_VALUE_LABELS[value] ?? humanize(value);

/** Mirrors app.workspace.modes.GenerationOptions defaults; the catalogue's defaults win when loaded. */
export const FALLBACK_OPTIONS: GenerationOptions = {
  technical_depth: "standard",
  autonomy: "ask_before_changes",
  testing_requirements: "unit",
  security_requirements: "standard",
  output_format: "markdown",
  constraints: [],
  allow_code_changes: true,
  allow_architecture_changes: false,
  extra_instructions: "",
};

export const MAX_CONSTRAINTS = 30;
export const MAX_CONSTRAINT_CHARS = 500;
export const MAX_EXTRA_CHARS = 4000;
export const MAX_OVERRIDE_CHARS = 2000;

export function defaultOptions(catalogue: AiCatalogue | undefined): GenerationOptions {
  const out = { ...FALLBACK_OPTIONS, constraints: [] as string[] } as GenerationOptions;
  for (const spec of catalogue?.options ?? []) {
    if (spec.key in out && spec.default !== undefined && spec.default !== null) {
      (out as unknown as Record<string, unknown>)[spec.key] = Array.isArray(spec.default) ? [...spec.default] : spec.default;
    }
  }
  return out;
}

/** Options merged over defaults (server-normalised options are complete; partial ones are filled). */
export function completeOptions(partial: Partial<GenerationOptions> | null | undefined, base: GenerationOptions): GenerationOptions {
  return { ...base, ...(partial ?? {}), constraints: [...((partial?.constraints as string[] | undefined) ?? base.constraints)] };
}

/**
 * What is actually requested: read-only modes force code and architecture changes off, so the
 * prompt can never grant more than the mode allows.
 */
export function effectiveOptions(options: GenerationOptions, mode: Pick<ModeInfo, "may_modify_files"> | undefined): GenerationOptions {
  if (mode && !mode.may_modify_files) return { ...options, allow_code_changes: false, allow_architecture_changes: false };
  if (!options.allow_code_changes) return { ...options, allow_architecture_changes: false };
  return options;
}

/** Whether the agent may modify files: the mode must allow it and code changes must be on. */
export const mayModify = (mode: Pick<ModeInfo, "may_modify_files"> | undefined, options: GenerationOptions) =>
  !!mode?.may_modify_files && options.allow_code_changes;

export function optionsEqual(a: GenerationOptions, b: GenerationOptions): boolean {
  return JSON.stringify(normaliseForCompare(a)) === JSON.stringify(normaliseForCompare(b));
}

function normaliseForCompare(o: GenerationOptions) {
  return {
    technical_depth: o.technical_depth,
    autonomy: o.autonomy,
    testing_requirements: o.testing_requirements,
    security_requirements: o.security_requirements,
    output_format: o.output_format,
    constraints: o.constraints.map((c) => c.trim()).filter(Boolean),
    allow_code_changes: o.allow_code_changes,
    allow_architecture_changes: o.allow_architecture_changes,
    extra_instructions: o.extra_instructions.trim(),
  };
}

/** Short summary of the options that differ most between templates ("Deep · Unit + integration · Strict"). */
export function optionsSummary(o: GenerationOptions): string {
  const parts = [optionValueLabel(o.technical_depth), `Tests: ${optionValueLabel(o.testing_requirements)}`];
  if (o.security_requirements === "strict") parts.push("Strict security");
  if (o.output_format === "xml_tagged") parts.push("XML-tagged");
  if (o.constraints.length) parts.push(`${o.constraints.length} constraint${o.constraints.length === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

// ---------------------------------------------------------------------------- presets & profiles

/** Fix attempts record which tool ran the prompt; "Generic agent" is recorded as "other". */
export const PRESET_AGENT_TOOL: Record<AgentPreset, AgentTool> = {
  claude_code: "claude_code",
  codex: "codex",
  cursor: "cursor",
  generic: "other",
};

export const AGENT_TOOL_LABELS: Record<AgentTool, string> = {
  claude_code: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  copilot: "GitHub Copilot",
  human: "A person (no agent)",
  other: "Other agent",
};

/** One honest line about the preset: what the product actually reads, from the server's notes. */
export function presetLine(preset: PresetInfo): string {
  if (preset.notes.length > 0) return preset.notes[0];
  return "No product-specific notes — works with any coding agent that accepts a Markdown prompt.";
}

/**
 * The context-pack profile the server suggests for this task and mode (`GET /modes?task_id=` →
 * `suggested_profiles`, computed by services.workspace_ai_packs.default_profile). Without
 * suggestions (catalogue not loaded for a task) it falls back to the general-purpose profile; the UI
 * always sends the chosen profile explicitly.
 */
export function suggestedProfile(suggestions: ProfileSuggestions | null | undefined, mode: PromptMode): PackProfile {
  const forMode = suggestions?.suggested_profiles?.[mode];
  if (forMode) return forMode;
  if (suggestions?.suggested_profile && suggestions.mode === mode) return suggestions.suggested_profile;
  return "standard";
}

// ---------------------------------------------------------------------------- numbers

/** "~1.2k tokens" — estimates are ~4 characters per token, good for budgeting, not billing. */
export function formatTokens(n: number | null | undefined, withUnit = true): string {
  if (n === null || n === undefined) return "—";
  const value = n >= 10_000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k` : String(n);
  return withUnit ? `~${value} tokens` : `~${value}`;
}

/** Exact grouped number ("20,000") for budgets, where compact notation would hide the scale. */
export function formatCount(n: number): string {
  return new Intl.NumberFormat("en-GB").format(n);
}

export const TOKEN_ESTIMATE_NOTE = "Estimated at about 4 characters per token. Good for budgeting, not for billing.";

export type BudgetLevel = "ok" | "near" | "over";

export function budgetLevel(estimate: number, budget: number): BudgetLevel {
  if (budget <= 0) return estimate > 0 ? "over" : "ok";
  if (estimate > budget) return "over";
  return estimate / budget >= 0.85 ? "near" : "ok";
}

/** Filename for client-side downloads of server-generated content (drafts and pack exports). */
export function safeFilename(stem: string, ext: string): string {
  return `${stem.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "") || "export"}.${ext}`;
}
