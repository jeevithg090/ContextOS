/** Test fixtures shaped exactly like the workspace AI API responses (backend/app/schemas/workspace_ai.py). */
import type { TaskDetail } from "../../types";
import type { AiCatalogue, ContextPack, FixContextResult, GenerationOptions, PromptSection, PromptTemplate, SavedPrompt } from "../types";

export const OPTIONS: GenerationOptions = {
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

const mode = (key: string, label: string, may: boolean) => ({ key, label, description: `${label} description.`, may_modify_files: may, required_sections: ["task_summary"], instructions: [], deliverable: `${label} deliverable.` });

export const CATALOGUE: AiCatalogue = {
  modes: [
    mode("investigate_only", "Investigate only", false),
    mode("root_cause_analysis", "Root cause analysis", false),
    mode("implementation_plan", "Implementation plan", false),
    mode("implement_fix", "Implement fix", true),
    mode("security_harden", "Security hardening", true),
    mode("refactor", "Refactor", true),
    mode("test_and_verify", "Test and verify", true),
    mode("full_autonomous_remediation", "Full autonomous remediation", true),
  ] as AiCatalogue["modes"],
  presets: [
    { key: "claude_code", label: "Claude Code", instruction_file: "CLAUDE.md", notes: ["Claude Code loads `CLAUDE.md` memory files from the repository automatically."] },
    { key: "codex", label: "Codex", instruction_file: "AGENTS.md", notes: ["Codex reads `AGENTS.md` files in the repository."] },
    { key: "cursor", label: "Cursor", instruction_file: ".cursor/rules", notes: ["Cursor applies project rules from `.cursor/rules`."] },
    { key: "generic", label: "Generic agent", instruction_file: null, notes: [] },
  ],
  profiles: [
    { key: "minimal", label: "Minimal", description: "Minimal.", token_budget: 2000, documents: [], includes_tests: false, includes_git_history: false },
    { key: "standard", label: "Standard", description: "Instructions, architecture, related files and their tests.", token_budget: 8000, documents: [], includes_tests: true, includes_git_history: true },
    { key: "deep", label: "Deep", description: "Deep.", token_budget: 20000, documents: [], includes_tests: true, includes_git_history: true },
    { key: "security_critical", label: "Security critical", description: "Security first.", token_budget: 24000, documents: [], includes_tests: true, includes_git_history: true },
    { key: "full", label: "Full", description: "Full.", token_budget: 60000, documents: [], includes_tests: true, includes_git_history: true },
  ],
  options: [
    { key: "technical_depth", label: "Technical depth", type: "enum", values: ["brief", "standard", "deep"], default: "standard", description: "How much evidence." },
    { key: "testing_requirements", label: "Required testing", type: "enum", values: ["none", "unit", "unit_integration", "full_regression"], default: "unit", description: "Which tests." },
    { key: "allow_code_changes", label: "Allow code changes", type: "boolean", values: [], default: true, description: "Turn off to make any mode read-only." },
  ],
  sections: [
    { key: "task_summary", title: "Task summary" },
    { key: "available_evidence", title: "Available evidence" },
    { key: "root_cause_hypotheses", title: "Root-cause hypotheses" },
    { key: "related_documentation", title: "Related documentation" },
  ],
  breakdown_plans: [],
  repository_configured: true,
  external_transfer: false,
  privacy_note: "Generated on the ContextOS server from records in your organisation.",
};

export const TASK: TaskDetail = {
  id: "tsk_1", key: "CTX-12", number: 12, board_id: "brd_1", column_id: "col_1", column_name: "In Progress", status_key: "in_progress",
  is_done: false, position: 0, title: "Redact bearer tokens in webhook logs", task_type: "backend", priority: "high", severity: null,
  labels: [], assignees: [], due_date: null, is_overdue: false, parent_task_id: null, subtasks_total: 0, subtasks_done: 0, blocked_by_open: 0,
  verification_status: "unverified", related_finding_id: null, related_incident_id: null, related_agent_id: null,
  created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-10T00:00:00Z", completed_at: null, archived_at: null,
  board_name: "Engineering", column: { id: "col_1", board_id: "brd_1", name: "In Progress", description: null, color: "accent", position: 1, wip_limit: null, status_key: "in_progress", is_done_column: false, requires_verification: false, automation: [], task_count: 1, wip_exceeded: false },
  description: "Tokens leak into logs.", reporter: null, related_files: ["backend/app/services/webhooks.py"], reproduction_steps: "", expected_behaviour: "", actual_behaviour: "",
  acceptance_criteria: [], resolution: null, verified_at: null, reopened_count: 0, parent: null, subtasks: [], blocked_by: [], blocking: [], comments: [], refs: [],
  attachments: [], links: { branch: [], commit: [], pull_request: [], deployment: [] }, fix_attempts: [], verification_runs: [], activity: [], generated_prompt_ids: [],
};

export const SECTIONS: PromptSection[] = [
  { key: "task_summary", title: "Task summary", content: "Redact bearer tokens before logging.", kind: "fact", kinds: ["fact"], sources: ["task:tsk_1"], required: true, edited: false },
  { key: "root_cause_hypotheses", title: "Root-cause hypotheses", content: "1. The logger receives raw headers.", kind: "hypothesis", kinds: ["hypothesis"], sources: [], required: false, edited: false },
];

export const PACK: ContextPack = {
  id: "cpk_1", task_id: "tsk_1", task_key: "CTX-12", profile: "standard", profile_label: "Standard", token_budget: 8000, token_estimate: 1200, over_budget: false,
  counts: { total: 3, included: 1, verified: 2, unverified: 0, excluded_sensitive: 1, over_budget: 1 },
  repository_verified: true, created_by: "usr_1", created_at: "2026-11-10T10:00:00Z", external_transfer: false, notes: [],
  items: [
    { key: "source_file:backend/app/services/webhooks.py", kind: "source_file", ref: "backend/app/services/webhooks.py", title: "webhooks.py", category: "fact", reason: "Listed as a related file on the task.", verified: true, included: true, token_estimate: 1200, excerpt: "def send(): ...", status: "included", origin: "related_file", can_include: true },
    { key: "doc:docs/DATA_MODEL.md", kind: "doc", ref: "docs/DATA_MODEL.md", title: "Data model", category: "fact", reason: "Supporting document.", verified: true, included: false, token_estimate: 0, excerpt: "", status: "over_budget", origin: "profile", can_include: true },
    { key: "source_file:.env", kind: "source_file", ref: ".env", title: ".env", category: "assumption", reason: "Excluded: environment file. Sensitive files are never read.", verified: false, included: false, token_estimate: 0, excerpt: "", status: "excluded_sensitive", origin: "related_file", can_include: false },
  ],
};

export const DRAFT: FixContextResult = {
  prompt_id: null, saved: false, version: null, task_id: "tsk_1", task_key: "CTX-12", mode: "implement_fix", mode_label: "Implement fix", preset: "generic", preset_label: "Generic agent",
  may_modify_files: true, options: OPTIONS, template_id: null, sections: SECTIONS, content: "# CTX-12: Redact bearer tokens — Implement fix\n\n## Task summary\n\nRedact bearer tokens before logging.\n",
  token_estimate: 40, sources: ["task:tsk_1"], context_pack: null, context_pack_profile: "standard", notes: [], problems: [], external_transfer: false, privacy_note: CATALOGUE.privacy_note,
};

export const SAVED: SavedPrompt = {
  id: "gpr_1", task_id: "tsk_1", task_key: "CTX-12", task_title: TASK.title, mode: "implement_fix", mode_label: "Implement fix", preset: "generic", preset_label: "Generic agent",
  version: 1, template_id: null, context_pack_id: "cpk_1", section_count: 2, edited_sections: [], token_estimate: 40, created_by: "usr_1",
  created_at: "2026-11-10T10:00:00Z", updated_at: "2026-11-10T10:00:00Z", external_transfer: false, may_modify_files: true, options: OPTIONS,
  sections: SECTIONS, content: DRAFT.content, sources: ["task:tsk_1"], problems: [], notes: [], privacy_note: CATALOGUE.privacy_note,
};

export const TEMPLATES: PromptTemplate[] = [
  { id: "builtin:investigate_only", name: "Investigate only", description: "Read-only investigation.", mode: "investigate_only", mode_label: "Investigate only", preset: "generic", preset_label: "Generic agent", options: OPTIONS, section_overrides: {}, is_builtin: true, created_by: null, created_at: null, updated_at: null },
  { id: "pt_1", name: "Strict security fix", description: "For security tasks.", mode: "security_harden", mode_label: "Security hardening", preset: "claude_code", preset_label: "Claude Code", options: { ...OPTIONS, security_requirements: "strict" }, section_overrides: { task_summary: "Mention the CVE." }, is_builtin: false, created_by: "usr_1", created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-02T00:00:00Z" },
];

export const page = <T,>(items: T[]) => ({ items, total: items.length, limit: 50, offset: 0 });
