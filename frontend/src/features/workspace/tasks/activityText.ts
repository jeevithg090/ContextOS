/**
 * Plain-language descriptions of task activity entries ("who changed what"). Pure, so the wording
 * is unit-tested. Values come from the server already redacted and truncated.
 */
import { humanize, type Tone } from "@/lib/domain";
import { PRIORITY_META, TASK_TYPE_LABELS } from "../analytics/taskMeta";
import type { TaskActivity, TaskPriority, TaskType } from "../types";

const FIELD_LABELS: Record<string, string> = {
  title: "title",
  description: "description",
  task_type: "type",
  priority: "priority",
  severity: "severity",
  due_date: "due date",
  parent_task_id: "parent task",
  related_agent_id: "related agent",
  related_incident_id: "related incident",
  related_finding_id: "related finding",
  related_files: "related files",
  reproduction_steps: "reproduction steps",
  expected_behaviour: "expected behaviour",
  actual_behaviour: "actual behaviour",
  acceptance_criteria: "acceptance criteria",
  resolution: "resolution",
};

/** Fields whose before/after values are long text: say that they changed, not what to. */
const LONG_FIELDS = new Set(["description", "reproduction_steps", "expected_behaviour", "actual_behaviour", "acceptance_criteria", "related_files", "resolution"]);

function fieldValue(field: string, value: string | null): string {
  if (value === null || value === "") return "none";
  if (field === "priority") return PRIORITY_META[value as TaskPriority]?.label ?? value;
  if (field === "task_type") return TASK_TYPE_LABELS[value as TaskType] ?? value;
  if (field === "severity") return humanize(value);
  if (field === "due_date") {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
  }
  return value;
}

const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const quote = (v: string | null) => (v ? `“${v}”` : "");

export interface ActivityText {
  text: string;
  tone: Tone;
  /** Extra context shown under the entry (e.g. why automation was skipped). */
  note?: string;
}

/** Describe an activity entry. The actor's name is shown separately (null actor = ContextOS automation). */
export function describeActivity(a: Pick<TaskActivity, "kind" | "from_value" | "to_value" | "details">): ActivityText {
  const d = a.details ?? {};
  const from = a.from_value;
  const to = a.to_value;
  switch (a.kind) {
    case "created":
      return { text: `created the task in ${quote(to)}`.trim(), tone: "accent" };
    case "created_from_finding":
      return { text: `created the task from the finding ${quote(to)}`.trim(), tone: "accent" };
    case "updated": {
      const field = typeof d.field === "string" ? d.field : "";
      const label = FIELD_LABELS[field] ?? humanize(field).toLowerCase();
      if (LONG_FIELDS.has(field)) return { text: `edited the ${label}`, tone: "neutral" };
      return { text: `changed the ${label} from ${fieldValue(field, from)} to ${fieldValue(field, to)}`, tone: "neutral" };
    }
    case "moved": {
      const note = d.reason === "column_deleted" ? "Moved because its column was deleted." : d.wip_override ? "The column's WIP limit was explicitly overridden." : undefined;
      return { text: `moved the task from ${quote(from) || "nowhere"} to ${quote(to)}`, tone: d.wip_override ? "warn" : "neutral", note };
    }
    case "automation":
      return { text: `moved the task from ${quote(from)} to ${quote(to)} by an automation rule`, tone: "accent", note: typeof d.trigger === "string" ? `Trigger: ${humanize(d.trigger).toLowerCase()}.` : undefined };
    case "automation_skipped":
      return { text: `skipped an automation rule in ${quote(from)}`, tone: "warn", note: typeof d.reason === "string" ? d.reason : undefined };
    case "archived":
      return { text: "archived the task", tone: "neutral" };
    case "restored":
      return { text: "restored the task", tone: "neutral" };
    case "labels_changed": {
      const named = (verb: string, names: string[]) => (names.length ? `${verb} ${names.length === 1 ? "label" : "labels"} ${names.map((n) => `“${n}”`).join(", ")}` : "");
      const parts = [named("added", list(d.added)), named("removed", list(d.removed))].filter(Boolean);
      return { text: parts.join(" and ") || "changed labels", tone: "neutral" };
    }
    case "assignees_changed": {
      const added = list(d.added);
      const removed = list(d.removed);
      const parts = [added.length ? `assigned ${added.join(", ")}` : "", removed.length ? `unassigned ${removed.join(", ")}` : ""].filter(Boolean);
      return { text: parts.join(" and ") || "changed assignee roles", tone: "neutral" };
    }
    case "commented":
      return { text: "commented", tone: "neutral" };
    case "comment_edited":
      return { text: "edited a comment", tone: "neutral" };
    case "comment_deleted":
      return { text: "deleted a comment", tone: "neutral" };
    case "dependency_added":
      return { text: `added a dependency on ${to ?? "another task"}`, tone: "neutral" };
    case "dependency_removed":
      return { text: `removed the dependency on ${from ?? "a task"}`, tone: "neutral" };
    case "reference_added":
      return { text: `linked security context ${quote(to)}`.trim(), tone: "accent" };
    case "reference_removed":
      return { text: `removed security context ${quote(from)}`.trim(), tone: "neutral" };
    case "attachment_added":
      return { text: `attached ${quote(to)}`.trim(), tone: "neutral" };
    case "attachment_removed":
      return { text: `removed the attachment ${quote(from)}`.trim(), tone: "neutral" };
    case "linked":
      return { text: `linked ${typeof d.kind === "string" ? humanize(d.kind).toLowerCase() : "work"} ${quote(to)}`.trim(), tone: "neutral" };
    case "unlinked":
      return { text: `removed the link ${quote(from)}`.trim(), tone: "neutral" };
    case "fix_attempt_created":
      return { text: `started a fix attempt (${humanize(to).toLowerCase()})`, tone: "accent" };
    case "fix_attempt_updated": {
      const claim = to === "claimed_complete";
      return {
        text: `changed a fix attempt from ${humanize(from).toLowerCase()} to ${humanize(to).toLowerCase()}`,
        tone: claim ? "warn" : "neutral",
        note: claim ? "Claimed complete is a claim, not verification." : undefined,
      };
    }
    case "verification": {
      const kind = typeof d.kind === "string" ? humanize(d.kind).toLowerCase() : "verification";
      const status = typeof d.run_status === "string" ? d.run_status : to;
      const tone: Tone = status === "passed" ? "ok" : status === "failed" || status === "error" ? "danger" : "warn";
      return { text: `recorded a verification run (${kind}) that ${status === "pending" ? "is pending" : status === "error" ? "errored" : status}`, tone, note: from !== to ? `Verification status: ${humanize(from)} → ${humanize(to)}.` : undefined };
    }
    case "verification_regressed":
      return { text: "verification regressed from passed to failed", tone: "danger", note: typeof d.note === "string" ? d.note : undefined };
    case "breakdown_applied":
      return { text: `broke the task down into ${to ?? "subtasks"}`, tone: "accent" };
    case "context_pack_created":
      return { text: `built a ${to ?? ""} context pack`.replace("  ", " "), tone: "neutral" };
    case "context_pack_deleted":
      return { text: "deleted a context pack", tone: "neutral" };
    case "prompt_generated":
      return { text: `generated a fix-context prompt ${quote(to)}`.trim(), tone: "accent" };
    case "prompt_edited":
      return { text: `edited a fix-context prompt (now ${to ?? "a new version"})`, tone: "neutral" };
    case "prompt_section_regenerated":
      return { text: `regenerated a prompt section${typeof d.section === "string" ? ` (${humanize(d.section).toLowerCase()})` : ""}`, tone: "neutral" };
    default:
      return { text: humanize(a.kind).toLowerCase(), tone: "neutral" };
  }
}
