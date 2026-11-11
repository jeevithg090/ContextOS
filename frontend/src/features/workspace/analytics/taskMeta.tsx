/**
 * Presentation for task fields shared by My Work, All Tasks, Remediation and Analytics:
 * labels for task types / priorities / status keys and the small badges built from them.
 */
import { Link } from "react-router-dom";
import { CalendarClock } from "lucide-react";
import { format, isPast } from "date-fns";
import { Badge, StatusBadge, Tooltip } from "@/components/ui";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";
import type { Assignee, Label, StatusKey, TaskCard, TaskPriority, TaskType } from "../types";
import type { RemediationState } from "./types";

export const PRIORITY_META: Record<TaskPriority, { label: string; tone: Tone }> = {
  urgent: { label: "Urgent", tone: "critical" },
  high: { label: "High", tone: "high" },
  medium: { label: "Medium", tone: "medium" },
  low: { label: "Low", tone: "low" },
  none: { label: "No priority", tone: "neutral" },
};

export const TASK_TYPE_LABELS: Record<TaskType, string> = {
  security_vulnerability: "Security vulnerability",
  prompt_injection: "Prompt injection",
  agent_misconfiguration: "Agent misconfiguration",
  data_exposure: "Data exposure",
  integration_bug: "Integration bug",
  backend: "Backend",
  frontend: "Frontend",
  performance: "Performance",
  feature: "Feature",
  tech_debt: "Tech debt",
  task: "Task",
};

export const STATUS_KEY_LABELS: Record<StatusKey, string> = {
  backlog: "Backlog",
  todo: "To do",
  investigating: "Investigating",
  ready: "Ready",
  in_progress: "In progress",
  review: "Review",
  testing: "Testing",
  verified: "Verified",
  done: "Done",
};

export const REMEDIATION_META: Record<RemediationState, { label: string; tone: Tone; description: string }> = {
  no_task: { label: "No task", tone: "danger", description: "No remediation task tracks this finding yet." },
  task_open: { label: "In progress", tone: "accent", description: "A linked task exists and is not in a done column yet." },
  task_done_unverified: {
    label: "Done, unverified",
    tone: "warn",
    description: "The linked task is done but has no passed verification run, so the fix is claimed, not proven.",
  },
  verified: { label: "Verified", tone: "ok", description: "A done linked task has a passed verification run. The finding can be resolved." },
};

export const taskTypeLabel = (type: string) => TASK_TYPE_LABELS[type as TaskType] ?? type;
export const statusKeyLabel = (key: string) => STATUS_KEY_LABELS[key as StatusKey] ?? key;
export const priorityLabel = (p: string) => PRIORITY_META[p as TaskPriority]?.label ?? p;

export function PriorityBadge({ priority, className }: { priority: string; className?: string }) {
  const meta = PRIORITY_META[priority as TaskPriority];
  return (
    <Badge tone={meta?.tone ?? "neutral"} className={className}>
      {meta?.label ?? priority}
    </Badge>
  );
}

export function RemediationStateBadge({ state }: { state: RemediationState }) {
  const meta = REMEDIATION_META[state];
  return (
    <Badge tone={meta.tone} dot title={meta.description}>
      {meta.label}
    </Badge>
  );
}

/** Verification status; "Unverified" is shown only where it matters (done or late-stage tasks). */
export function VerificationBadge({ status }: { status: string }) {
  return <StatusBadge status={status} />;
}

const COLOR_TONES: Record<string, Tone> = {
  slate: "neutral",
  accent: "accent",
  trusted: "trusted",
  approved: "approved",
  external: "external",
  suspicious: "suspicious",
  blocked: "blocked",
  high: "high",
  medium: "medium",
  low: "low",
};

/** A task label; colour is a token name or "#rrggbb" chosen by the team (decorative, not a status). */
export function LabelChip({ label }: { label: Label }) {
  const tone = COLOR_TONES[label.color];
  const hex = !tone && /^#[0-9a-f]{6}$/i.test(label.color) ? label.color : undefined;
  return (
    <span className="inline-flex h-[18px] items-center gap-1 rounded border border-border-strong bg-surface-2 px-1.5 text-2xs text-fg-muted">
      <span className={cn("h-1.5 w-1.5 rounded-full", tone && TONE_CLASSES[tone].dot)} style={hex ? { background: hex } : undefined} aria-hidden />
      {label.name}
    </span>
  );
}

export function TaskKeyLink({ task, className }: { task: Pick<TaskCard, "id" | "key">; className?: string }) {
  return (
    <Link
      to={`/work/tasks/${encodeURIComponent(task.id)}`}
      onClick={(e) => e.stopPropagation()}
      className={cn("font-mono text-xs text-accent hover:text-accent-strong hover:underline", className)}
    >
      {task.key}
    </Link>
  );
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

export function AssigneeStack({ assignees, max = 3 }: { assignees: Assignee[]; max?: number }) {
  const people = assignees.filter((a) => a.role === "assignee");
  if (people.length === 0) return <span className="text-xs text-fg-faint">Unassigned</span>;
  const names = people.map((a) => a.name).join(", ");
  return (
    <Tooltip content={names}>
      <span className="inline-flex items-center" aria-label={`Assigned to ${names}`}>
        {people.slice(0, max).map((a, i) => (
          <span
            key={a.user_id}
            className={cn(
              "inline-flex h-5 w-5 items-center justify-center rounded-full border border-surface bg-surface-3 text-[9px] font-semibold text-fg-muted",
              i > 0 && "-ml-1.5",
            )}
            aria-hidden
          >
            {initials(a.name)}
          </span>
        ))}
        {people.length > max && <span className="ml-1 text-2xs text-fg-muted">+{people.length - max}</span>}
      </span>
    </Tooltip>
  );
}

export function DueDate({ due, done, overdue }: { due: string | null; done?: boolean; overdue?: boolean }) {
  if (!due) return <span className="text-fg-faint">—</span>;
  const late = overdue ?? (!done && isPast(new Date(due)));
  return (
    <span className={cn("inline-flex items-center gap-1 whitespace-nowrap text-xs", late ? "text-danger" : "text-fg-muted")}>
      <CalendarClock className="h-3.5 w-3.5" aria-hidden />
      {format(new Date(due), "d MMM")}
      {late && <span className="sr-only">(overdue)</span>}
    </span>
  );
}
