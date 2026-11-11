/**
 * Small task presentation pieces shared by board cards, the task drawer and the task page:
 * priority icon, verification state, subtask progress and the blocked marker.
 */
import { AlertOctagon, Ban, ChevronDown, ChevronUp, ChevronsUp, Minus, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import { Badge, Tooltip } from "@/components/ui";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";
import { PRIORITY_META } from "../analytics/taskMeta";
import type { TaskPriority, VerificationStatus } from "../types";

const PRIORITY_ICONS: Record<TaskPriority, typeof ChevronUp> = {
  urgent: AlertOctagon,
  high: ChevronsUp,
  medium: ChevronUp,
  low: ChevronDown,
  none: Minus,
};

export function PriorityIcon({ priority, className }: { priority: TaskPriority; className?: string }) {
  const Icon = PRIORITY_ICONS[priority] ?? Minus;
  const meta = PRIORITY_META[priority];
  return (
    <span title={`Priority: ${meta?.label ?? priority}`} className={cn("inline-flex", TONE_CLASSES[meta?.tone ?? "neutral"].text, className)}>
      <Icon className="h-3.5 w-3.5" aria-hidden />
      <span className="sr-only">Priority: {meta?.label ?? priority}</span>
    </span>
  );
}

export const VERIFICATION_META: Record<VerificationStatus, { label: string; tone: Tone; description: string }> = {
  unverified: {
    label: "Unverified",
    tone: "neutral",
    description: "No verification run has been recorded. A fix marked complete is a claim until a run passes.",
  },
  pending: { label: "Verification pending", tone: "warn", description: "A verification run is recorded as pending; no result yet." },
  passed: { label: "Verified", tone: "ok", description: "The latest verification run passed." },
  failed: { label: "Verification failed", tone: "danger", description: "The latest verification run failed or errored." },
};

const VERIFICATION_ICONS: Record<VerificationStatus, typeof ShieldCheck> = {
  unverified: ShieldQuestion,
  pending: ShieldAlert,
  passed: ShieldCheck,
  failed: ShieldX,
};

/** Compact verification marker for cards (icon + tooltip). */
export function VerificationIcon({ status, emphasise = false }: { status: VerificationStatus; emphasise?: boolean }) {
  const meta = VERIFICATION_META[status] ?? VERIFICATION_META.unverified;
  const Icon = VERIFICATION_ICONS[status] ?? ShieldQuestion;
  const tone: Tone = status === "unverified" && emphasise ? "warn" : meta.tone;
  return (
    <Tooltip content={emphasise && status === "unverified" ? "Done but unverified: no passed verification run yet." : meta.description}>
      <span className={cn("inline-flex items-center", TONE_CLASSES[tone].text)} tabIndex={-1}>
        <Icon className="h-3.5 w-3.5" aria-hidden />
        <span className="sr-only">{meta.label}</span>
      </span>
    </Tooltip>
  );
}

export function VerificationStatusBadge({ status }: { status: VerificationStatus }) {
  const meta = VERIFICATION_META[status] ?? VERIFICATION_META.unverified;
  return (
    <Badge tone={meta.tone} dot title={meta.description}>
      {meta.label}
    </Badge>
  );
}

export function SubtaskProgress({ done, total }: { done: number; total: number }) {
  if (total === 0) return null;
  const pct = Math.round((done / total) * 100);
  return (
    <span className="inline-flex items-center gap-1 text-2xs text-fg-muted" title={`${done} of ${total} subtasks done`}>
      <span className="relative h-1 w-8 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span className={cn("absolute inset-y-0 left-0 rounded-full", done === total ? "bg-ok" : "bg-accent")} style={{ width: `${pct}%` }} />
      </span>
      <span className="num">
        {done}/{total}
      </span>
      <span className="sr-only">subtasks done</span>
    </span>
  );
}

export function BlockedMarker({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="inline-flex items-center gap-1 text-2xs text-danger" title={`Blocked by ${count} open task${count === 1 ? "" : "s"}`}>
      <Ban className="h-3 w-3" aria-hidden />
      <span className="num">{count}</span>
      <span className="sr-only">open blocking task{count === 1 ? "" : "s"}</span>
    </span>
  );
}
