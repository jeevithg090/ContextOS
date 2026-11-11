/** Presentation helpers for the Approval Centre: countdowns, risk chips and activity labels. */
import { useEffect, useState } from "react";
import { trustTone, type Tone } from "@/lib/domain";
import { pluralize } from "@/lib/format";
import type { Approval, ApprovalActivity } from "./types";

/** Re-render every `intervalMs` (for live countdowns). One timer per component. */
export function useNow(intervalMs = 1000, enabled = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, enabled]);
  return now;
}

/**
 * Deadline in this browser's clock: the server's `seconds_remaining` measured from when the
 * response arrived. This avoids trusting the local clock against the server's `expires_at`.
 */
export function deadlineOf(approval: Pick<Approval, "status" | "seconds_remaining">, receivedAt: number): number | null {
  if (approval.status !== "pending" || approval.seconds_remaining === null) return null;
  return receivedAt + approval.seconds_remaining * 1000;
}

export function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export function countdownTone(ms: number): Tone {
  if (ms <= 60_000) return "danger";
  if (ms <= 180_000) return "warn";
  return "neutral";
}

export function countdownLabel(ms: number): string {
  if (ms <= 0) return "Deadline passed";
  return `${formatCountdown(ms)} left to decide`;
}

const RAN = new Set(["completed", "failed"]);

/** The integration reported the call as run although nobody approved it here. */
export function ranWithoutApproval(a: Pick<Approval, "status" | "tool_invocation_status">): boolean {
  return a.status !== "approved" && RAN.has(a.tool_invocation_status ?? "");
}

export interface RiskChip {
  key: string;
  label: string;
  tone: Tone;
  title: string;
}

/** Why this request is risky, as short chips. Only facts recorded with the approval are shown. */
export function riskChips(a: Approval): RiskChip[] {
  const chips: RiskChip[] = [];
  const r = a.risk;
  const dest = a.target.destination;
  const destLevel = dest?.classification_at_decision ?? dest?.classification ?? r.destination_classification;
  if (destLevel && destLevel !== "TRUSTED" && destLevel !== "APPROVED") {
    chips.push({
      key: "destination",
      label: `${destLevel.charAt(0)}${destLevel.slice(1).toLowerCase()} destination`,
      tone: trustTone(destLevel),
      title: `The destination was classified ${destLevel} when the call was paused.`,
    });
  }
  if (r.secrets_in_arguments > 0) {
    chips.push({
      key: "secrets",
      label: pluralize(r.secrets_in_arguments, "credential") + " in arguments",
      tone: "danger",
      title: "Secrets were detected in the call's arguments (shown redacted; the agent would send the real value).",
    });
  }
  if (r.session_secret_matches > 0) {
    chips.push({
      key: "session-secret",
      label: "Credential from session context",
      tone: "danger",
      title: "A credential in the arguments was previously seen in this session's context.",
    });
  }
  if (r.trifecta) {
    chips.push({
      key: "trifecta",
      label: "Lethal trifecta",
      tone: "critical",
      title: "The session had accessed sensitive data, been exposed to untrusted content and had an outbound channel. A risk condition, not proof of an attack.",
    });
  }
  if (a.target.sensitive_resource_count > 0) {
    chips.push({
      key: "sensitive",
      label: pluralize(a.target.sensitive_resource_count, "sensitive resource"),
      tone: "high",
      title: "Files, paths or other resources flagged as sensitive.",
    });
  }
  if (r.detections.length > 0) {
    chips.push({
      key: "detections",
      label: pluralize(r.detections.length, "detection"),
      tone: "medium",
      title: `Detection rules that matched the request: ${r.detections.join(", ")}`,
    });
  }
  if (r.session_level === "high" || r.session_level === "critical") {
    chips.push({
      key: "session",
      label: `Session risk ${r.session_score}`,
      tone: r.session_level === "critical" ? "critical" : "high",
      title: r.session_summary ?? `Session risk was ${r.session_level} when the call was paused.`,
    });
  }
  return chips;
}

export function decidedByLabel(a: Pick<Approval, "status" | "decided_by">): string {
  if (a.status === "expired") return "Nobody (timed out)";
  if (a.status === "cancelled") return "Cancelled";
  return a.decided_by?.name || a.decided_by?.email || "Unknown user";
}

export function activityTitle(entry: ApprovalActivity): { title: string; tone: Tone } {
  const outcome = typeof entry.details.outcome === "string" ? entry.details.outcome : null;
  const who = entry.actor_name ?? (entry.actor_type === "api_key" ? "the integration" : entry.actor_type);
  switch (entry.action) {
    case "tool.approval_required":
      return { title: `Paused for approval (reported by ${who})`, tone: "approval" };
    case "approval.decided":
      return outcome === "approved" ? { title: `Approved by ${who}`, tone: "allow" } : { title: `Rejected by ${who}`, tone: "deny" };
    case "approval.expired":
      return { title: "Expired: nobody decided before the deadline", tone: "neutral" };
    default:
      return { title: entry.action, tone: "neutral" };
  }
}

/** Short, readable source label for a context item. */
export function sourceLabel(item: { source_display_name: string | null; source_identifier: string | null; source_id: string }): string {
  return item.source_display_name || item.source_identifier || item.source_id;
}
