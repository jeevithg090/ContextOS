/** Presentation vocabulary for incidents: workflow steps, transition verbs, timeline and activity labels. */
import { Activity as ActivityIcon, FileText, MessageSquare, Radar, Scale, UserCheck, Wrench, Zap, type LucideIcon } from "lucide-react";
import { decisionTone, severityTone, trustTone, type IncidentStatus, type Tone } from "@/lib/domain";
import type { TimelineEntry, TimelineEntryType } from "./types";

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  open: "Open",
  investigating: "Investigating",
  contained: "Contained",
  resolved: "Resolved",
  false_positive: "False positive",
};

export const STATUS_DESCRIPTIONS: Record<IncidentStatus, string> = {
  open: "Raised, nobody has started working on it yet.",
  investigating: "Someone is establishing what happened and what is affected.",
  contained: "The immediate risk is stopped (credential rotated, agent restricted); clean-up continues.",
  resolved: "Handled, with a recorded resolution.",
  false_positive: "Not a real problem, with a recorded reason.",
};

/** The main path, left to right. False positive is an alternative end state. */
export const WORKFLOW: IncidentStatus[] = ["open", "investigating", "contained", "resolved"];

export const CLOSED: IncidentStatus[] = ["resolved", "false_positive"];

export function isClosed(status: string): boolean {
  return (CLOSED as string[]).includes(status);
}

/** Button label for moving from `from` to `to`. */
export function transitionLabel(from: IncidentStatus, to: IncidentStatus): string {
  if (isClosed(from) && to === "investigating") return "Reopen";
  if (to === "open") return "Move back to open";
  if (to === "investigating") return from === "contained" ? "Back to investigating" : "Start investigating";
  if (to === "contained") return "Mark contained";
  if (to === "resolved") return "Resolve…";
  return from === "resolved" ? "Reclassify as false positive…" : "False positive…";
}

export const ENTRY_META: Record<TimelineEntryType, { label: string; plural: string; icon: LucideIcon }> = {
  event: { label: "Event", plural: "Events", icon: Zap },
  finding: { label: "Finding", plural: "Findings", icon: Radar },
  policy_decision: { label: "Decision", plural: "Decisions", icon: Scale },
  approval: { label: "Approval", plural: "Approvals", icon: UserCheck },
  activity: { label: "Activity", plural: "Activity", icon: MessageSquare },
};

export function entryIcon(entry: TimelineEntry): LucideIcon {
  if (entry.type !== "event") return ENTRY_META[entry.type].icon;
  if (entry.event_type?.startsWith("tool.")) return Wrench;
  if (entry.event_type === "context.ingested" || entry.refs.context_item_id) return FileText;
  if (entry.event_type?.startsWith("session.")) return ActivityIcon;
  return Zap;
}

/** Colour carries meaning only: severity, a non-allow decision, or untrusted content. */
export function entryTone(entry: TimelineEntry): Tone {
  if (entry.severity) return severityTone(entry.severity);
  if (entry.decision && entry.decision !== "ALLOW") return decisionTone(entry.decision);
  if (entry.status === "error") return "danger";
  if (entry.type === "approval") return entry.status === "approved" ? "allow" : entry.status === "pending" ? "approval" : "deny";
  if (entry.trust_level && ["SUSPICIOUS", "BLOCKED"].includes(entry.trust_level)) return trustTone(entry.trust_level);
  if (entry.type === "activity") return "accent";
  return "neutral";
}

export const ACTIVITY_LABELS: Record<string, string> = {
  created: "opened the incident",
  note: "added a note",
  status_change: "changed the status",
  severity_change: "changed the severity",
  assigned: "changed the assignee",
  finding_linked: "linked a finding",
  finding_status: "triaged a finding",
  resolution_updated: "updated the resolution",
  exported: "exported the evidence bundle",
};

export const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const;
