/**
 * Presentation vocabulary for Security Intelligence: windows, status actions, confidence wording,
 * category explanations and durations. Colour semantics stay in "@/lib/domain".
 */
import { FINDING_CATEGORY_LABELS, humanize, type Tone } from "@/lib/domain";
import type { StatsWindow } from "./types";

export const WINDOWS: Array<{ value: StatsWindow; label: string; long: string }> = [
  { value: "24h", label: "24h", long: "the last 24 hours" },
  { value: "7d", label: "7d", long: "the last 7 days" },
  { value: "30d", label: "30d", long: "the last 30 days" },
  { value: "90d", label: "90d", long: "the last 90 days" },
];

export function windowMeta(value: string | null | undefined) {
  return WINDOWS.find((w) => w.value === value) ?? WINDOWS[1];
}

/** Default list view: findings that still need someone's attention. */
export const ACTIVE_STATUSES = ["open", "acknowledged"] as const;

export const STATUS_OPTIONS: Array<{ value: string; label: string; description: string }> = [
  { value: "open", label: "Open", description: "Detected and not yet looked at." },
  { value: "acknowledged", label: "Acknowledged", description: "Someone is looking at it." },
  { value: "resolved", label: "Resolved", description: "The underlying problem was dealt with." },
  { value: "false_positive", label: "False positive", description: "Judged not to be suspicious. Lifts the evidence against its source." },
];

/**
 * Mirror of backend ALLOWED_TRANSITIONS, used only to decide which quick actions a list row shows.
 * The server validates every transition (409 otherwise); the detail page uses `allowed_transitions`.
 */
export const TRANSITIONS: Record<string, string[]> = {
  open: ["acknowledged", "resolved", "false_positive"],
  acknowledged: ["open", "resolved", "false_positive"],
  resolved: ["open", "false_positive"],
  false_positive: ["open"],
};

export type TriageAction = "acknowledged" | "resolved" | "false_positive" | "open";

export const ACTION_META: Record<TriageAction, { label: string; verb: string; done: string; noteRequired: boolean; noteLabel: string; description: string }> = {
  acknowledged: {
    label: "Acknowledge",
    verb: "Acknowledge",
    done: "Finding acknowledged",
    noteRequired: false,
    noteLabel: "",
    description: "Tell your team someone is looking at this. It stays in the open backlog.",
  },
  resolved: {
    label: "Resolve",
    verb: "Resolve finding",
    done: "Finding resolved",
    noteRequired: false,
    noteLabel: "What was done (optional)",
    description: "The problem was dealt with: credentials rotated, source blocked, policy added. A new occurrence opens a new finding.",
  },
  false_positive: {
    label: "False positive",
    verb: "Mark as false positive",
    done: "Marked as a false positive",
    noteRequired: true,
    noteLabel: "Why is this not suspicious?",
    description:
      "Use this when the detection was wrong. The finding stops counting as evidence against its source, so the source's trust can recover when it is next assessed.",
  },
  open: {
    label: "Reopen",
    verb: "Reopen finding",
    done: "Finding reopened",
    noteRequired: false,
    noteLabel: "Why reopen it? (optional)",
    description: "Put the finding back in the open backlog. The previous resolution stays in the history.",
  },
};

export function confidenceWords(confidence: number): { label: string; percent: string; tone: Tone } {
  const pct = `${Math.round(Math.max(0, Math.min(1, confidence)) * 100)}%`;
  if (confidence >= 0.85) return { label: "High confidence", percent: pct, tone: "ok" };
  if (confidence >= 0.6) return { label: "Medium confidence", percent: pct, tone: "warn" };
  return { label: "Low confidence", percent: pct, tone: "neutral" };
}

export function categoryLabel(category: string | null | undefined): string {
  if (!category) return "—";
  return FINDING_CATEGORY_LABELS[category] ?? humanize(category);
}

/** One plain-language line per category: what the detector saw. */
export const CATEGORY_DESCRIPTIONS: Record<string, string> = {
  prompt_injection: "Content tries to steer the agent with instructions it should treat as data.",
  instruction_override: "Content tries to replace or cancel the agent's instructions.",
  credential_access: "The agent read, or was told to read, credential material.",
  secret_exposure: "A credential appeared in an outbound call.",
  exfiltration: "Data — often a credential — was sent, or was meant to be sent, outside the environment.",
  untrusted_source: "A source that may only provide data contained instructions.",
  suspicious_tool_use: "A tool call looks like an attack technique.",
  dangerous_permissions: "The agent holds permissions that make abuse easy.",
  lethal_trifecta: "Sensitive data, untrusted content and an outbound channel met in one session.",
  anomaly: "Behaviour that differs from what this agent normally does.",
  cross_agent_contamination: "Content from a session with injection detections reached another agent.",
  policy_violation: "A tool call matched a policy that denies it.",
  destination_risk: "A tool call targets a destination classified as risky.",
  permission_escalation: "The agent tried to widen its own permissions or persistence.",
};

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

const HISTORY_LABELS: Record<string, string> = {
  "finding.acknowledged": "Acknowledged",
  "finding.resolved": "Resolved",
  "finding.false_positive": "Marked false positive",
  "finding.reopened": "Reopened",
  "finding.note_updated": "Resolution note edited",
  "finding.incident_linked": "Linked to an incident",
};

export function historyLabel(action: string): string {
  return HISTORY_LABELS[action] ?? humanize(action.replace(/^finding\./, ""));
}

export function historyTone(action: string): Tone {
  if (action === "finding.resolved") return "ok";
  if (action === "finding.false_positive") return "neutral";
  if (action === "finding.reopened") return "high";
  if (action === "finding.acknowledged") return "medium";
  return "accent";
}

export const SORT_OPTIONS = [
  { value: "severity", label: "Most severe" },
  { value: "recent", label: "Recently seen" },
  { value: "first_seen", label: "Newest" },
  { value: "occurrences", label: "Most occurrences" },
] as const;
