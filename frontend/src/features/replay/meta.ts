/** Presentation helpers shared by the Replay Lab views. */
import {
  ArrowRightLeft,
  Bot,
  CircleAlert,
  CirclePlay,
  CircleStop,
  FileInput,
  MessageSquare,
  Plug,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { decisionTone, type Tone } from "@/lib/domain";

const EVENT_ICONS: Record<string, LucideIcon> = {
  "session.started": CirclePlay,
  "session.ended": CircleStop,
  "prompt.submitted": MessageSquare,
  "context.ingested": FileInput,
  "tool.requested": Wrench,
  "tool.completed": Wrench,
  "tool.failed": CircleAlert,
  "agent.delegated": ArrowRightLeft,
  "agent.message": Bot,
  "mcp.server_connected": Plug,
};

export function eventIcon(eventType: string): LucideIcon {
  return EVENT_ICONS[eventType] ?? Wrench;
}

export const EVENT_LABELS: Record<string, string> = {
  "session.started": "Session started",
  "session.ended": "Session ended",
  "prompt.submitted": "Prompt",
  "context.ingested": "Context",
  "tool.requested": "Tool request",
  "tool.completed": "Tool result",
  "tool.failed": "Tool failure",
  "agent.delegated": "Delegation",
  "agent.message": "Agent message",
  "mcp.server_connected": "MCP server",
};

export function eventLabel(eventType: string): string {
  return EVENT_LABELS[eventType] ?? eventType;
}

/** Tone of a step's marker on the risk track: its decision, else neutral. */
export function stepTone(decision: string | null | undefined): Tone {
  return decision ? decisionTone(decision) : "neutral";
}

export function signed(n: number): string {
  if (n > 0) return `+${n}`;
  if (n < 0) return `−${Math.abs(n)}`;
  return "±0";
}

export const CONDITION_LABELS = [
  { key: "sensitive_access", label: "Sensitive data" },
  { key: "untrusted_exposure", label: "Untrusted content" },
  { key: "outbound_channel", label: "Outbound channel" },
] as const;

export const CHANGE_LABELS: Record<string, string> = {
  removed: "Not in set",
  disabled: "Disabled",
  monitor: "Monitor only",
  no_longer_matches: "No longer matches",
  outcome_changed: "Outcome changed",
  newly_matches: "Newly matches",
};

export const SIMULATION_BANNER = "SIMULATION — hypothetical outcomes evaluated against recorded inputs, not historical fact";
