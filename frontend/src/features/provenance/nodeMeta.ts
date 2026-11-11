/**
 * Presentation vocabulary for the provenance graph: node types, lanes, accents and path outcomes.
 * Colour decisions go through lib/domain tones so the graph matches badges everywhere else.
 */
import {
  Activity,
  Bot,
  Database,
  FileText,
  Globe,
  Hammer,
  HardDrive,
  Radar,
  Scale,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { decisionTone, severityTone, trustTone, type Tone } from "@/lib/domain";
import type { GraphEdge, GraphNode, PathOutcome } from "./types";

export interface NodeTypeMeta {
  label: string;
  plural: string;
  icon: LucideIcon;
  /** One-line answer to "what is this node?" (legend + inspector). */
  description: string;
}

export const NODE_TYPE_META: Record<string, NodeTypeMeta> = {
  source: { label: "Source", plural: "Sources", icon: Database, description: "Where content came from: a file, web page, MCP server, API or person." },
  context_item: { label: "Context item", plural: "Context items", icon: FileText, description: "One piece of content delivered to an agent (its receipt)." },
  session: { label: "Session", plural: "Sessions", icon: Activity, description: "One run of an agent." },
  agent: { label: "Agent", plural: "Agents", icon: Bot, description: "The agent that ran the session." },
  tool_invocation: { label: "Tool call", plural: "Tool calls", icon: Wrench, description: "A tool the agent requested, with the policy decision." },
  tool: { label: "Tool", plural: "Tools", icon: Hammer, description: "The tool definition a call used." },
  resource: { label: "Resource", plural: "Resources", icon: HardDrive, description: "A file, URL, host or command a tool call touched." },
  destination: { label: "Destination", plural: "Destinations", icon: Globe, description: "Where a tool call could send data." },
  finding: { label: "Finding", plural: "Findings", icon: Radar, description: "Suspicious behaviour ContextOS detected." },
  policy_decision: { label: "Policy decision", plural: "Policy decisions", icon: Scale, description: "The recorded policy evaluation of a tool call." },
};

export function nodeTypeMeta(type: string): NodeTypeMeta {
  return NODE_TYPE_META[type] ?? { label: type.replace(/_/g, " "), plural: type.replace(/_/g, " "), icon: FileText, description: "" };
}

/** Left-to-right columns. Empty lanes collapse so the canvas never shows blank columns. */
export const LANES = [
  { key: "sources", label: "Sources" },
  { key: "context", label: "Context" },
  { key: "detections", label: "Detections" },
  { key: "agents", label: "Agents" },
  { key: "sessions", label: "Sessions" },
  { key: "calls", label: "Tool calls" },
  { key: "targets", label: "Resources & destinations" },
  { key: "outcomes", label: "Decisions & findings" },
] as const;
export type LaneKey = (typeof LANES)[number]["key"];

const TYPE_LANE: Record<string, LaneKey> = {
  source: "sources",
  context_item: "context",
  agent: "agents",
  session: "sessions",
  tool_invocation: "calls",
  resource: "targets",
  destination: "targets",
  tool: "targets",
  policy_decision: "outcomes",
};

/** Lane for a node. Findings raised by content sit next to the context; others next to the calls. */
export function laneOf(node: GraphNode, incoming: GraphEdge[] | undefined, nodeType: (id: string) => string | undefined): LaneKey {
  if (node.type === "finding") {
    return incoming?.some((e) => nodeType(e.src) === "context_item") ? "detections" : "outcomes";
  }
  return TYPE_LANE[node.type] ?? "targets";
}

export function riskTone(level?: string | null): Tone {
  switch (level) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "neutral";
  }
}

/** The colour that carries meaning for this node type (trust, severity, decision or risk). */
export function nodeTone(node: GraphNode): Tone {
  switch (node.type) {
    case "source":
    case "context_item":
    case "destination":
      return trustTone(node.trust_level);
    case "finding":
      return severityTone(node.severity);
    case "tool_invocation":
    case "policy_decision":
      return node.decision ? decisionTone(node.decision) : "neutral";
    case "session":
      return riskTone(node.risk_level);
    case "resource":
      return node.sensitive ? "warn" : "neutral";
    default:
      return "neutral";
  }
}

export const OUTCOME_META: Record<PathOutcome, { label: string; tone: Tone; description: string }> = {
  prevented: { label: "Prevented", tone: "ok", description: "Denied (or rejected) at an enforced execution boundary." },
  awaiting_approval: { label: "Held for approval", tone: "approval", description: "Paused at an enforced boundary until a human decides." },
  advisory_only: { label: "Advisory only", tone: "warn", description: "A blocking decision was returned, but the integration may not have honoured it." },
  not_prevented: { label: "Not prevented", tone: "danger", description: "Allowed, approved, or only observed after it ran." },
};

export function outcomeMeta(outcome: string) {
  return OUTCOME_META[outcome as PathOutcome] ?? { label: outcome.replace(/_/g, " "), tone: "neutral" as Tone, description: "" };
}

export function confidenceText(edge: Pick<GraphEdge, "confidence" | "basis">): string {
  if (edge.basis === "finding_record") return "Recorded on the finding as its subject (no provenance edge was written for it).";
  if (edge.confidence === "inferred") return "Inferred by ContextOS (for example, matching secret fingerprints), not reported directly.";
  return "Observed: recorded directly from the integration's events.";
}

/** Node types users can hide to declutter the canvas; findings are shown by default. */
export const OPTIONAL_TYPES = ["finding", "policy_decision", "tool", "agent"] as const;
export type OptionalType = (typeof OPTIONAL_TYPES)[number];
export const DEFAULT_HIDDEN: OptionalType[] = ["policy_decision", "tool", "agent"];
