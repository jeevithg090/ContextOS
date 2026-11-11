/** Presentation vocabulary for the agents feature (labels only; colour semantics stay in lib/domain). */
import { humanize, severityTone, type Tone } from "@/lib/domain";
import type { ToolCategory } from "./types";

export const TOOL_CATEGORY_LABELS: Record<ToolCategory, string> = {
  file_read: "File read",
  file_write: "File write",
  shell: "Shell",
  http: "HTTP",
  browser: "Browser",
  email: "Email",
  messaging: "Messaging",
  database: "Database",
  code_execution: "Code execution",
  infrastructure: "Infrastructure",
  agent_delegation: "Agent delegation",
  search: "Search",
  mcp: "MCP tool",
  other: "Other",
};

export function toolCategoryLabel(category?: string | null): string {
  return (category && TOOL_CATEGORY_LABELS[category as ToolCategory]) || humanize(category);
}

const FRAMEWORK_LABELS: Record<string, string> = {
  claude_code: "Claude Code",
  mcp: "MCP",
  mcp_gateway: "MCP gateway",
  python_sdk: "Python SDK",
  langgraph: "LangGraph",
  langchain: "LangChain",
  openai_agents: "OpenAI Agents",
  crewai: "CrewAI",
  autogen: "AutoGen",
  custom: "Custom",
};

export function frameworkLabel(framework?: string | null): string {
  return (framework && FRAMEWORK_LABELS[framework]) || humanize(framework);
}

export const ENVIRONMENT_LABELS: Record<string, string> = {
  development: "Development",
  staging: "Staging",
  production: "Production",
};

/** Production is the only environment that changes which policies apply by default, so it alone is highlighted. */
export function environmentTone(environment?: string | null): Tone {
  return environment === "production" ? "accent" : "neutral";
}

/** Risk levels share the severity scale (low → critical). */
export function riskTone(level?: string | null): Tone {
  return severityTone(level);
}

export function relationshipLabel(kind: string, direction: "outgoing" | "incoming"): string {
  if (kind === "delegates_to") return direction === "outgoing" ? "Delegates to" : "Receives work from";
  if (kind === "messages") return direction === "outgoing" ? "Sends messages to" : "Receives messages from";
  return humanize(kind);
}

export const INTEGRATION_LABELS: Record<string, string> = {
  claude_code: "Claude Code hooks",
  mcp_gateway: "MCP gateway",
  python_sdk: "Python SDK",
  custom: "Custom integration",
};

export function integrationLabel(kind?: string | null): string {
  return (kind && INTEGRATION_LABELS[kind]) || humanize(kind);
}

/** Stable display order for decision breakdowns (most restrictive first). */
export const DECISION_ORDER = ["DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT", "ALLOW"] as const;

export function sortedCounts(counts: Record<string, number>, order: readonly string[]): Array<[string, number]> {
  const rank = (k: string) => {
    const i = order.indexOf(k);
    return i === -1 ? order.length : i;
  };
  return Object.entries(counts)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b));
}

export function durationLabel(startIso: string, endIso?: string | null): string {
  const start = new Date(startIso).getTime();
  const end = endIso ? new Date(endIso).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "—";
  const s = Math.round((end - start) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}
