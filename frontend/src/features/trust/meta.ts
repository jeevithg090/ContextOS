/**
 * Trust Centre vocabulary and the capability rules mirrored from
 * backend/app/services/trust_service_common.py (the server re-validates everything).
 */
import { TRUST_LEVELS, type TrustLevel } from "@/lib/domain";
import { pluralize } from "@/lib/format";
import type { AppliesTo, Capability, CheckResult, ReassessSummary, SourceType } from "./types";

export const SOURCE_CAPABILITIES: Capability[] = ["read", "instruct", "execute", "credential_access"];
export const DESTINATION_CAPABILITIES: Capability[] = ["send"];
const ALLOW_LEVELS = new Set<TrustLevel>(["TRUSTED", "APPROVED"]);
const DATA_ONLY_LEVELS = new Set<TrustLevel>(["EXTERNAL", "UNKNOWN", "SUSPICIOUS"]);

export const CAPABILITY_META: Record<Capability, { label: string; description: string }> = {
  read: { label: "Read", description: "Content may be consumed as data." },
  instruct: { label: "Instruct", description: "Content may direct what the agent does." },
  execute: { label: "Execute", description: "Content may trigger tool execution." },
  credential_access: { label: "Credentials", description: "Content may lead the agent to access credentials." },
  send: { label: "Send", description: "Data may be sent to this destination." },
};

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  web: "Web page",
  repository: "Repository",
  file: "File",
  document: "Document",
  email: "Email",
  api: "API response",
  mcp_server: "MCP server",
  mcp_tool: "MCP tool",
  browser: "Browser page",
  database: "Database",
  user_upload: "Uploaded file",
  user_prompt: "User prompt",
  tool_output: "Tool output",
  agent_output: "Sub-agent output",
  system: "System prompt",
  other: "Other",
};

export function sourceTypeLabel(type: string | null | undefined): string {
  if (!type) return "Any type";
  return SOURCE_TYPE_LABELS[type as SourceType] ?? type;
}

/** Identifier without the web scheme, for compact display (the full value stays in titles/details). */
export function displayIdentifier(identifier: string): string {
  return identifier.replace(/^(https?|wss?):\/\//i, "");
}

export const DESTINATION_KIND_LABELS: Record<string, string> = {
  domain: "Domain",
  ip: "IP address",
  email: "Email",
  service: "Service",
  agent: "Agent",
  unknown: "Auto-detect",
};

/** Names of the checks the destination engine performs (backend/app/engines/trust/destinations.py). */
export const CHECK_LABELS: Record<string, string> = {
  allowlist: "Destination allowlist",
  blocklist: "Blocking / suspicious rules",
  ip_literal: "Raw IP address",
  internal_address: "Internal address",
  cloud_metadata: "Cloud metadata endpoint",
  exfiltration_service: "Known capture, tunnel or paste service",
  punycode: "Internationalised (punycode) name",
  lookalike: "Lookalike of an allowlisted domain",
  first_seen: "Seen before",
  reported_by_integration: "Derived from the call's arguments",
};

export function checkLabel(check: string): string {
  return CHECK_LABELS[check] ?? check.replace(/_/g, " ");
}

export const CHECK_RESULT_META: Record<CheckResult, { label: string; tone: "ok" | "warn" | "danger" | "neutral" }> = {
  pass: { label: "Pass", tone: "ok" },
  warn: { label: "Warning", tone: "warn" },
  fail: { label: "Fail", tone: "danger" },
  unknown: { label: "Not checked", tone: "neutral" },
};

export function allowedCapabilities(appliesTo: AppliesTo): Capability[] {
  if (appliesTo === "source") return SOURCE_CAPABILITIES;
  if (appliesTo === "destination") return DESTINATION_CAPABILITIES;
  return [...SOURCE_CAPABILITIES, ...DESTINATION_CAPABILITIES];
}

/** Capabilities a level grants when none are chosen (matches the backend defaults). */
export function defaultCapabilities(level: TrustLevel, appliesTo: AppliesTo): Capability[] {
  const caps: Capability[] = [];
  if (appliesTo !== "destination") {
    if (level === "TRUSTED") caps.push("read", "instruct", "execute");
    else if (level !== "BLOCKED") caps.push("read");
  }
  if (appliesTo !== "source" && ALLOW_LEVELS.has(level)) caps.push("send");
  return caps;
}

/** Whether a capability may be granted at a level (data-only levels allow 'read' only). */
export function capabilityAllowed(level: TrustLevel, capability: Capability): boolean {
  if (level === "BLOCKED") return false;
  if (capability === "send") return ALLOW_LEVELS.has(level);
  if (DATA_ONLY_LEVELS.has(level)) return capability === "read";
  return true;
}

export function capabilityProblems(level: TrustLevel, appliesTo: AppliesTo, caps: Capability[]): string[] {
  const allowed = new Set(allowedCapabilities(appliesTo));
  const problems: string[] = [];
  caps.forEach((c) => {
    if (!allowed.has(c)) problems.push(c === "send" ? "'send' applies to destinations only." : `'${c}' applies to sources only.`);
    else if (!capabilityAllowed(level, c)) {
      if (level === "BLOCKED") problems.push("BLOCKED grants no capabilities.");
      else if (c === "send") problems.push("Only TRUSTED or APPROVED destinations can be granted 'send'.");
      else problems.push(`${level} content is always treated as data, so only 'read' can be granted.`);
    }
  });
  return Array.from(new Set(problems));
}

export const LEVEL_HELP: Record<TrustLevel, string> = {
  TRUSTED: "First-party content. By default it may be read, instruct the agent and trigger tools.",
  APPROVED: "Approved for the capabilities you choose only — for example read but not instruct.",
  EXTERNAL: "A known third party. Content is data and never instructions.",
  UNKNOWN: "Not classified. Content is data and never instructions.",
  SUSPICIOUS: "Treated as hostile data: readable, never followed.",
  BLOCKED: "Must not be consumed or contacted. Grants nothing.",
};

export const LEVEL_OPTIONS = TRUST_LEVELS.map((l) => ({ value: l, label: l.charAt(0) + l.slice(1).toLowerCase() }));

export function reassessMessage(summary: ReassessSummary | null | undefined): string | undefined {
  if (!summary) return undefined;
  const parts: string[] = [];
  if (summary.sources_checked) parts.push(`${pluralize(summary.sources_changed, "source")} reclassified of ${summary.sources_checked} checked`);
  if (summary.destinations_checked)
    parts.push(`${pluralize(summary.destinations_changed, "destination")} reclassified of ${summary.destinations_checked} checked`);
  if (!parts.length) return "No stored sources or destinations were affected.";
  const text = parts.join("; ") + ".";
  return summary.truncated ? `${text} Only the ${summary.limit} most recently seen of each were re-assessed now; the rest update when next observed.` : text;
}
