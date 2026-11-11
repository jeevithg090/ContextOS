/**
 * Domain vocabulary mirrored from backend/app/domain/enums.py, plus the presentation mapping
 * (labels + colour tokens). Keep this file the ONLY place where status → colour is decided.
 */

export const TRUST_LEVELS = ["TRUSTED", "APPROVED", "EXTERNAL", "UNKNOWN", "SUSPICIOUS", "BLOCKED"] as const;
export type TrustLevel = (typeof TRUST_LEVELS)[number];

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const DECISIONS = ["ALLOW", "DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT"] as const;
export type Decision = (typeof DECISIONS)[number];

export type EnforcementMode = "enforced" | "advisory" | "observed";

export const FINDING_STATUSES = ["open", "acknowledged", "resolved", "false_positive"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const INCIDENT_STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export const APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired", "cancelled"] as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];

export const ROLES = ["owner", "admin", "security_analyst", "developer", "viewer"] as const;
export type Role = (typeof ROLES)[number];

export type Tone =
  | "neutral"
  | "accent"
  | "trusted"
  | "approved"
  | "external"
  | "unknown"
  | "suspicious"
  | "blocked"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "allow"
  | "deny"
  | "approval"
  | "restrict"
  | "audit"
  | "ok"
  | "warn"
  | "danger";

/** Tailwind classes per tone: [text, background-tint, border, dot]. */
export const TONE_CLASSES: Record<Tone, { text: string; bg: string; border: string; dot: string }> = {
  neutral: { text: "text-fg-muted", bg: "bg-surface-3/60", border: "border-border-strong", dot: "bg-fg-faint" },
  accent: { text: "text-accent", bg: "bg-accent/10", border: "border-accent/30", dot: "bg-accent" },
  trusted: { text: "text-trust-trusted", bg: "bg-trust-trusted/10", border: "border-trust-trusted/30", dot: "bg-trust-trusted" },
  approved: { text: "text-trust-approved", bg: "bg-trust-approved/10", border: "border-trust-approved/30", dot: "bg-trust-approved" },
  external: { text: "text-trust-external", bg: "bg-trust-external/10", border: "border-trust-external/30", dot: "bg-trust-external" },
  unknown: { text: "text-trust-unknown", bg: "bg-trust-unknown/10", border: "border-trust-unknown/25", dot: "bg-trust-unknown" },
  suspicious: { text: "text-trust-suspicious", bg: "bg-trust-suspicious/10", border: "border-trust-suspicious/30", dot: "bg-trust-suspicious" },
  blocked: { text: "text-trust-blocked", bg: "bg-trust-blocked/10", border: "border-trust-blocked/30", dot: "bg-trust-blocked" },
  critical: { text: "text-sev-critical", bg: "bg-sev-critical/10", border: "border-sev-critical/35", dot: "bg-sev-critical" },
  high: { text: "text-sev-high", bg: "bg-sev-high/10", border: "border-sev-high/30", dot: "bg-sev-high" },
  medium: { text: "text-sev-medium", bg: "bg-sev-medium/10", border: "border-sev-medium/30", dot: "bg-sev-medium" },
  low: { text: "text-sev-low", bg: "bg-sev-low/10", border: "border-sev-low/30", dot: "bg-sev-low" },
  info: { text: "text-sev-info", bg: "bg-sev-info/10", border: "border-sev-info/25", dot: "bg-sev-info" },
  allow: { text: "text-dec-allow", bg: "bg-dec-allow/10", border: "border-dec-allow/30", dot: "bg-dec-allow" },
  deny: { text: "text-dec-deny", bg: "bg-dec-deny/10", border: "border-dec-deny/35", dot: "bg-dec-deny" },
  approval: { text: "text-dec-approval", bg: "bg-dec-approval/10", border: "border-dec-approval/30", dot: "bg-dec-approval" },
  restrict: { text: "text-dec-restrict", bg: "bg-dec-restrict/10", border: "border-dec-restrict/30", dot: "bg-dec-restrict" },
  audit: { text: "text-dec-audit", bg: "bg-dec-audit/10", border: "border-dec-audit/30", dot: "bg-dec-audit" },
  ok: { text: "text-ok", bg: "bg-ok/10", border: "border-ok/30", dot: "bg-ok" },
  warn: { text: "text-warn", bg: "bg-warn/10", border: "border-warn/30", dot: "bg-warn" },
  danger: { text: "text-danger", bg: "bg-danger/10", border: "border-danger/30", dot: "bg-danger" },
};

export const TRUST_META: Record<TrustLevel, { label: string; tone: Tone; description: string }> = {
  TRUSTED: { label: "Trusted", tone: "trusted", description: "First-party or explicitly trusted. May provide instructions." },
  APPROVED: { label: "Approved", tone: "approved", description: "Approved for the listed capabilities only." },
  EXTERNAL: { label: "External", tone: "external", description: "Known third party. Content is treated as data, never instructions." },
  UNKNOWN: { label: "Unknown", tone: "unknown", description: "Not yet classified." },
  SUSPICIOUS: { label: "Suspicious", tone: "suspicious", description: "Evidence of manipulative or malicious content." },
  BLOCKED: { label: "Blocked", tone: "blocked", description: "Must not be consumed or contacted." },
};

export const SEVERITY_META: Record<Severity, { label: string; tone: Tone; rank: number }> = {
  critical: { label: "Critical", tone: "critical", rank: 4 },
  high: { label: "High", tone: "high", rank: 3 },
  medium: { label: "Medium", tone: "medium", rank: 2 },
  low: { label: "Low", tone: "low", rank: 1 },
  info: { label: "Info", tone: "info", rank: 0 },
};

export const DECISION_META: Record<Decision, { label: string; tone: Tone; description: string }> = {
  ALLOW: { label: "Allow", tone: "allow", description: "Action permitted." },
  DENY: { label: "Deny", tone: "deny", description: "Action blocked at the enforcement boundary." },
  REQUIRE_APPROVAL: { label: "Needs approval", tone: "approval", description: "Paused until a human approves." },
  RESTRICT: { label: "Restrict", tone: "restrict", description: "Permitted with constraints." },
  AUDIT: { label: "Audit", tone: "audit", description: "Permitted and recorded for review." },
};

export const ENFORCEMENT_META: Record<EnforcementMode, { label: string; tone: Tone; description: string }> = {
  enforced: { label: "Enforced", tone: "ok", description: "Decided at a real execution boundary that honours the decision." },
  advisory: { label: "Advisory", tone: "warn", description: "Decision returned, but the integration may not honour it." },
  observed: { label: "Observed only", tone: "neutral", description: "Reported after the fact — nothing could be prevented." },
};

export const FINDING_CATEGORIES = [
  "prompt_injection", "instruction_override", "credential_access", "secret_exposure", "exfiltration", "untrusted_source",
  "suspicious_tool_use", "dangerous_permissions", "lethal_trifecta", "anomaly", "cross_agent_contamination",
  "policy_violation", "destination_risk", "permission_escalation",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const FINDING_CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt injection",
  instruction_override: "Instruction override",
  credential_access: "Credential access",
  secret_exposure: "Secret exposure",
  exfiltration: "Exfiltration",
  untrusted_source: "Untrusted source",
  suspicious_tool_use: "Suspicious tool use",
  dangerous_permissions: "Dangerous permissions",
  lethal_trifecta: "Lethal trifecta",
  anomaly: "Anomaly",
  cross_agent_contamination: "Cross-agent contamination",
  policy_violation: "Policy violation",
  destination_risk: "Destination risk",
  permission_escalation: "Permission escalation",
};

export function trustTone(level?: string | null): Tone {
  return (level && TRUST_META[level as TrustLevel]?.tone) || "unknown";
}
export function severityTone(sev?: string | null): Tone {
  return (sev && SEVERITY_META[sev as Severity]?.tone) || "info";
}
export function decisionTone(dec?: string | null): Tone {
  return (dec && DECISION_META[dec as Decision]?.tone) || "neutral";
}
export function humanize(value?: string | null): string {
  if (!value) return "—";
  return value.replace(/[_.]/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export * from "./vocabulary";
export * from "./secretTypes";
