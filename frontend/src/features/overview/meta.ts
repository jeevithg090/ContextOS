/**
 * Overview presentation logic (pure): URL state, KPI definitions with their one-line explanations,
 * onboarding stage and labels. Kept free of React so it is unit-tested directly.
 *
 * URL state: ?window=24h|7d|30d (default 24h) and ?sim=0 to exclude Simulation Lab rows (included by
 * default so a fresh install that only ran simulations still shows its results, clearly labelled).
 */
import type { Tone } from "@/lib/domain";
import { formatNumber, pluralize } from "@/lib/format";
import type { Onboarding, Overview, OverviewWindow } from "./types";

export const WINDOWS: Array<{ value: OverviewWindow; label: string; long: string }> = [
  { value: "24h", label: "24h", long: "the last 24 hours" },
  { value: "7d", label: "7d", long: "the last 7 days" },
  { value: "30d", label: "30d", long: "the last 30 days" },
];

export function windowFrom(params: URLSearchParams): OverviewWindow {
  const value = params.get("window");
  return WINDOWS.find((w) => w.value === value)?.value ?? "24h";
}

export function windowLong(window: OverviewWindow): string {
  return WINDOWS.find((w) => w.value === window)?.long ?? window;
}

export function includeSimulatedFrom(params: URLSearchParams): boolean {
  return params.get("sim") !== "0";
}

/** Appends `sim=1` to list-page links when simulated rows are on, so the target shows the same rows. */
export function withSim(href: string, includeSimulated: boolean): string {
  if (!includeSimulated) return href;
  return href + (href.includes("?") ? "&" : "?") + "sim=1";
}

export interface Kpi {
  key: string;
  label: string;
  value: string;
  tone?: Tone;
  hint: string;
  /** What the number counts and where it comes from (tooltip / accessible description). */
  explanation: string;
  href: string;
}

/** Percentage with one decimal at most. Never rounds a partial share up to 100% or down to 0%. */
export function formatShare(share: number | null): string {
  if (share === null) return "—";
  if (share >= 1) return "100%";
  if (share <= 0) return "0%";
  const pct = Math.min(99.9, Math.max(0.1, Math.round(share * 1000) / 10));
  return `${Number.isInteger(pct) ? pct.toFixed(0) : pct.toFixed(1)}%`;
}

export function buildKpis(data: Overview): Kpi[] {
  const p = data.posture;
  const sim = data.include_simulated;
  const window = windowLong(data.window);
  const critical = p.open_findings_by_severity.critical ?? 0;
  const high = p.open_findings_by_severity.high ?? 0;
  const cov = p.enforcement_coverage;
  const notEnforced = cov.advisory + cov.observed;

  return [
    {
      key: "findings",
      label: "Critical & high findings",
      value: formatNumber(critical + high),
      tone: critical ? "critical" : high ? "high" : undefined,
      hint: critical + high ? `${formatNumber(critical)} critical · ${formatNumber(high)} high · ${formatNumber(p.open_findings_total)} open in all` : p.open_findings_total ? `${pluralize(p.open_findings_total, "lower-severity finding")} open` : "No open findings",
      explanation: "Open or acknowledged findings of critical or high severity, across all time.",
      href: withSim("/intelligence?severity=critical&severity=high", sim),
    },
    {
      key: "approvals",
      label: "Pending approvals",
      value: formatNumber(p.pending_approvals),
      tone: p.pending_approvals ? "approval" : undefined,
      hint: p.pending_approvals ? "Tool calls paused until a person decides" : "Nothing is waiting for a person",
      explanation: "Approval requests still pending and not past their deadline. Expired requests are not counted.",
      href: withSim("/approvals", sim),
    },
    {
      key: "incidents",
      label: "Open incidents",
      value: formatNumber(p.open_incidents),
      tone: p.open_incidents ? "high" : undefined,
      hint: p.open_incidents ? "Open, investigating or contained" : "No incident is open",
      explanation: "Incidents not yet resolved or closed as false positives.",
      href: withSim("/incidents", sim),
    },
    {
      key: "blocked",
      label: "Blocked actions",
      value: formatNumber(p.blocked_actions),
      tone: p.blocked_actions ? "deny" : undefined,
      hint: `Denied before running, in ${window}`,
      explanation: "Tool calls denied by policy at an integration that enforces decisions before the tool runs. Advisory and observed denials are not counted: nothing guaranteed they were stopped.",
      href: "#blocked-actions",
    },
    {
      key: "trifecta",
      label: "Trifecta sessions",
      value: formatNumber(p.trifecta_sessions),
      tone: p.trifecta_sessions ? "critical" : undefined,
      hint: `Active in ${window}`,
      explanation: "Sessions where sensitive data access, untrusted content and an outbound channel all occurred. A risk condition that makes exfiltration possible, not proof of an attack.",
      href: withSim("/agents?sort=risk", sim),
    },
    {
      key: "coverage",
      label: "Enforcement coverage",
      value: formatShare(cov.share),
      tone: cov.share === null ? undefined : cov.share >= 0.999 ? "ok" : cov.share >= 0.5 ? "warn" : "danger",
      hint: cov.total ? `${formatNumber(cov.enforced)} of ${pluralize(cov.total, "decision")} enforced${notEnforced ? ` · ${formatNumber(notEnforced)} not` : ""}` : `No policy decisions in ${window}`,
      explanation: "Share of policy decisions returned at an execution boundary that honours them. The rest were advisory (the integration may ignore them) or observed (reported after the tool ran).",
      href: "/integrations",
    },
  ];
}

export type OnboardingStage =
  /** Nothing to show yet: the checklist replaces the dashboard. */
  | "empty"
  /** Only Simulation Lab data exists; the dashboard shows it with a "connect a real agent" prompt. */
  | "simulated_only"
  /** Real events are flowing. */
  | "live";

export function onboardingStage(onboarding: Onboarding): OnboardingStage {
  if (onboarding.has_events) return "live";
  return onboarding.has_simulations ? "simulated_only" : "empty";
}

export const INTEGRATION_LABELS: Record<string, string> = {
  claude_code: "Claude Code",
  mcp_gateway: "MCP gateway",
  python_sdk: "Python SDK",
  custom: "Custom integration",
};

export function integrationLabel(kind: string): string {
  return INTEGRATION_LABELS[kind] ?? kind.replace(/[_-]/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function formatRemaining(seconds: number | null): string {
  if (seconds === null) return "No deadline";
  if (seconds < 60) return `${seconds}s left`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m left`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m left`;
}

/** The commands a developer runs to connect Claude Code (sdk/README.md, docs/integrations/claude-code.md). */
export function claudeCodeCommands(origin: string): string {
  return [
    "pip install -e sdk",
    `contextos init --url ${origin} --api-key ctxk_... --claude-code`,
    "contextos doctor",
  ].join("\n");
}
