import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { utcDayLabel } from "../ActivityCharts";
import { buildKpis, claudeCodeCommands, formatRemaining, formatShare, includeSimulatedFrom, onboardingStage, windowFrom, withSim } from "../meta";
import { OverviewPage } from "../OverviewPage";
import type { Overview } from "../types";

const zeroSev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
const zeroDec = { ALLOW: 0, DENY: 0, REQUIRE_APPROVAL: 0, RESTRICT: 0, AUDIT: 0 };
const hours = Array.from({ length: 24 }, (_, i) => new Date(Date.UTC(2026, 10, 10, 10 + i)).toISOString());

function overview(patch: Partial<Overview> = {}): Overview {
  return {
    window: "24h",
    bucket: "hour",
    since: hours[0],
    until: "2026-11-11T10:00:00Z",
    generated_at: "2026-11-11T09:40:00Z",
    include_simulated: true,
    posture: {
      agents_total: 1,
      agents_active: 1,
      sessions_active: 2,
      trifecta_sessions: 1,
      sources_by_trust: { TRUSTED: 1, APPROVED: 0, EXTERNAL: 0, UNKNOWN: 2, SUSPICIOUS: 1, BLOCKED: 0 },
      open_findings_by_severity: { ...zeroSev, critical: 2, high: 1, medium: 3 },
      open_findings_total: 6,
      pending_approvals: 1,
      open_incidents: 1,
      decisions_by_outcome: { ...zeroDec, ALLOW: 2, DENY: 1, REQUIRE_APPROVAL: 1 },
      decisions_total: 4,
      enforcement_coverage: { total: 4, enforced: 3, advisory: 0, observed: 1, share: 0.75 },
      blocked_actions: 1,
    },
    series: {
      bucket: "hour",
      events: hours.map((t, i) => ({ t, live: i === 23 ? 12 : 0, simulated: 0 })),
      findings_by_severity: hours.map((t, i) => ({ t, ...zeroSev, critical: i === 23 ? 2 : 0 })),
      decisions_by_outcome: hours.map((t, i) => ({ t, ...zeroDec, DENY: i === 23 ? 1 : 0 })),
    },
    top_risky_agents: [
      {
        id: "agt_1", name: "coder", environment: "development", framework: "claude_code", status: "active", risk_score: 100, risk_level: "critical",
        reason: "Credential from context sent outbound", reason_detail: "A secret that entered this session reappeared in an outbound call.",
        session_id: "asn_1", trifecta: true, open_findings: 6, last_seen_at: "2026-11-11T09:39:00Z", is_simulation: false,
      },
    ],
    recent_findings: [],
    attention: {
      pending_approvals: [{ id: "apr_1", summary: "coder wants to WebFetch hooks.webhook.site", agent: { id: "agt_1", name: "coder" }, session_id: "asn_2", tool_name: "WebFetch", requested_at: "2026-11-11T09:39:00Z", expires_at: "2026-11-11T09:49:00Z", seconds_remaining: 540, is_simulation: false }],
      critical_findings: [{ id: "fnd_1", title: "Credential read in this session attempted to send to webhook.site", severity: "critical", category: "exfiltration", status: "open", rule_id: "CTX-CRED-FLOW-001", agent: { id: "agt_1", name: "coder" }, session_id: "asn_1", incident_id: "inc_1", occurrence_count: 1, first_seen_at: "2026-11-11T09:39:00Z", last_seen_at: "2026-11-11T09:39:00Z", is_simulation: false }],
      open_incidents: [{ id: "inc_1", number: 1, title: "Lethal trifecta conditions in a session of coder", severity: "critical", status: "open", opened_at: "2026-11-11T09:39:00Z", primary_agent: { id: "agt_1", name: "coder" }, is_simulation: false }],
    },
    recent_blocked_or_paused: [
      { invocation_id: "inv_1", session_id: "asn_1", agent: { id: "agt_1", name: "coder" }, tool: { name: "WebFetch", category: "http", server: null }, action: "send POST to webhook.site", decision: "DENY", enforcement: "enforced", status: "denied", outcome: "Blocked before it ran", reason: 'DENY by policy "Block credential exfiltration"', policy_decision_id: "dec_1", approval_id: null, at: "2026-11-11T09:39:00Z", is_simulation: false },
      { invocation_id: "inv_2", session_id: "asn_3", agent: { id: "agt_1", name: "coder" }, tool: { name: "Bash", category: "shell", server: null }, action: "run rm -rf ~/", decision: "DENY", enforcement: "observed", status: "completed", outcome: "Policy denied it, but the call was reported after it ran; nothing was prevented", reason: null, policy_decision_id: "dec_2", approval_id: null, at: "2026-11-11T09:30:00Z", is_simulation: true },
    ],
    integrations: [{ id: "int_1", kind: "claude_code", name: "claude_code", status: "connected", status_reason: "Sent events in the last 24 hours.", last_event_at: "2026-11-11T09:39:00Z", event_count: 12, decision_count: 4, enforcement_capable: true, enforcement_note: "The PreToolUse hook asks ContextOS before each tool call.", last_error: null }],
    recent_activity: [{ id: "aud_1", seq: 3, occurred_at: "2026-11-11T09:39:00Z", actor_type: "api_key", actor_id: "key_1", actor_label: "API key “laptop”", action: "tool.denied", target_type: "tool_invocation", target_id: "inv_1", details: { session_id: "asn_1" } }],
    onboarding: { has_agents: true, has_api_key: true, has_events: true, has_simulations: true },
    simulated: { events: 3, findings: 1, decisions: 1 },
    ...patch,
  };
}

describe("overview presentation logic", () => {
  const qs = (s: string) => new URLSearchParams(s);

  it("reads the window and simulated toggle from the URL with safe defaults", () => {
    expect(windowFrom(qs(""))).toBe("24h");
    expect(windowFrom(qs("window=30d"))).toBe("30d");
    expect(windowFrom(qs("window=1y"))).toBe("24h");
    expect(includeSimulatedFrom(qs(""))).toBe(true);
    expect(includeSimulatedFrom(qs("sim=0"))).toBe(false);
    expect(withSim("/approvals", true)).toBe("/approvals?sim=1");
    expect(withSim("/intelligence?severity=high", true)).toBe("/intelligence?severity=high&sim=1");
    expect(withSim("/incidents", false)).toBe("/incidents");
  });

  it("builds KPIs from server numbers only, with honest enforcement wording", () => {
    const kpis = Object.fromEntries(buildKpis(overview()).map((k) => [k.key, k]));
    expect(kpis.findings.value).toBe("3");
    expect(kpis.findings.tone).toBe("critical");
    expect(kpis.findings.href).toBe("/intelligence?severity=critical&severity=high&sim=1");
    expect(kpis.blocked.explanation).toMatch(/Advisory and observed denials are not counted/);
    expect(kpis.trifecta.explanation).toMatch(/not proof of an attack/);
    expect(kpis.coverage.value).toBe("75%");
    expect(kpis.coverage.hint).toBe("3 of 4 decisions enforced · 1 not");
    const quiet = overview({ posture: { ...overview().posture, enforcement_coverage: { total: 0, enforced: 0, advisory: 0, observed: 0, share: null } } });
    expect(buildKpis(quiet).find((k) => k.key === "coverage")?.value).toBe("—");
  });

  it("formats shares, deadlines, UTC day labels and the setup commands", () => {
    expect(formatShare(1)).toBe("100%");
    expect(formatShare(0)).toBe("0%");
    expect(formatShare(0.6667)).toBe("66.7%");
    expect(formatShare(0.9999)).toBe("99.9%");
    expect(formatShare(0.0001)).toBe("0.1%");
    expect(formatRemaining(45)).toBe("45s left");
    expect(formatRemaining(540)).toBe("9m left");
    expect(formatRemaining(null)).toBe("No deadline");
    expect(utcDayLabel("2026-11-05T00:00:00Z")).toBe("5 Nov");
    expect(claudeCodeCommands("https://ctx.example")).toContain("contextos init --url https://ctx.example --api-key ctxk_... --claude-code");
  });

  it("decides the onboarding stage from persisted state", () => {
    expect(onboardingStage({ has_agents: false, has_api_key: true, has_events: false, has_simulations: false })).toBe("empty");
    expect(onboardingStage({ has_agents: true, has_api_key: true, has_events: false, has_simulations: false })).toBe("empty");
    expect(onboardingStage({ has_agents: false, has_api_key: true, has_events: false, has_simulations: true })).toBe("simulated_only");
    expect(onboardingStage({ has_agents: true, has_api_key: true, has_events: true, has_simulations: false })).toBe("live");
  });
});

type Reply = { status?: number; body?: unknown };
let handler: (url: string) => Reply;
const calls: string[] = [];

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      calls.push(url);
      const reply = handler(url);
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status ?? 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});

afterEach(() => vi.unstubAllGlobals());

function renderAt(path = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path="/" element={<OverviewPage />} />
            </Routes>
          </ToastProvider>
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("OverviewPage", () => {
  it("shows posture, attention and honest outcomes for denied calls", async () => {
    handler = () => ({ body: overview() });
    renderAt();
    expect(await screen.findByText("coder wants to WebFetch hooks.webhook.site")).toBeInTheDocument();
    expect(calls[0]).toBe("/api/v1/overview?window=24h&include_simulated=true");

    const summary = screen.getByRole("region", { name: "Security summary" });
    expect(within(summary).getByRole("link", { name: /Pending approvals/ })).toHaveAttribute("href", "/approvals?sim=1");
    expect(within(summary).getByText("75%")).toBeInTheDocument();

    expect(screen.getByText("Blocked before it ran")).toBeInTheDocument();
    expect(screen.getByText(/nothing was prevented/)).toBeInTheDocument();
    expect(screen.getByText("Credential from context sent outbound")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "Risk score of coder" })).toHaveAttribute("aria-valuenow", "100");
    expect(screen.getByText(/Includes 3 simulated events/)).toBeInTheDocument();
    expect(screen.getAllByText("Simulation").length).toBeGreaterThan(0);
  });

  it("switches window and excludes simulated rows through the URL", async () => {
    handler = () => ({ body: overview() });
    renderAt("/?window=7d");
    await screen.findByText("Blocked before it ran");
    expect(calls[0]).toContain("window=7d");
    fireEvent.click(screen.getByRole("checkbox", { name: "Include simulated" }));
    await waitFor(() => expect(calls.some((c) => c.includes("include_simulated=false"))).toBe(true));
    fireEvent.click(screen.getByRole("radio", { name: "30d" }));
    await waitFor(() => expect(calls.some((c) => c.includes("window=30d") && c.includes("include_simulated=false"))).toBe(true));
  });

  it("replaces the dashboard with a setup checklist when nothing has reported", async () => {
    handler = () => ({ body: overview({ onboarding: { has_agents: false, has_api_key: true, has_events: false, has_simulations: false }, simulated: { events: 0, findings: 0, decisions: 0 } }) });
    renderAt();
    expect(await screen.findByRole("heading", { name: "Connect your first agent" })).toBeInTheDocument();
    expect(screen.getByText(/--claude-code/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open API keys" })).toHaveAttribute("href", "/settings?tab=api-keys");
    expect(screen.getByRole("link", { name: "Open the Simulation Lab" })).toHaveAttribute("href", "/simulation");
    expect(screen.getAllByText("Done:")).toHaveLength(1); // only the API key exists
    expect(screen.getAllByText("To do:")).toHaveLength(2);
    expect(screen.queryByRole("region", { name: "Security summary" })).not.toBeInTheDocument();
  });

  it("explains empty panels instead of showing blanks", async () => {
    const base = overview();
    handler = () => ({
      body: overview({
        attention: { pending_approvals: [], critical_findings: [], open_incidents: [] },
        recent_blocked_or_paused: [],
        top_risky_agents: [],
        posture: { ...base.posture, pending_approvals: 0, open_incidents: 0, open_findings_by_severity: zeroSev, open_findings_total: 0 },
      }),
    });
    renderAt();
    expect(await screen.findByText("Nothing needs attention right now")).toBeInTheDocument();
    expect(screen.getByText("No tool call was denied or paused in the last 24 hours")).toBeInTheDocument();
    expect(screen.getByText("No agent carries risk right now")).toBeInTheDocument();
  });

  it("shows an error with retry when the overview cannot be loaded", async () => {
    handler = () => ({ status: 500, body: { error: { code: "internal", message: "Database unavailable" } } });
    renderAt();
    expect(await screen.findByText("Database unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
