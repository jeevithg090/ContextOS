import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { FindingDetailPage } from "../FindingDetailPage";
import { IntelligencePage } from "../IntelligencePage";
import type { FindingDetail, FindingStats, FindingSummary } from "../types";

let permissions: string[] = ["read", "write"];

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

const SUMMARY: FindingSummary = {
  id: "fnd_1",
  title: "Credential sent to an unknown destination",
  category: "exfiltration",
  rule_id: "CTX-CRED-FLOW-001",
  severity: "critical",
  confidence: 0.95,
  status: "open",
  agent: { id: "agt_1", name: "coder" },
  session: { id: "ses_1", external_session_id: "sess-x" },
  source: { id: "src_1", source_type: "file", identifier: "/work/app/.env", display_name: ".env", trust_level: "TRUSTED" },
  incident: null,
  occurrence_count: 3,
  first_seen_at: "2026-11-10T10:00:00Z",
  last_seen_at: "2026-11-10T10:05:00Z",
  is_simulation: false,
};

const STATS: FindingStats = {
  window: "7d",
  bucket: "day",
  since: "2026-11-05T00:00:00Z",
  until: "2026-11-11T09:00:00Z",
  include_simulated: false,
  simulated_open: 0,
  open: { total: 1, needs_triage: 1, acknowledged: 0, by_severity: { ...zero, critical: 1 }, by_category: [{ category: "exfiltration", count: 1 }], oldest_first_seen_at: "2026-11-10T10:00:00Z" },
  period: {
    total: 1,
    by_severity: { ...zero, critical: 1 },
    by_category: [{ category: "exfiltration", count: 1 }],
    by_status: { open: 1, acknowledged: 0, resolved: 0, false_positive: 0 },
    trend: Array.from({ length: 7 }, (_, i) => ({ t: new Date(Date.UTC(2026, 10, 5 + i)).toISOString(), ...zero, total: 0 })),
    top_sources: [],
    mttr: { mean_seconds: null, median_seconds: null, resolved_count: 0 },
  },
  agents: [{ id: "agt_1", name: "coder", count: 1 }],
  categories: [{ category: "exfiltration", count: 1 }],
};

const DETAIL: FindingDetail = {
  ...SUMMARY,
  explanation: "A credential read from .env was sent to a destination nobody has classified.",
  remediation: "Rotate the token and block the destination.",
  resolution_note: null,
  resolved_by: null,
  evidence: [
    { type: "tool_invocation", id: "inv_1", label: "WebFetch", session_id: "ses_1", excerpt: "token=[REDACTED:github_token]", detail: "Outbound body carried the credential", found: true },
    { type: "context_item", id: "ci_gone", label: null, session_id: null, excerpt: null, detail: null, found: false },
  ],
  related: {
    agent: { id: "agt_1", name: "coder", framework: "claude_code", environment: "dev", status: "active" },
    session: { id: "ses_1", external_session_id: "sess-x", status: "active", started_at: "2026-11-10T09:59:00Z", risk_score: 80, risk_level: "critical", trifecta: true },
    source: null,
    context_item: null,
    tool_invocation: null,
    decision: null,
    destination: null,
    incident: null,
    tasks: [],
  },
  history: [],
  allowed_transitions: ["acknowledged", "resolved", "false_positive"],
  incident_candidates: [{ id: "inc_1", number: 7, title: "Poisoned README", status: "open", severity: "high", reason: "Same session" }],
  provenance_note: "Observed relationships, not causation.",
};

type Reply = { status?: number; body?: unknown };
let handler: (url: string, method: string, body: unknown) => Reply;
const calls: Array<{ url: string; method: string; body: unknown }> = [];

beforeEach(() => {
  permissions = ["read", "write"];
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ url, method, body });
      const reply = handler(url, method, body);
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

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TestRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path="/intelligence" element={<IntelligencePage />} />
              <Route path="/intelligence/:findingId" element={<FindingDetailPage />} />
              <Route path="/work/tasks/:taskId" element={<p>Task page</p>} />
            </Routes>
          </ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
}

describe("IntelligencePage", () => {
  it("shows the backlog and filters the list from the summary tiles", async () => {
    handler = (url) => (url.includes("/findings/stats") ? { body: STATS } : { body: { items: [SUMMARY], total: 1, limit: 50, offset: 0 } });
    renderAt("/intelligence");
    expect(await screen.findByText("Credential sent to an unknown destination")).toBeInTheDocument();
    const firstList = calls.find((c) => c.url.startsWith("/api/v1/findings?"));
    expect(firstList?.url).toContain("status=open&status=acknowledged");

    fireEvent.click(screen.getByRole("button", { name: /Open critical/ }));
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/api/v1/findings?") && c.url.includes("severity=critical"))).toBe(true));
  });

  it("explains an empty backlog instead of showing a blank table", async () => {
    handler = (url) =>
      url.includes("/findings/stats")
        ? { body: { ...STATS, open: { ...STATS.open, total: 0, needs_triage: 0, by_severity: zero, by_category: [] } } }
        : { body: { items: [], total: 0, limit: 50, offset: 0 } };
    renderAt("/intelligence");
    expect(await screen.findByText("Nothing needs attention")).toBeInTheDocument();
  });
});

describe("FindingDetailPage", () => {
  it("renders explanation, confidence, evidence and investigation links", async () => {
    handler = () => ({ body: DETAIL });
    renderAt("/intelligence/fnd_1");
    expect(await screen.findByText(/sent to a destination nobody has classified/)).toBeInTheDocument();
    expect(screen.getByText("High · 95%")).toBeInTheDocument();
    expect(screen.getByText("The referenced record is no longer available.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View in provenance graph/ })).toHaveAttribute("href", "/provenance?finding=fnd_1");
    expect(screen.getByRole("link", { name: /Replay session/ })).toHaveAttribute("href", "/replay/ses_1");
  });

  it("acknowledges without a dialog and requires a reason for a false positive", async () => {
    handler = (_url, method) => (method === "PATCH" ? { body: { ...DETAIL, status: "acknowledged" } } : { body: DETAIL });
    renderAt("/intelligence/fnd_1");
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "acknowledged" }));

    fireEvent.click(screen.getByRole("button", { name: "False positive" }));
    const confirm = await screen.findByRole("button", { name: "Mark as false positive" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Why is this not suspicious?"), { target: { value: "Security training example" } });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(calls.filter((c) => c.method === "PATCH").at(-1)?.body).toEqual({ status: "false_positive", resolution_note: "Security training example" }),
    );
  });

  it("creates a remediation task and opens it", async () => {
    handler = (url, method) =>
      method === "POST" && url.endsWith("/workspace/tasks/from-finding")
        ? { status: 201, body: { created: true, task: { id: "tsk_1", key: "CTX-1", title: "Remediate" } } }
        : { body: DETAIL };
    renderAt("/intelligence/fnd_1");
    fireEvent.click(await screen.findByRole("button", { name: "Create remediation task" }));
    expect(await screen.findByText("Task page")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ finding_id: "fnd_1" });
  });

  it("shows the workspace's refusal instead of failing silently", async () => {
    handler = (_url, method) =>
      method === "POST" ? { status: 409, body: { error: { code: "conflict", message: "The remediation board is archived" } } } : { body: DETAIL };
    renderAt("/intelligence/fnd_1");
    fireEvent.click(await screen.findByRole("button", { name: "Create remediation task" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The remediation board is archived");
  });

  it("is read-only without write permission, and says when a finding does not exist", async () => {
    permissions = ["read"];
    handler = () => ({ body: DETAIL });
    const { unmount } = renderAt("/intelligence/fnd_1");
    expect(await screen.findByText(/sent to a destination nobody has classified/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create remediation task" })).not.toBeInTheDocument();
    unmount();

    handler = () => ({ status: 404, body: { error: { code: "not_found", message: "Finding 'fnd_x' not found" } } });
    renderAt("/intelligence/fnd_x");
    expect(await screen.findByText("Finding not found")).toBeInTheDocument();
  });
});
