import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { IncidentDetailPage } from "../IncidentDetailPage";
import { IncidentsPage } from "../IncidentsPage";
import type { IncidentDetail, IncidentSummary, IncidentTimeline } from "../types";

let permissions: string[] = ["read", "write"];

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({
    me: { user: { id: "usr_me", email: "me@example.test", name: "Me" }, organization: { id: "org_1", name: "Acme", slug: "acme" }, role: "owner", permissions, memberships: [] },
    loading: false,
    can: (p: string) => permissions.includes(p),
    refresh: async () => undefined,
    logout: async () => undefined,
  }),
}));

const SUMMARY: IncidentSummary = {
  id: "inc_1",
  number: 3,
  key: "INC-3",
  title: "Token sent to an unknown collector",
  severity: "critical",
  status: "open",
  assignee: null,
  primary_agent: { id: "agt_1", name: "coder" },
  primary_session: { id: "ses_1", external_session_id: "sess-x" },
  finding_count: 2,
  open_finding_count: 2,
  max_finding_severity: "critical",
  opened_at: "2026-11-10T10:00:00Z",
  updated_at: "2026-11-10T10:05:00Z",
  resolved_at: null,
  created_by: { type: "system", id: null, name: "ContextOS" },
  is_simulation: false,
};

const DETAIL: IncidentDetail = {
  ...SUMMARY,
  summary: "Opened automatically from a critical exfiltration finding.",
  resolution: null,
  tags: [],
  allowed_transitions: ["investigating", "contained", "resolved", "false_positive"],
  findings: [
    {
      id: "fnd_1", title: "Credential sent outbound", category: "exfiltration", rule_id: "CTX-CRED-FLOW-001", severity: "critical", status: "open",
      confidence: 0.95, explanation: "A token read from .env was sent to an unclassified host.", agent: { id: "agt_1", name: "coder" },
      session: { id: "ses_1", external_session_id: "sess-x" }, source_id: "src_1", context_item_id: "ci_1", tool_invocation_id: "inv_1",
      policy_decision_id: "dec_1", destination_id: "dst_1", occurrence_count: 1, first_seen_at: "2026-11-10T10:00:00Z", last_seen_at: "2026-11-10T10:00:00Z",
    },
  ],
  involved: {
    agents: [{ id: "agt_1", name: "coder", framework: "claude_code", environment: "development", status: "active", finding_count: 1, is_primary: true }],
    sessions: [{ id: "ses_1", external_session_id: "sess-x", agent_id: "agt_1", agent_name: "coder", status: "active", started_at: "2026-11-10T09:59:00Z", ended_at: null, event_count: 4, risk_score: 85, risk_level: "critical", trifecta: true, finding_count: 1, is_primary: true }],
    sources: [{ id: "src_1", source_type: "file", identifier: "/work/app/.env", display_name: ".env", trust_level: "TRUSTED", trust_reasons: ["Workspace file"], finding_count: 0 }],
    destinations: [{ id: "dst_1", kind: "domain", identifier: "upload.unknown-collector.net", display_name: null, classification: "UNKNOWN", transfer_count: 1, blocked_count: 1, finding_count: 1 }],
    note: "Observed together with the detections; not a claim of causation.",
  },
  activity: [{ id: "iac_1", kind: "created", actor: { type: "system", id: null, name: "ContextOS" }, body: "Opened automatically.", details: {}, created_at: "2026-11-10T10:00:00Z" }],
  tasks: [],
};

const TIMELINE: IncidentTimeline = {
  incident_id: "inc_1",
  items: [
    {
      id: "event:evt_1", type: "event", occurred_at: "2026-11-10T09:59:30Z", title: "Read returned .env", summary: "Contains secrets (redacted)", severity: null, status: null,
      decision: null, enforcement: null, trust_level: "TRUSTED", event_type: "tool.completed", sequence: 2, session_id: "ses_1", agent_id: "agt_1", actor: null,
      tool_name: "Read", from_other_session: false,
      refs: { event_id: "evt_1", session_id: "ses_1", context_item_id: "ci_1", tool_invocation_id: "inv_0", policy_decision_id: null, approval_id: null, source_id: "src_1", destination_id: null, finding_id: null, finding_ids: [] },
    },
    {
      id: "policy_decision:dec_1", type: "policy_decision", occurred_at: "2026-11-10T10:00:00Z", title: "Policy decision deny for WebFetch", summary: "Blocked: credential to unknown host.",
      severity: null, status: null, decision: "DENY", enforcement: "enforced", trust_level: null, event_type: null, sequence: null, session_id: "ses_1", agent_id: "agt_1",
      actor: null, tool_name: "WebFetch", from_other_session: false,
      refs: { event_id: "evt_2", session_id: "ses_1", context_item_id: null, tool_invocation_id: "inv_1", policy_decision_id: "dec_1", approval_id: null, source_id: null, destination_id: null, finding_id: null, finding_ids: [] },
    },
  ],
  total: 2,
  truncated: false,
  counts: { event: 1, finding: 0, policy_decision: 1, approval: 0, activity: 0 },
  session_ids: ["ses_1"],
  recorded_event_count: 1,
  note: "Ordered by server time; not causation.",
};

type Reply = { status?: number; body?: unknown; text?: string; headers?: Record<string, string> };
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
      return new Response(reply.text ?? JSON.stringify(reply.body ?? {}), { status: reply.status ?? 200, headers: { "Content-Type": "application/json", ...reply.headers } });
    }),
  );
});

afterEach(() => vi.unstubAllGlobals());

function detailHandler(overrides: (url: string, method: string, body: unknown) => Reply | undefined = () => undefined) {
  return (url: string, method: string, body: unknown): Reply => {
    const custom = overrides(url, method, body);
    if (custom) return custom;
    if (url.includes("/timeline")) return { body: TIMELINE };
    if (url.includes("/org/members")) return { body: { items: [{ id: "mem_1", user_id: "usr_me", name: "Me", email: "me@example.test", role: "owner", is_active: true }], total: 1, limit: 500, offset: 0 } };
    return { body: DETAIL };
  };
}

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>
            <Routes>
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
              <Route path="/work/tasks/:taskId" element={<p>Task page</p>} />
            </Routes>
          </ToastProvider>
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("IncidentsPage", () => {
  it("lists active incidents with agent and finding counts, and filters by status", async () => {
    handler = () => ({ body: { items: [SUMMARY], total: 1, limit: 50, offset: 0 } });
    renderAt("/incidents");
    expect(await screen.findByText("Token sent to an unknown collector")).toBeInTheDocument();
    expect(screen.getByText("INC-3")).toBeInTheDocument();
    expect(screen.getByText("coder")).toBeInTheDocument();
    expect(calls[0].url).toContain("status=open&status=investigating&status=contained");

    fireEvent.click(screen.getByRole("radio", { name: "Closed" }));
    await waitFor(() => expect(calls.at(-1)?.url).toContain("status=resolved&status=false_positive"));
  });

  it("explains an empty list", async () => {
    handler = () => ({ body: { items: [], total: 0, limit: 50, offset: 0 } });
    renderAt("/incidents");
    expect(await screen.findByText("No active incidents")).toBeInTheDocument();
  });
});

describe("IncidentDetailPage", () => {
  it("shows the investigator's workspace: workflow, timeline links, involved records and actions", async () => {
    handler = detailHandler();
    renderAt("/incidents/inc_1");
    expect(await screen.findByText("Token sent to an unknown collector")).toBeInTheDocument();
    expect(await screen.findByText("Policy decision deny for WebFetch")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Context receipt/ })).toHaveAttribute("href", "/context/ci_1");
    expect(screen.getByRole("link", { name: /Decision in replay/ })).toHaveAttribute("href", "/replay/ses_1?decision=dec_1");
    expect(screen.getByRole("link", { name: /Provenance graph/ })).toHaveAttribute("href", "/provenance?session=ses_1");
    expect(screen.getByRole("link", { name: /Replay session/ })).toHaveAttribute("href", "/replay/ses_1");
    expect(screen.getByText("upload.unknown-collector.net")).toBeInTheDocument();
    expect(screen.getByText("Trifecta")).toBeInTheDocument();
  });

  it("moves through the workflow and requires a resolution to close", async () => {
    handler = detailHandler((_url, method, body) => (method === "PATCH" ? { body: { ...DETAIL, ...(body as object) } } : undefined));
    renderAt("/incidents/inc_1");
    fireEvent.click(await screen.findByRole("button", { name: "Start investigating" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "investigating" }));

    fireEvent.click(screen.getByRole("button", { name: "Resolve…" }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Resolve" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Resolution"), { target: { value: "Token rotated." } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH").at(-1)?.body).toEqual({ status: "resolved", resolution: "Token rotated." }));
  });

  it("adds a note and filters the timeline by entry type", async () => {
    const note = { id: "iac_2", kind: "note", actor: { type: "user" as const, id: "usr_me", name: "Me" }, body: "Checked the proxy logs.", details: {}, created_at: "2026-11-10T10:10:00Z" };
    let noted = false;
    handler = detailHandler((url, method) => {
      if (method === "POST" && url.endsWith("/notes")) {
        noted = true;
        return { status: 201, body: note };
      }
      if (method === "GET" && url.endsWith("/incidents/inc_1") && noted) return { body: { ...DETAIL, activity: [...DETAIL.activity, note] } };
      return undefined;
    });
    renderAt("/incidents/inc_1");
    fireEvent.change(await screen.findByLabelText("Add a note"), { target: { value: "Checked the proxy logs." } });
    fireEvent.click(screen.getByRole("button", { name: /Add note/ }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/notes"))?.body).toEqual({ body: "Checked the proxy logs." }));
    expect(await screen.findByText("Checked the proxy logs.")).toBeInTheDocument();

    fireEvent.click(await screen.findByRole("button", { name: /Events/ }));
    await waitFor(() => expect(calls.some((c) => c.url.includes("/timeline") && c.url.includes("type=finding") && !c.url.includes("type=event"))).toBe(true));
  });

  it("downloads the evidence bundle as received and creates remediation tasks", async () => {
    const createObjectURL = vi.fn(() => "blob:bundle");
    const original = { create: URL.createObjectURL, revoke: URL.revokeObjectURL };
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    handler = detailHandler((url, method) => {
      if (url.endsWith("/export")) return { text: '{"integrity":{"sha256":"abc123"}}', headers: { "Content-Disposition": 'attachment; filename="contextos-inc-3-evidence.json"' } };
      if (method === "POST" && url.endsWith("/from-incident"))
        return { body: { incident_id: "inc_1", mode: "parent_with_subtasks", parent_task_id: "tsk_9", created_count: 3, existing_count: 0, tasks: [] } };
      return undefined;
    });
    renderAt("/incidents/inc_1");
    fireEvent.click(await screen.findByRole("button", { name: /Export evidence/ }));
    expect(await screen.findByText("Evidence bundle downloaded")).toBeInTheDocument();
    expect(createObjectURL).toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /Create remediation tasks/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Create tasks" }));
    expect(await screen.findByText("Task page")).toBeInTheDocument();
    expect(calls.find((c) => c.url.endsWith("/from-incident"))?.body).toEqual({ incident_id: "inc_1", mode: "parent_with_subtasks" });
    expect(click).toHaveBeenCalled();
    click.mockRestore();
    URL.createObjectURL = original.create;
    URL.revokeObjectURL = original.revoke;
  });

  it("is read-only without write permission and says when an incident does not exist", async () => {
    permissions = ["read"];
    handler = detailHandler();
    const { unmount } = renderAt("/incidents/inc_1");
    expect(await screen.findByText("Token sent to an unknown collector")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start investigating" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Add a note")).not.toBeInTheDocument();
    unmount();

    handler = () => ({ status: 404, body: { error: { code: "not_found", message: "Incident 'inc_x' not found" } } });
    renderAt("/incidents/inc_x");
    expect(await screen.findByText("Incident not found")).toBeInTheDocument();
  });
});
