import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, notFound, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { ReplayLabPage } from "../ReplayLabPage";
import type { Replay, ReplayPolicy, ReplaySessionSummary, ReplayStep, StepRefs } from "../types";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

afterEach(() => vi.unstubAllGlobals());

const AGENT = { id: "agt_payments", name: "payments-coder", framework: "claude_code", environment: "production", status: "active", is_simulation: false };

const SESSION_ROW: ReplaySessionSummary = {
  id: "ses_main",
  agent: AGENT,
  external_session_id: "sess-7f3a",
  status: "active",
  started_at: "2026-11-10T09:00:00Z",
  last_event_at: "2026-11-10T09:15:00Z",
  event_count: 3,
  risk_score: 72,
  risk_level: "high",
  trifecta: true,
  open_findings: 2,
  is_simulation: false,
};

const REFS: StepRefs = { context_item_id: null, tool_invocation_id: null, policy_decision_id: null, finding_ids: [], approval_id: null, child_session_id: null, source_id: null, destination_id: null };

function step(index: number, overrides: Partial<ReplayStep>): ReplayStep {
  return {
    index,
    sequence: index + 1,
    event_id: `evt_${index}`,
    event_type: "tool.requested",
    received_at: `2026-11-10T09:0${index}:00Z`,
    occurred_at: `2026-11-10T09:0${index}:00Z`,
    title: `Step ${index}`,
    summary: null,
    processing_status: "processed",
    from_other_session: false,
    trust_level: null,
    tool: null,
    refs: REFS,
    outcome: null,
    findings: [],
    risk_after: { score: index * 20, level: index > 1 ? "high" : "low", delta: 20, trifecta: false, sensitive_access: index > 0, untrusted_exposure: index > 0, outbound_channel: index > 1, summary: "Recomputed from recorded events.", factors: [], basis: "recomputed from recorded events" },
    recorded_risk: null,
    ...overrides,
  };
}

const STEPS: ReplayStep[] = [
  step(0, { event_type: "context.ingested", title: "Read .env", trust_level: "TRUSTED", refs: { ...REFS, context_item_id: "ctx_env" } }),
  step(1, {
    title: "WebFetch to collector.example",
    tool: { name: "WebFetch", category: "http", status: "denied" },
    refs: { ...REFS, tool_invocation_id: "inv_exfil", policy_decision_id: "pdc_deny" },
    outcome: { policy_decision_id: "pdc_deny", decision: "DENY", enforcement: "enforced", explanation: 'DENY by policy "Block credential exfiltration"', matched_policies: ["Block credential exfiltration"], approval_id: null, approval_status: null },
  }),
  step(2, {
    title: "Bash curl to upload.example",
    tool: { name: "Bash", category: "shell", status: "completed" },
    refs: { ...REFS, tool_invocation_id: "inv_curl", policy_decision_id: "pdc_advisory" },
    outcome: { policy_decision_id: "pdc_advisory", decision: "DENY", enforcement: "advisory", explanation: 'DENY by policy "No shell uploads"', matched_policies: ["No shell uploads"], approval_id: null, approval_status: null },
  }),
];

function replay(overrides: Partial<Replay> = {}): Replay {
  return {
    session: { ...SESSION_ROW, parent_session_id: null, ended_at: null },
    basis: "Steps are the recorded events, redacted at ingestion.",
    risk_basis: "recomputed from recorded events",
    risk_note: "Risk per step is recomputed from the recorded events up to that step.",
    total_steps: 3,
    decision_steps: 2,
    offset: 0,
    limit: 500,
    truncated: false,
    focus_index: null,
    steps: STEPS,
    ...overrides,
  };
}

const POLICY: ReplayPolicy = {
  id: "pol_exfil",
  name: "Block credential exfiltration",
  description: null,
  enabled: true,
  mode: "enforce",
  priority: 1000,
  outcome: "DENY",
  severity: "critical",
  version: 3,
  is_builtin: true,
  restrictions: {},
  explanation: "secrets_in_arguments is not empty",
};

function routes({ sessions, replayReply }: { sessions?: Reply; replayReply?: (c: { query: URLSearchParams }) => Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/sessions") return sessions ?? { body: page([SESSION_ROW]) };
    if (c.path === "/replay/sessions/ses_main") return replayReply ? replayReply(c) : { body: replay() };
    if (c.path === "/replay/sessions/ses_foreign") return notFound("Session 'ses_foreign'");
    if (c.method === "GET" && c.path === "/policies") return { body: page([POLICY], { limit: 500 }) };
    return undefined;
  };
}

const renderReplay = (path = "/replay") =>
  renderPage(<ReplayLabPage />, { path, routePath: path.startsWith("/replay/") ? "/replay/:sessionId" : "/replay" });

const currentStep = () => within(screen.getByRole("list", { name: "Recorded steps" })).getByRole("button", { current: "step" });

describe("ReplayLabPage — session picker", () => {
  it("shows a loading state while recent sessions load", () => {
    stubApi(routes({ sessions: hang }));
    renderReplay();
    expect(screen.getByRole("heading", { name: "Replay Lab" })).toBeInTheDocument();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error", async () => {
    stubApi(routes({ sessions: serverError("Session index unavailable") }));
    renderReplay();
    expect(await screen.findByText("Session index unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains where sessions come from when there are none", async () => {
    stubApi(routes({ sessions: { body: page([]) } }));
    renderReplay();
    expect(await screen.findByText("No sessions recorded yet")).toBeInTheDocument();
    expect(screen.getByText(/Run a Simulation Lab scenario to replay a realistic attack/)).toBeInTheDocument();
  });

  it("lists sessions with their live risk and opens one", async () => {
    stubApi(routes());
    renderReplay();
    const open = await screen.findByRole("button", { name: "Replay session sess-7f3a" });
    const row = open.closest("tr") as HTMLElement;
    expect(within(row).getByRole("link", { name: "Agent payments-coder" })).toHaveAttribute("href", "/agents/agt_payments");
    expect(within(row).getByText("Trifecta")).toBeInTheDocument();
    expect(within(row).getByText("3")).toBeInTheDocument();
    expect(within(row).getByText("2")).toBeInTheDocument();
    fireEvent.click(open);
    await waitFor(() => expect(currentLocation()).toBe("/replay/ses_main"));
  });
});

describe("ReplayLabPage — session replay", () => {
  it("shows a loading state while the replay loads", () => {
    stubApi(routes({ replayReply: () => hang }));
    renderReplay("/replay/ses_main");
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("says the session was not found for an unknown or foreign id, without retrying", async () => {
    const api = stubApi(routes());
    renderReplay("/replay/ses_foreign");
    expect(await screen.findByText("Session not found")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Choose another session" })).toHaveAttribute("href", "/replay");
    expect(api.gets("/replay/sessions/ses_foreign")).toHaveLength(1);
  });

  it("shows the server's error for other failures", async () => {
    stubApi(routes({ replayReply: () => serverError("Replay builder unavailable") }));
    renderReplay("/replay/ses_main");
    expect(await screen.findByText("Replay builder unavailable")).toBeInTheDocument();
  });

  it("shows the recorded steps, the live risk and links to the session and its provenance", async () => {
    stubApi(routes());
    renderReplay("/replay/ses_main");
    expect(await screen.findByRole("heading", { name: /sess-7f3a/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Session detail/ })).toHaveAttribute("href", "/sessions/ses_main");
    expect(screen.getByRole("link", { name: /Provenance graph/ })).toHaveAttribute("href", "/provenance?session=ses_main");
    expect(screen.getByText("Events").nextSibling).toHaveTextContent("3");
    expect(screen.getByText("Decisions").nextSibling).toHaveTextContent("2");
    expect(screen.getByLabelText(/Live session risk/)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Replay/ })).toHaveTextContent("3");
    expect(currentStep()).toHaveTextContent("Read .env");
    expect(screen.getByText(/Steps are the recorded events, redacted at ingestion\./)).toBeInTheDocument();
  });

  it("opens the linked decision and words an advisory denial honestly", async () => {
    stubApi(routes({ replayReply: () => ({ body: replay({ focus_index: 2 }) }) }));
    renderReplay("/replay/ses_main?decision=pdc_advisory");
    expect(await screen.findByRole("heading", { name: /sess-7f3a/ })).toBeInTheDocument();
    expect(currentStep()).toHaveTextContent("Bash curl to upload.example");
    const outcome = screen.getByRole("region", { name: "Recorded outcome" });
    expect(within(outcome).getByText("Deny")).toBeInTheDocument();
    expect(within(outcome).getByText("Advisory")).toBeInTheDocument();
    expect(within(outcome).getByText("Advisory: the decision was returned, but the integration may not have honoured it.")).toBeInTheDocument();
    expect(outcome.textContent).not.toMatch(/\bblocked\b/i);

    // The enforced denial carries no advisory caveat.
    fireEvent.click(within(screen.getByRole("list", { name: "Recorded steps" })).getByText("WebFetch to collector.example"));
    const enforced = screen.getByRole("region", { name: "Recorded outcome" });
    expect(within(enforced).getByText("Enforced")).toBeInTheDocument();
    expect(within(enforced).queryByText(/may not have honoured it/)).not.toBeInTheDocument();
    expect(within(enforced).getByText("Matched: Block credential exfiltration")).toBeInTheDocument();
  });

  it("says when a linked decision is not part of the session", async () => {
    const api = stubApi(routes());
    renderReplay("/replay/ses_main?decision=pdc_elsewhere");
    expect(await screen.findByText(/The linked policy decision was not found in this session/)).toBeInTheDocument();
    expect(api.gets("/replay/sessions/ses_main")[0].query.get("decision_id")).toBe("pdc_elsewhere");
    expect(currentStep()).toHaveTextContent("Read .env");
  });

  it("explains that a session has no recorded steps", async () => {
    stubApi(routes({ replayReply: () => ({ body: replay({ steps: [], total_steps: 0, decision_steps: 0 }) }) }));
    renderReplay("/replay/ses_main");
    expect(await screen.findByRole("heading", { name: /sess-7f3a/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Replay/ })).toHaveTextContent("0");
    expect(screen.getByText("Nothing recorded for this session yet")).toBeInTheDocument();
    expect(screen.getByText("Steps appear here as the integration reports events for this session.")).toBeInTheDocument();
  });

  it("labels the counterfactual tab as a simulation against recorded inputs", async () => {
    stubApi(routes());
    renderReplay("/replay/ses_main?tab=counterfactual");
    const banner = await screen.findByRole("note", { name: "Simulation notice" });
    expect(banner).toHaveTextContent("SIMULATION — hypothetical outcomes evaluated against recorded inputs, not historical fact");
    expect(await screen.findByText("Block credential exfiltration")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run simulation/ })).toBeInTheDocument();
  });
});
