import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { IntegrationsPage } from "../IntegrationsPage";
import type { CatalogEntry, ConnectedIntegration, IntegrationsOverview, SetupGuide } from "../types";

const CLAUDE: CatalogEntry = {
  kind: "claude_code", name: "Claude Code", status: "supported", summary: "Hooks report and decide.", best_enforcement: "enforced",
  monitoring: [{ name: "PostToolUse", mode: "observed", description: "Each tool result." }],
  enforcement: [{ name: "PreToolUse deny", mode: "enforced", description: "Denied calls do not run." }],
  limitations: ["Cannot see the model's reasoning."], integration_surface: null, available_today: null, interim_kind: null,
  docs_path: "docs/integrations/claude-code.md", api_key_scopes: ["ingest", "decide"], health: "connected", last_event_at: "2026-11-10T10:00:00Z",
};
const CURSOR: CatalogEntry = {
  ...CLAUDE, kind: "cursor", name: "Cursor", status: "planned", summary: "Planned.", best_enforcement: null, monitoring: [], enforcement: [],
  limitations: ["Not supported yet."], integration_surface: "Cursor hooks", available_today: "Wrap MCP servers with the gateway.",
  interim_kind: "mcp_gateway", docs_path: null, api_key_scopes: [], health: "never_seen", last_event_at: null,
};
const CONNECTED: ConnectedIntegration = {
  id: "int_1", kind: "claude_code", name: "claude_code", display_name: "Claude Code", supported: true, best_enforcement: "enforced",
  health: "connected", health_detail: "Received an event in the last 15 minutes.", first_seen_at: "2026-11-09T10:00:00Z",
  last_event_at: "2026-11-10T10:00:00Z", event_count: 42, decision_count: 7, events_24h: 12,
  decisions: { enforced: 7, advisory: 0, observed: 2 }, agent_count: 1, last_error: null,
};
const GUIDE: SetupGuide = {
  kind: "claude_code", name: "Claude Code", status: "supported", interim_kind: null, server_url: "http://localhost:8000",
  server_url_note: "Taken from the address you used.", api_key_scopes: [{ scope: "ingest", required: true, purpose: "Report events." }],
  steps: [
    { title: "Create an API key", description: "Create a key.", commands: [], link: { label: "Settings → API keys", href: "/settings?tab=api-keys" } },
    { title: "Connect the project and install the hooks", description: "Run init.", commands: [{ language: "bash", code: "contextos init --url http://localhost:8000 --api-key ctxk_your_key --claude-code", title: null }], link: null },
  ],
  verification: "Claude Code appears as Connected.", notes: ["Only hooked tool calls are covered."], docs_path: "docs/integrations/claude-code.md",
};

let overview: IntegrationsOverview;
const urls: string[] = [];

beforeEach(() => {
  urls.length = 0;
  overview = { connected: [CONNECTED], catalog: [CLAUDE, CURSOR], stale_after_minutes: 15, generated_at: "2026-11-10T10:01:00Z" };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      urls.push(url);
      const body = url.includes("/setup") ? { ...GUIDE, kind: url.split("/")[4], name: url.includes("cursor") ? "Cursor" : "Claude Code", status: url.includes("cursor") ? "planned" : "supported", interim_kind: url.includes("cursor") ? "mcp_gateway" : null } : overview;
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => vi.unstubAllGlobals());

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/integrations"]}>
        <TooltipProvider>
          <ToastProvider>{ui}</ToastProvider>
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("IntegrationsPage", () => {
  it("shows connected integrations with health and enforcement evidence", async () => {
    wrap(<IntegrationsPage />);
    const connected = (await screen.findByRole("heading", { name: "Connected integrations" })).closest("section") as HTMLElement;
    expect(within(connected).getByText("Claude Code")).toBeInTheDocument();
    expect(within(connected).getByText("Connected")).toBeInTheDocument();
    expect(within(connected).getByText("42")).toBeInTheDocument();
    expect(within(connected).getByText("12 in 24 h")).toBeInTheDocument();
    expect(within(connected).getByText("enforced")).toBeInTheDocument();
    expect(within(connected).getByText("observed only")).toBeInTheDocument();
  });

  it("labels every capability with an explicit enforcement claim and lists planned frameworks as planned", async () => {
    wrap(<IntegrationsPage />);
    const matrix = (await screen.findByRole("heading", { name: "Capability matrix" })).closest("section") as HTMLElement;
    expect(within(matrix).getByText("PreToolUse deny")).toBeInTheDocument();
    expect(within(matrix).getByText("Enforced")).toBeInTheDocument();
    expect(within(matrix).getByText("Observed only")).toBeInTheDocument();
    expect(within(matrix).getByText("Cannot see the model's reasoning.")).toBeInTheDocument();
    expect(within(matrix).queryByText("Cursor")).not.toBeInTheDocument();
    const planned = screen.getByRole("heading", { name: "Planned — not supported yet" }).closest("section") as HTMLElement;
    expect(within(planned).getByText("Cursor")).toBeInTheDocument();
    expect(within(planned).getByText("Planned")).toBeInTheDocument();
    expect(within(planned).getByText("Wrap MCP servers with the gateway.")).toBeInTheDocument();
  });

  it("renders setup steps with commands and switches guides", async () => {
    wrap(<IntegrationsPage />);
    expect(await screen.findByText("Connect the project and install the hooks")).toBeInTheDocument();
    expect(screen.getByText(/contextos init --url http:\/\/localhost:8000/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Settings → API keys/ })).toHaveAttribute("href", "/settings?tab=api-keys");
    fireEvent.click(screen.getByRole("button", { name: "Interim setup for Cursor" }));
    await waitFor(() => expect(urls).toContain("/api/v1/integrations/cursor/setup"));
    expect(await screen.findByText(/Interim path through the/)).toBeInTheDocument();
  });

  it("shows an empty state when nothing has connected", async () => {
    overview = { ...overview, connected: [], catalog: [{ ...CLAUDE, health: "never_seen", last_event_at: null }, CURSOR] };
    wrap(<IntegrationsPage />);
    expect(await screen.findByText("No integration has sent events yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set up Claude Code" })).toBeInTheDocument();
  });
});
