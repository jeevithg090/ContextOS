import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import type { TrustLevel } from "@/lib/domain";
import { TestRouter } from "@/test/router";
import { TrustCentrePage } from "../TrustCentrePage";
import type { TrustDestination, TrustSource, TrustSummary } from "../types";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

const levels = (n: Partial<Record<TrustLevel, number>> = {}): Record<TrustLevel, number> => ({
  TRUSTED: 0, APPROVED: 0, EXTERNAL: 0, UNKNOWN: 0, SUSPICIOUS: 0, BLOCKED: 0, ...n,
});

function summary(sources: number): TrustSummary {
  return {
    sources: { total: sources, by_level: levels({ SUSPICIOUS: sources }), can_instruct: 0, manual: 0, with_findings: 0 },
    destinations: { total: 1, by_level: levels({ UNKNOWN: 1 }), with_blocked_calls: 0, with_sensitive_transfers: 0 },
    rules: { total: 3, enabled: 3, source: 2, destination: 1 },
    sources_with_findings: [],
    recently_downgraded: [],
    downgrade_window_days: 30,
  } as unknown as TrustSummary;
}

const REAL: TrustSource = {
  id: "src_real", source_type: "repository", identifier: "github.com/acme/app/README.md", display_name: "README.md", domain: "github.com",
  trust_level: "SUSPICIOUS", trust_capabilities: ["read"], trust_rule_id: null, trust_rule_name: null, manually_classified: false,
  observation_count: 2, finding_count: 0, max_finding_severity: null, first_seen_at: "2026-11-10T10:00:00Z", last_seen_at: "2026-11-10T10:00:00Z",
  is_simulation: false,
};
const SIMULATED: TrustSource = { ...REAL, id: "src_sim", identifier: "https://pricing.vendor-site.example/plans", display_name: "Pricing page", is_simulation: true };

const DEST: TrustDestination = {
  id: "dst_sim", kind: "domain", identifier: "hooks.exfil.invalid", display_name: null, classification: "UNKNOWN", trust_rule_id: null,
  trust_rule_name: null, override_rule_id: null, transfer_count: 0, blocked_count: 1, sensitive_transfer_count: 0,
  first_seen_at: "2026-11-10T10:00:00Z", last_seen_at: "2026-11-10T10:00:00Z", verification: { passed: 1, warned: 0, failed: 0, unknown: 0 },
  is_simulation: true,
};

const urls: string[] = [];

beforeEach(() => {
  urls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      urls.push(url);
      const sim = url.includes("include_simulated=true");
      let body: unknown;
      if (url.startsWith("/api/v1/trust/summary")) body = summary(sim ? 2 : 1);
      else if (url.startsWith("/api/v1/trust/sources")) body = { items: sim ? [REAL, SIMULATED] : [REAL], total: sim ? 2 : 1, limit: 50, offset: 0 };
      else if (url.startsWith("/api/v1/trust/destinations")) body = { items: sim ? [DEST] : [], total: sim ? 1 : 0, limit: 50, offset: 0 };
      else if (url.startsWith("/api/v1/trust/rules")) body = { items: [], total: 0, limit: 1000, offset: 0 };
      else body = {};
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => vi.unstubAllGlobals());

function renderPage(entry = "/trust") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TestRouter initialEntries={[entry]}>
        <TooltipProvider>
          <ToastProvider>
            <TrustCentrePage />
          </ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
}

describe("Trust Centre — include simulated", () => {
  it("hides Simulation Lab-only sources by default and lists them, labelled, when included", async () => {
    renderPage();
    const table = await screen.findByRole("table", { name: "Context sources" });
    expect(await within(table).findByText("README.md")).toBeInTheDocument();
    expect(within(table).queryByText("Pricing page")).not.toBeInTheDocument();
    expect(urls.some((u) => u.startsWith("/api/v1/trust/sources") && u.includes("include_simulated"))).toBe(false);
    expect(urls.some((u) => u.startsWith("/api/v1/trust/summary") && u.includes("include_simulated"))).toBe(false);

    fireEvent.click(screen.getByRole("checkbox", { name: "Include simulated" }));

    const simulatedRow = (await within(table).findByText("Pricing page")).closest("tr") as HTMLElement;
    expect(within(simulatedRow).getByText("Simulation")).toBeInTheDocument();
    const realRow = within(table).getByText("README.md").closest("tr") as HTMLElement;
    expect(within(realRow).queryByText("Simulation")).not.toBeInTheDocument();
    await waitFor(() => expect(urls).toContain("/api/v1/trust/summary?include_simulated=true"));
  });

  it("applies the same switch to destinations from the URL", async () => {
    renderPage("/trust?tab=destinations&sim=1");
    const table = await screen.findByRole("table", { name: "Destinations" });
    const row = (await within(table).findByText("hooks.exfil.invalid")).closest("tr") as HTMLElement;
    expect(within(row).getByText("Simulation")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Include simulated" })).toBeChecked();
    expect(urls.some((u) => u.startsWith("/api/v1/trust/destinations") && u.includes("include_simulated=true"))).toBe(true);
  });
});
