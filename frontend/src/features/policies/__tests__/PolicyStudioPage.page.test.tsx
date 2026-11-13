import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hang, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { PolicyStudioPage } from "../PolicyStudioPage";
import type { Policy } from "../types";

let permissions: string[] = ["read", "policy:manage"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "policy:manage"];
});
afterEach(() => vi.unstubAllGlobals());

const DENY_POLICY: Policy = {
  id: "pol_exfil",
  name: "Block credential exfiltration",
  description: "Deny outbound calls that carry a credential.",
  enabled: true,
  mode: "enforce",
  priority: 1000,
  outcome: "DENY",
  conditions: { field: "secrets_in_arguments", op: "not_empty" },
  restrictions: {},
  severity: "critical",
  tags: ["exfiltration"],
  version: 3,
  is_builtin: true,
  builtin_key: "block_credential_exfiltration",
  created_by: null,
  created_at: "2026-11-01T08:00:00Z",
  updated_at: "2026-11-09T08:00:00Z",
  explanation: "secrets_in_arguments is not empty",
  stats: { window_days: 7, matched: 4, monitor_matched: 0, simulated: 2, last_matched_at: "2026-11-10T09:10:00Z", daily: [0, 1, 0, 0, 2, 0, 1] },
};

const AUDIT_POLICY: Policy = {
  ...DENY_POLICY,
  id: "pol_reads",
  name: "Audit .env reads",
  description: null,
  enabled: false,
  mode: "monitor",
  priority: 100,
  outcome: "AUDIT",
  conditions: { field: "tool.name", op: "eq", value: "Read" },
  severity: "low",
  tags: [],
  version: 1,
  is_builtin: false,
  builtin_key: null,
  created_by: "usr_me",
  explanation: "tool.name is Read",
  stats: { window_days: 7, matched: 0, monitor_matched: 0, simulated: 0, last_matched_at: null, daily: [0, 0, 0, 0, 0, 0, 0] },
};

const ORG = { id: "org_test", name: "Acme Test Org", slug: "acme-test", created_at: "2026-01-01T00:00:00Z", settings: { retention_days: 30, fail_mode: "closed", default_decision: "AUDIT", approval_timeout_s: 600, store_previews: true }, member_count: 2, active_api_key_count: 1 };

function routes({ policies = [DENY_POLICY, AUDIT_POLICY], list }: { policies?: Policy[]; list?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.method === "GET" && c.path === "/policies") return list ?? { body: page(policies, { limit: 500 }) };
    if (c.path === "/org") return { body: ORG };
    if (c.method === "PATCH" && c.path === `/policies/${DENY_POLICY.id}`) return { body: { ...DENY_POLICY, ...(c.body as object), version: DENY_POLICY.version + 1 } };
    return undefined;
  };
}

const renderStudio = (query = "") => renderPage(<PolicyStudioPage />, { path: `/policies${query}`, routePath: "/policies" });

describe("PolicyStudioPage", () => {
  it("shows a loading state while policies load", () => {
    stubApi(routes({ list: hang }));
    renderStudio();
    expect(screen.getByRole("heading", { name: "What are agents allowed to do?" })).toBeInTheDocument();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes({ list: serverError("Policy store unavailable") }));
    renderStudio();
    expect(await screen.findByText("Couldn’t load this view")).toBeInTheDocument();
    expect(screen.getByText("Policy store unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("explains the default decision when there are no policies", async () => {
    stubApi(routes({ policies: [] }));
    renderStudio();
    expect(await screen.findByText("No policies yet")).toBeInTheDocument();
    expect(screen.getByText(/every tool call gets the organisation's default decision/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create policy" })).toBeInTheDocument();
    // The banner shows the organisation's real default from /org.
    const banner = screen.getByRole("region", { name: "How policies decide" });
    await waitFor(() => expect(within(banner).getByText(/If nothing matches, the default applies/)).toHaveTextContent("Audit"));
  });

  it("offers to clear filters when nothing matches them", async () => {
    stubApi(routes({ policies: [] }));
    renderStudio("?outcome=DENY");
    expect(await screen.findByText("No policies match these filters")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Clear/ }).length).toBeGreaterThan(0);
  });

  it("groups policies by outcome in precedence order with version, mode, state and recorded matches", async () => {
    stubApi(routes());
    renderStudio();
    const deny = await screen.findByRole("region", { name: "Deny policies" });
    expect(within(deny).getByRole("button", { name: "Block credential exfiltration" })).toBeInTheDocument();
    expect(within(deny).getByText("Built-in")).toBeInTheDocument();
    expect(within(deny).getByText("v3 · p1000")).toBeInTheDocument();
    expect(within(deny).getByText("secrets_in_arguments is not empty")).toBeInTheDocument();
    expect(within(deny).getByText("Block the call where the integration enforces decisions.")).toBeInTheDocument();
    expect(within(deny).getByText("+2 sim")).toBeInTheDocument();
    expect(within(deny).getByRole("switch", { name: "Disable Block credential exfiltration" })).toBeChecked();

    const audit = screen.getByRole("region", { name: "Audit policies" });
    expect(within(audit).getByText("Disabled")).toBeInTheDocument();
    expect(within(audit).getByRole("switch", { name: "Enable Audit .env reads" })).not.toBeChecked();
    expect(within(audit).getByText("0 of 1 policy enabled")).toBeInTheDocument();

    // Precedence: DENY is listed before AUDIT.
    expect(deny.compareDocumentPosition(audit) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText("2 policies · 1 enabled · 1 enforcing")).toBeInTheDocument();
  });

  it("asks before an enforced DENY policy stops enforcing, then saves the change", async () => {
    const api = stubApi(routes());
    renderStudio();
    const deny = await screen.findByRole("region", { name: "Deny policies" });
    fireEvent.click(within(deny).getByRole("switch", { name: "Disable Block credential exfiltration" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Disable this DENY policy?")).toBeInTheDocument();
    expect(within(dialog).getByText(/currently blocks matching tool calls where integrations enforce decisions/)).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "PATCH")).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Disable policy" }));
    await waitFor(() => expect(api.calls.find((c) => c.method === "PATCH")?.body).toEqual({ enabled: false }));
    expect(await screen.findByText("“Block credential exfiltration” disabled")).toBeInTheDocument();
  });

  it("is read-only without policy:manage", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderStudio();
    const deny = await screen.findByRole("region", { name: "Deny policies" });
    expect(within(deny).getByRole("switch", { name: "Disable Block credential exfiltration" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "New policy" })).not.toBeInTheDocument();
  });
});
