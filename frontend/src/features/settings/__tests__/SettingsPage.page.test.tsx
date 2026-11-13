import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, makeMe, page, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import type { ApiKey, Member, Org } from "../api";
import { SettingsPage } from "../SettingsPage";

let permissions: string[] = ["read", "write", "admin"];
vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: makeMe(permissions), loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

beforeEach(() => {
  permissions = ["read", "write", "admin"];
});
afterEach(() => vi.unstubAllGlobals());

const ORG: Org = {
  id: "org_test",
  name: "Acme Test Org",
  slug: "acme-test",
  created_at: "2026-01-01T00:00:00Z",
  settings: { retention_days: 45, fail_mode: "closed", default_decision: "AUDIT", approval_timeout_s: 600, store_previews: false },
  member_count: 2,
  active_api_key_count: 1,
};

const MEMBERS: Member[] = [
  { id: "mem_me", user_id: "usr_me", name: "Ada Analyst", email: "me@acme.test", role: "owner", is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: "2026-11-10T08:00:00Z" },
  { id: "mem_dev", user_id: "usr_dev", name: "Dev Person", email: "dev@acme.test", role: "developer", is_active: true, created_at: "2026-01-02T00:00:00Z", last_login_at: null },
];

const KEY: ApiKey = {
  id: "key_ci",
  name: "ci-ingest",
  prefix: "ctxk_test12",
  scopes: ["ingest", "decide"],
  agent_id: null,
  agent_name: null,
  created_by_user_id: "usr_me",
  created_by_name: "Ada Analyst",
  created_at: "2026-11-01T08:00:00Z",
  last_used_at: null,
  expires_at: null,
  revoked_at: null,
  status: "active",
};

function routes({ org }: { org?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/org") return org ?? { body: ORG };
    if (c.path === "/org/members") return { body: page(MEMBERS, { limit: 500 }) };
    if (c.path === "/org/api-keys") return { body: page([KEY], { limit: 500 }) };
    if (c.path === "/agents") return { body: page([]) };
    return undefined;
  };
}

const renderSettings = (query = "") => renderPage(<SettingsPage />, { path: `/settings${query}`, routePath: "/settings" });

describe("SettingsPage", () => {
  it("shows a loading state while the organisation loads", () => {
    stubApi(routes({ org: hang }));
    renderSettings();
    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getByLabelText("Loading")).toHaveAttribute("aria-busy", "true");
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes({ org: serverError("Organisation settings unavailable") }));
    renderSettings();
    expect(await screen.findByText("Organisation settings unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows the organisation's identity and enforcement defaults from the API", async () => {
    stubApi(routes());
    renderSettings();
    const form = await screen.findByRole("form", { name: "Organisation settings" });
    expect(within(form).getByLabelText("Name")).toHaveValue("Acme Test Org");
    expect(within(form).getByText("acme-test")).toBeInTheDocument();
    expect(within(form).getByText("org_test")).toBeInTheDocument();
    expect(within(form).getByRole("spinbutton")).toHaveValue(600);
    expect(within(form).getByText("= 10 min")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Members/ })).toHaveTextContent("2");
    expect(screen.getByRole("tab", { name: /API keys/ })).toHaveTextContent("1");
    expect(screen.queryByText("Only owners and admins can change these settings.")).not.toBeInTheDocument();
  });

  it("is read-only for non-admins and hides the API key count", async () => {
    permissions = ["read"];
    stubApi(routes());
    renderSettings();
    expect(await screen.findByText("Only owners and admins can change these settings.")).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toBeDisabled();
    expect(screen.getByRole("tab", { name: /API keys/ })).toHaveTextContent(/^API keys$/);
  });

  it("opens the data & privacy tab from the URL with the stored retention and preview settings", async () => {
    stubApi(routes());
    renderSettings("?tab=privacy");
    const form = await screen.findByRole("form", { name: "Data settings" });
    expect(within(form).getByLabelText("Retention period")).toHaveValue(45);
    expect(within(form).getByText("≈ 1.5 months")).toBeInTheDocument();
    expect(within(form).getByRole("checkbox", { name: "Previews are not stored" })).not.toBeChecked();
  });

  it("switches tabs through the URL and lists members and API keys", async () => {
    stubApi(routes());
    renderSettings();
    await screen.findByRole("form", { name: "Organisation settings" });
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Members/ }));
    await waitFor(() => expect(currentLocation()).toBe("/settings?tab=members"));
    expect(await screen.findByText("Dev Person")).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: /API keys/ }));
    await waitFor(() => expect(currentLocation()).toBe("/settings?tab=api-keys"));
    expect(await screen.findByText("ci-ingest")).toBeInTheDocument();
  });
});
