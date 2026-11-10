import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import type { Me } from "@/features/auth/AuthProvider";
import { MembersTab } from "../MembersTab";
import { ApiKeysTab } from "../ApiKeysTab";
import { formatDuration } from "../meta";

let currentMe: Me;

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({
    me: currentMe,
    loading: false,
    can: (p: string) => currentMe.permissions.includes(p),
    refresh: async () => undefined,
    logout: async () => undefined,
  }),
}));

function makeMe(role: string, permissions: string[]): Me {
  return {
    user: { id: "usr_owner", email: "owner@acme.test", name: "Ada Owner" },
    organization: { id: "org_1", name: "Acme", slug: "acme" },
    role,
    permissions,
    memberships: [{ organization_id: "org_1", organization_name: "Acme", role }],
  };
}

const MEMBERS = {
  items: [
    { id: "mem_owner", user_id: "usr_owner", name: "Ada Owner", email: "owner@acme.test", role: "owner", is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null },
    { id: "mem_dev", user_id: "usr_dev", name: "Dev Person", email: "dev@acme.test", role: "developer", is_active: true, created_at: "2026-01-02T00:00:00Z", last_login_at: "2026-01-03T00:00:00Z" },
  ],
  total: 2,
  limit: 500,
  offset: 0,
};

type Handler = (url: string, init?: RequestInit) => { status?: number; body?: unknown };
let handler: Handler;
const calls: Array<{ url: string; method: string; body?: unknown }> = [];

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const { status = 200, body } = handler(url, init);
      return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TooltipProvider>
          <ToastProvider>{ui}</ToastProvider>
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("MembersTab", () => {
  it("protects the last owner and the signed-in user for admins", async () => {
    currentMe = makeMe("owner", ["read", "write", "admin"]);
    handler = () => ({ body: MEMBERS });
    wrap(<MembersTab />);

    const ownerRole = await screen.findByLabelText("Role for Ada Owner");
    expect(ownerRole).toBeDisabled(); // last owner
    expect(screen.getByLabelText("Role for Dev Person")).not.toBeDisabled();

    const ownerRow = ownerRole.closest("tr") as HTMLElement;
    expect(within(ownerRow).getByRole("button", { name: "Remove" })).toBeDisabled(); // yourself
    const devRow = screen.getByLabelText("Role for Dev Person").closest("tr") as HTMLElement;
    expect(within(devRow).getByRole("button", { name: "Remove" })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: "Add member" })).toBeInTheDocument();
  });

  it("is read-only for viewers", async () => {
    currentMe = makeMe("viewer", ["read"]);
    handler = () => ({ body: MEMBERS });
    wrap(<MembersTab />);
    expect(await screen.findByText("Dev Person")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add member" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Role for Dev Person")).not.toBeInTheDocument();
  });

  it("confirms a role change before sending it", async () => {
    currentMe = makeMe("owner", ["read", "write", "admin"]);
    handler = (_url, init) => (init?.method === "PATCH" ? { body: { ...MEMBERS.items[1], role: "viewer" } } : { body: MEMBERS });
    wrap(<MembersTab />);
    fireEvent.change(await screen.findByLabelText("Role for Dev Person"), { target: { value: "viewer" } });
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    fireEvent.click(await screen.findByRole("button", { name: "Change role" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")).toMatchObject({ url: "/api/v1/org/members/mem_dev", body: { role: "viewer" } }));
  });
});

describe("ApiKeysTab", () => {
  it("shows the raw key once after creation and never refetches it", async () => {
    currentMe = makeMe("owner", ["read", "admin"]);
    const created = {
      id: "key_new", name: "laptop", prefix: "ctxk_abc123", scopes: ["decide", "ingest"], agent_id: null, agent_name: null,
      created_by_user_id: "usr_owner", created_by_name: "Ada Owner", created_at: "2026-01-01T00:00:00Z", last_used_at: null,
      expires_at: null, revoked_at: null, status: "active", key: "ctxk_abc123SECRETVALUE",
    };
    let listed: unknown[] = [];
    handler = (url, init) => {
      if (url.startsWith("/api/v1/org/api-keys") && init?.method === "POST") {
        const row: Record<string, unknown> = { ...created };
        delete row.key;
        listed = [row];
        return { status: 201, body: created };
      }
      if (url.startsWith("/api/v1/org/api-keys")) return { body: { items: listed, total: listed.length, limit: 500, offset: 0 } };
      if (url.startsWith("/api/v1/agents")) return { body: { items: [], total: 0, limit: 200, offset: 0 } };
      return { status: 404, body: { error: { code: "not_found", message: "nope" } } };
    };
    wrap(<ApiKeysTab canAdmin />);

    expect(await screen.findByText("No API keys yet")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Create API key" })[0]);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "laptop" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    expect(await screen.findByLabelText("New API key")).toHaveTextContent("ctxk_abc123SECRETVALUE");
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({ name: "laptop", scopes: ["ingest", "decide"], agent_id: null, expires_in_days: 90 });
    await screen.findByText("ctxk_abc123…");

    fireEvent.click(screen.getByRole("button", { name: "I’ve stored it" }));
    expect(screen.queryByText(/SECRETVALUE/)).not.toBeInTheDocument();
  });

  it("explains that only admins can manage keys", () => {
    currentMe = makeMe("developer", ["read", "write"]);
    handler = () => ({ status: 403, body: { error: { code: "forbidden", message: "no" } } });
    wrap(<ApiKeysTab canAdmin={false} />);
    expect(screen.getByText("Only owners and admins can manage API keys")).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });
});

describe("formatDuration", () => {
  it("formats seconds for humans", () => {
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(600)).toBe("10 min");
    expect(formatDuration(5400)).toBe("1.5 h");
  });
});
