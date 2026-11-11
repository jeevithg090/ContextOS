import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { AuditLogPage } from "../AuditLogPage";
import { auditTarget } from "../meta";
import type { AuditEntry, AuditVerifyResult } from "../types";

let permissions: string[] = ["read"];

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: (p: string) => permissions.includes(p), refresh: async () => undefined, logout: async () => undefined }),
}));

const ENTRIES: AuditEntry[] = [
  {
    id: "aud_2", seq: 2, occurred_at: "2026-11-10T10:00:00Z", actor_type: "api_key", actor_id: "key_1", actor_label: "ci key", actor_detail: "ctxk_ab12…",
    action: "tool.denied", target_type: "tool_invocation", target_id: "inv_1",
    details: { decision: "DENY", enforcement: "enforced", session_id: "ses_1", token: "[REDACTED:sensitive_field:abcd1234]" },
    prev_hash: "a".repeat(64), hash: "b".repeat(64),
  },
  {
    id: "aud_1", seq: 1, occurred_at: "2026-11-10T09:00:00Z", actor_type: "user", actor_id: "usr_1", actor_label: "Ada Owner", actor_detail: "ada@acme.test",
    action: "policy.updated", target_type: "policy", target_id: "pol_1", details: { name: "Block exfiltration" }, prev_hash: null, hash: "a".repeat(64),
  },
];

const THREAT = { detects: ["Edits without the server secret"], does_not_protect_against: ["Someone with both DB write access and the secret"], anchoring: "Store the head hash externally." };
const VALID: AuditVerifyResult = {
  valid: true, checked: 2, head_seq: 2, head_hash: "b".repeat(64), first_invalid_seq: null, first_invalid_entry_id: null, reason: null,
  reason_explained: null, summary: "All 2 entries verified.", verified_at: "2026-11-10T10:05:00Z", threat_model: THREAT,
};
const INVALID: AuditVerifyResult = {
  ...VALID, valid: false, first_invalid_seq: 2, first_invalid_entry_id: "aud_2", reason: "entry contents do not match its hash",
  reason_explained: "This entry was changed after it was written.", summary: "Verification failed at entry #2.",
};

let verifyBody: AuditVerifyResult = VALID;
const urls: string[] = [];

beforeEach(() => {
  urls.length = 0;
  verifyBody = VALID;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      urls.push(url);
      const body = url.startsWith("/api/v1/audit/verify") ? verifyBody : { items: ENTRIES, total: 2, limit: 50, offset: 0 };
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => vi.unstubAllGlobals());

function wrap(ui: ReactNode, path = "/audit") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TestRouter initialEntries={[path]}>
        <TooltipProvider>
          <ToastProvider>{ui}</ToastProvider>
        </TooltipProvider>
      </TestRouter>
    </QueryClientProvider>,
  );
}

describe("auditTarget", () => {
  it("maps audit target types onto app routes", () => {
    expect(auditTarget({ target_type: "context_source", target_id: "src_1", details: {} })).toMatchObject({ kind: "entity", type: "source" });
    expect(auditTarget({ target_type: "tool_invocation", target_id: "inv_1", details: { session_id: "ses_1" } })).toMatchObject({ kind: "entity", sessionId: "ses_1" });
    expect(auditTarget({ target_type: "api_key", target_id: "key_1", details: { name: "ci" } })).toEqual({ kind: "page", label: "ci", href: "/settings?tab=api-keys", id: "key_1" });
    expect(auditTarget({ target_type: "trust_rule", target_id: "tr_1", details: {} })).toMatchObject({ href: "/trust?tab=rules&rule=tr_1" });
    expect(auditTarget({ target_type: "generated_prompt", target_id: "gp_1", details: {} })).toEqual({ kind: "plain", type: "generated_prompt", id: "gp_1" });
    expect(auditTarget({ target_type: null, target_id: null, details: {} })).toBeNull();
  });
});

describe("AuditLogPage", () => {
  it("lists entries with actors and targets and expands details", async () => {
    wrap(<AuditLogPage />);
    expect(await screen.findByText("tool.denied")).toBeInTheDocument();
    expect(screen.getByText("Ada Owner")).toBeInTheDocument();
    expect(screen.getByText("ci key")).toBeInTheDocument();
    expect(screen.getByText("2 entries")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show details of entry 2" }));
    expect(await screen.findByText("Only this actor")).toBeInTheDocument();
    expect(screen.getAllByText("b".repeat(64)).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Only this actor" }));
    await waitFor(() => expect(urls.some((u) => u.includes("actor_id=key_1") && u.includes("actor_type=api_key"))).toBe(true));
  });

  it("sends URL filters to the API", async () => {
    wrap(<AuditLogPage />, "/audit?action=policy.&target_type=policy&target_id=pol_1");
    await screen.findByText("policy.updated");
    const listCall = urls.find((u) => u.startsWith("/api/v1/audit?")) ?? "";
    expect(listCall).toContain("action=policy.");
    expect(listCall).toContain("target_id=pol_1");
    expect(screen.getByRole("button", { name: /Remove filter: Target policy/ })).toBeInTheDocument();
  });

  it("shows an intact-chain result with the threat model", async () => {
    wrap(<AuditLogPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Verify chain" }));
    const result = await screen.findByRole("status", { name: "Audit chain verification result" });
    expect(within(result).getByText(/Chain intact — 2 entries verified/)).toBeInTheDocument();
    expect(within(result).getByText("Someone with both DB write access and the secret")).toBeInTheDocument();
  });

  it("shows where the chain breaks when tampering is detected", async () => {
    verifyBody = INVALID;
    wrap(<AuditLogPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Verify chain" }));
    const alert = await screen.findByRole("alert", { name: "Audit chain verification result" });
    expect(within(alert).getByText("Tampering detected at entry #2")).toBeInTheDocument();
    expect(within(alert).getByText("entry contents do not match its hash")).toBeInTheDocument();
  });

  it("offers export to admins only", async () => {
    permissions = ["read"];
    const { unmount } = wrap(<AuditLogPage />);
    await screen.findByText("tool.denied");
    expect(screen.queryByRole("button", { name: "Export JSONL" })).not.toBeInTheDocument();
    unmount();
    permissions = ["read", "admin"];
    wrap(<AuditLogPage />);
    expect(await screen.findByRole("button", { name: "Export JSONL" })).toBeInTheDocument();
  });
});
