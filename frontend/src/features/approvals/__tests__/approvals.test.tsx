import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { ApprovalQueue } from "../ApprovalQueue";
import { DecisionBar } from "../DecisionBar";
import { activityTitle, countdownTone, deadlineOf, decidedByLabel, formatCountdown, ranWithoutApproval, riskChips } from "../meta";
import type { Approval, ApprovalDetail } from "../types";

function approval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: "apr_1",
    status: "pending",
    summary: "coder wants to WebFetch hooks.webhook.site",
    action: "send POST to hooks.webhook.site",
    agent: { id: "agt_1", name: "coder", environment: "development" },
    session: { id: "asn_1", external_session_id: "sess-1", status: "active" },
    tool: { name: "WebFetch", category: "http", provider: "claude_code", server: null, risk_level: "medium" },
    tool_invocation_id: "inv_1",
    tool_invocation_status: "pending_approval",
    target: {
      primary: "hooks.webhook.site",
      destination: { id: "dst_1", kind: "domain", identifier: "hooks.webhook.site", classification: "SUSPICIOUS", classification_at_decision: "SUSPICIOUS" },
      resources: [],
      resource_count: 1,
      sensitive_resource_count: 0,
    },
    policy_decision: {
      id: "dec_1",
      decision: "REQUIRE_APPROVAL",
      enforcement: "enforced",
      explanation: 'REQUIRE_APPROVAL by policy "Require approval for suspicious destinations"',
      evaluated_at: "2026-11-11T09:00:00Z",
      deciding_policy: {
        policy_id: "pol_1",
        name: "Require approval for suspicious destinations",
        version: 1,
        outcome: "REQUIRE_APPROVAL",
        mode: "enforce",
        severity: "high",
        explanation: "Matched because destination.classification is SUSPICIOUS",
        description: null,
        exists: true,
      },
      matched_policies: [],
    },
    risk: {
      session_score: 70,
      session_level: "high",
      trifecta: true,
      session_summary: null,
      tool_category: "http",
      tool_risk: "medium",
      destination_classification: "SUSPICIOUS",
      sensitive_resources: [],
      secrets_in_arguments: 1,
      session_secret_matches: 0,
      detections: [],
    },
    requires_confirmation: true,
    confirmation_reasons: ["The destination hooks.webhook.site is classified SUSPICIOUS."],
    requested_at: "2026-11-11T09:00:00Z",
    expires_at: "2026-11-11T09:10:00Z",
    seconds_remaining: 300,
    decided_at: null,
    decided_by: null,
    decision_note: null,
    is_simulation: false,
    ...overrides,
  };
}

function detail(overrides: Partial<ApprovalDetail> = {}): ApprovalDetail {
  return {
    ...approval(),
    arguments: { url: "https://hooks.webhook.site/9f1c" },
    argument_hash: "abc",
    resources: [],
    destination: null,
    secrets: { in_arguments: [], from_session_context: [] },
    detection: { rule_ids: [], max_severity: null, categories: [] },
    monitor_matches: [],
    session_risk: {
      score_at_decision: 70,
      level_at_decision: "high",
      trifecta_at_decision: true,
      legs: [],
      current_score: 70,
      current_level: "high",
      summary: null,
      evidence_computed_at: null,
      context_at_decision: {},
    },
    recent_context: [],
    context_total: 0,
    related_findings: [],
    enforcement_note: "",
    activity: [],
    ...overrides,
  };
}

function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return (
    <TestRouter>
      <QueryClientProvider client={qc}>
        <ToastProvider>{children}</ToastProvider>
      </QueryClientProvider>
    </TestRouter>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("approval meta", () => {
  it("formats countdowns and escalates their tone", () => {
    expect(formatCountdown(65_000)).toBe("1:05");
    expect(formatCountdown(3_725_000)).toBe("1h 02m");
    expect(formatCountdown(-5)).toBe("0:00");
    expect(countdownTone(30_000)).toBe("danger");
    expect(countdownTone(120_000)).toBe("warn");
    expect(countdownTone(600_000)).toBe("neutral");
  });

  it("anchors the deadline to when the response arrived, only while pending", () => {
    expect(deadlineOf(approval(), 1_000)).toBe(301_000);
    expect(deadlineOf(approval({ status: "approved", seconds_remaining: null }), 1_000)).toBeNull();
  });

  it("builds risk chips only from recorded facts", () => {
    const keys = riskChips(approval()).map((c) => c.key);
    expect(keys).toEqual(["destination", "secrets", "trifecta", "session"]);
    const safe = approval({
      target: { ...approval().target, destination: null },
      risk: { ...approval().risk, trifecta: false, secrets_in_arguments: 0, session_level: "low", destination_classification: null },
    });
    expect(riskChips(safe)).toEqual([]);
  });

  it("labels outcomes and audit entries in plain language", () => {
    expect(decidedByLabel(approval({ status: "expired" }))).toBe("Nobody (timed out)");
    expect(decidedByLabel(approval({ status: "approved", decided_by: { id: "u", name: "Ada", email: null } }))).toBe("Ada");
    expect(ranWithoutApproval(approval({ tool_invocation_status: "completed" }))).toBe(true);
    expect(ranWithoutApproval(approval({ status: "approved", tool_invocation_status: "completed" }))).toBe(false);
    const entry = { id: "a", seq: 3, occurred_at: "", action: "approval.decided", actor_type: "user", actor_id: "u", actor_name: "Ada", details: { outcome: "rejected" } };
    expect(activityTitle(entry)).toEqual({ title: "Rejected by Ada", tone: "deny" });
  });
});

describe("ApprovalQueue", () => {
  it("shows the action, deciding policy, risk chips and a live countdown", () => {
    const onSelect = vi.fn();
    render(
      wrap(
        <ApprovalQueue items={[approval()]} receivedAt={Date.now()} selectedId={null} onSelect={onSelect} onDeadline={() => undefined} loading={false} error={null} onRetry={() => undefined} onShowHistory={() => undefined} />,
      ),
    );
    expect(screen.getByText("send POST to hooks.webhook.site")).toBeInTheDocument();
    expect(screen.getByText("Require approval for suspicious destinations")).toBeInTheDocument();
    expect(screen.getByText("Suspicious destination")).toBeInTheDocument();
    expect(screen.getByText(/left to decide/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("option"));
    expect(onSelect).toHaveBeenCalledWith("apr_1");
  });

  it("explains how approvals arise when the queue is empty", () => {
    render(
      wrap(<ApprovalQueue items={[]} receivedAt={0} selectedId={null} onSelect={() => undefined} onDeadline={() => undefined} loading={false} error={null} onRetry={() => undefined} onShowHistory={() => undefined} />),
    );
    expect(screen.getByText("Nothing is waiting for a human")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review approval policies" })).toHaveAttribute("href", "/policies");
  });
});

describe("DecisionBar", () => {
  function mockDecide(status: number, body: unknown) {
    return vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
  }

  it("rejects with the R shortcut and sends the note", async () => {
    const fetchMock = mockDecide(200, detail({ status: "rejected" }));
    const onDecided = vi.fn();
    render(wrap(<DecisionBar approval={detail()} canApprove deadlinePassed={false} onDecided={onDecided} />));
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "Not expected" } });
    // Typing in the note never triggers shortcuts.
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "r" });
    expect(fetchMock).not.toHaveBeenCalled();
    await act(async () => {
      fireEvent.keyDown(window, { key: "r" });
    });
    await waitFor(() => expect(onDecided).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/v1/approvals/apr_1/decide");
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ approve: false, note: "Not expected" });
  });

  it("asks for confirmation before approving a flagged request", async () => {
    const fetchMock = mockDecide(200, detail({ status: "approved" }));
    render(wrap(<DecisionBar approval={detail()} canApprove deadlinePassed={false} onDecided={() => undefined} />));
    fireEvent.click(screen.getByRole("button", { name: /Approve/ }));
    expect(await screen.findByText("Approve this request?")).toBeInTheDocument();
    expect(screen.getByText("The destination hooks.webhook.site is classified SUSPICIOUS.")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Approve anyway" }));
    });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))).toEqual({ approve: true, note: null });
  });

  it("shows the server's conflict message when the request was already decided", async () => {
    mockDecide(409, { error: { code: "conflict", message: "This request was already approved." } });
    render(wrap(<DecisionBar approval={detail({ requires_confirmation: false })} canApprove deadlinePassed={false} onDecided={() => undefined} />));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Approve/ }));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("This request was already approved.");
  });

  it("explains the missing permission instead of offering dead buttons", () => {
    render(wrap(<DecisionBar approval={detail()} canApprove={false} deadlinePassed={false} onDecided={() => undefined} />));
    expect(screen.queryByRole("button", { name: /Approve/ })).toBeNull();
    expect(screen.getByText(/needs the/)).toBeInTheDocument();
  });
});
