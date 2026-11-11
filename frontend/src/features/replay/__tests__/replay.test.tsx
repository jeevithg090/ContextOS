import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { CounterfactualResults } from "../counterfactual/CounterfactualResults";
import { SimulationBanner } from "../counterfactual/SimulationBanner";
import { ReplayPlayer } from "../player/ReplayPlayer";
import { clampIndex, intervalFor } from "../player/usePlayer";
import { EMPTY_POLICY_SET, changeCount, isEnabled, parseDraft, setEnabled, setOverride, toRequest } from "../policySet";
import type { CounterfactualResult, Replay, ReplayPolicy, ReplayStep } from "../types";

const POLICY: ReplayPolicy = {
  id: "pol_block",
  name: "Block credential exfiltration",
  description: null,
  enabled: true,
  mode: "enforce",
  priority: 1000,
  outcome: "DENY",
  severity: "critical",
  version: 1,
  is_builtin: true,
  restrictions: {},
  explanation: "secrets_in_arguments is not empty",
};

function step(index: number, overrides: Partial<ReplayStep> = {}): ReplayStep {
  return {
    index,
    sequence: 10 + index,
    event_id: `evt_${index}`,
    event_type: "tool.requested",
    received_at: "2026-11-11T09:00:00Z",
    occurred_at: "2026-11-11T09:00:00Z",
    title: `Step title ${index}`,
    summary: null,
    processing_status: "processed",
    from_other_session: false,
    trust_level: null,
    tool: null,
    refs: { context_item_id: null, tool_invocation_id: null, policy_decision_id: null, finding_ids: [], approval_id: null, child_session_id: null, source_id: null, destination_id: null },
    outcome: null,
    findings: [],
    risk_after: { score: index * 10, level: "low", delta: 10, trifecta: false, sensitive_access: false, untrusted_exposure: false, outbound_channel: false, summary: "No lethal-trifecta conditions observed yet.", factors: [], basis: "recomputed from recorded events" },
    recorded_risk: null,
    ...overrides,
  };
}

function replay(steps: ReplayStep[]): Replay {
  return {
    session: { id: "asn_1", external_session_id: "sess-1", agent: { id: "agt_1", name: "coder", framework: "claude_code", environment: "development", status: "active", is_simulation: false }, parent_session_id: null, status: "active", started_at: "2026-11-11T09:00:00Z", ended_at: null, last_event_at: null, event_count: steps.length, risk_score: 30, risk_level: "medium", trifecta: false, is_simulation: false },
    basis: "Steps are recorded events.",
    risk_basis: "recomputed from recorded events",
    risk_note: "Recomputed.",
    total_steps: steps.length,
    decision_steps: 1,
    offset: 0,
    limit: 500,
    truncated: false,
    focus_index: null,
    steps,
  };
}

function renderUi(ui: React.ReactNode) {
  return render(
    <TestRouter>
      <TooltipProvider>{ui}</TooltipProvider>
    </TestRouter>,
  );
}

describe("policy set state", () => {
  it("disables, re-enables and folds a disable into an override when outcome changes", () => {
    let s = setEnabled(EMPTY_POLICY_SET, POLICY, false);
    expect(s.disabled).toEqual(["pol_block"]);
    expect(isEnabled(s, POLICY)).toBe(false);
    s = setOverride(s, POLICY, { outcome: "AUDIT" });
    expect(s.disabled).toEqual([]);
    expect(s.overrides.pol_block).toEqual({ outcome: "AUDIT", enabled: false });
    s = setEnabled(s, POLICY, true);
    expect(s.overrides.pol_block).toEqual({ outcome: "AUDIT" });
    s = setOverride(s, POLICY, { outcome: "DENY" });
    expect(s.overrides).toEqual({});
    expect(changeCount(s)).toBe(0);
  });

  it("enables a policy saved as disabled through an override and builds the request", () => {
    const saved = { ...POLICY, enabled: false };
    const s = setEnabled(EMPTY_POLICY_SET, saved, true);
    expect(s.overrides).toEqual({ pol_block: { enabled: true } });
    expect(toRequest("asn_1", s)).toEqual({
      session_id: "asn_1",
      policy_set: { base: "current", disable_policy_ids: [], overrides: { pol_block: { enabled: true } }, add_policies: [] },
    });
    const none = toRequest("asn_1", { ...s, base: "none", defaultDecision: "DENY" });
    expect(none.policy_set.overrides).toEqual({});
    expect(none.default_decision).toBe("DENY");
  });

  it("parses drafts and reports shape problems before calling the server", () => {
    expect(parseDraft("{")[1][0]).toMatch(/Not valid JSON/);
    expect(parseDraft('{"name": "x", "outcome": "nope", "conditions": {}}')[1]).toEqual([expect.stringMatching(/"outcome" must be one of/)]);
    const [draft, errors] = parseDraft('{"name": "Deny reads", "outcome": "deny", "conditions": {"field": "tool.name", "op": "eq", "value": "Read"}}');
    expect(errors).toEqual([]);
    expect(draft?.outcome).toBe("DENY");
  });
});

describe("player", () => {
  it("clamps indices and scales the interval by speed", () => {
    expect(clampIndex(-3, 5)).toBe(0);
    expect(clampIndex(9, 5)).toBe(4);
    expect(clampIndex(2, 0)).toBe(0);
    expect(intervalFor(2)).toBe(intervalFor(1) / 2);
  });

  it("steps with the keyboard and buttons and shows the recorded outcome", () => {
    const steps = [
      step(0, { event_type: "session.started", title: "Session started" }),
      step(1, {
        title: "Denied WebFetch to webhook.site",
        refs: { ...step(1).refs, policy_decision_id: "pdc_1" },
        outcome: { policy_decision_id: "pdc_1", decision: "DENY", enforcement: "enforced", explanation: 'DENY by policy "Block credential exfiltration"', matched_policies: ["Block credential exfiltration"], approval_id: null, approval_status: null },
      }),
      step(2, { title: "Session ended", event_type: "session.ended" }),
    ];
    renderUi(<ReplayPlayer replay={replay(steps)} initialIndex={0} onWindow={() => undefined} keyboard />);
    const list = screen.getByRole("list", { name: "Recorded steps" });
    expect(within(list).getByRole("button", { current: "step" })).toHaveTextContent("Session started");

    fireEvent.keyDown(window, { key: "ArrowRight" });
    expect(within(list).getByRole("button", { current: "step" })).toHaveTextContent("Denied WebFetch");
    expect(screen.getByText(/DENY by policy/)).toBeInTheDocument();
    expect(screen.getAllByText("recomputed from recorded events").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Last step (End)" }));
    expect(within(list).getByRole("button", { current: "step" })).toHaveTextContent("Session ended");
    fireEvent.keyDown(window, { key: "Home" });
    expect(within(list).getByRole("button", { current: "step" })).toHaveTextContent("Session started");
    expect(screen.getByRole("slider", { name: "Replay position" })).toHaveValue("0");
  });
});

describe("counterfactual views", () => {
  it("always shows the simulation banner and highlights changed decisions", () => {
    renderUi(<SimulationBanner caveats={["Steps after a hypothetically denied action might not have occurred."]} />);
    expect(screen.getByRole("note", { name: "Simulation notice" })).toHaveTextContent("SIMULATION — hypothetical outcomes evaluated against recorded inputs, not historical fact");

    const result: CounterfactualResult = {
      simulation: true,
      label: "SIMULATION",
      basis: "recorded PolicyDecision.input_snapshot",
      session_id: "asn_1",
      policy_set: { base: "current", default_decision: "ALLOW", policies: [], warnings: [] },
      steps: [
        {
          decision_id: "pdc_1", invocation_id: "inv_1", event_id: "evt_1", sequence: 11, step_index: 1, evaluated_at: "2026-11-11T09:00:00Z",
          tool: { name: "WebFetch", category: "http" }, is_simulation: false,
          original_decision: "DENY", original_enforcement: "enforced", original_matches: ["Block credential exfiltration"], original_explanation: "DENY by policy",
          hypothetical_decision: "REQUIRE_APPROVAL", changed: true, hypothetical_matches: [], hypothetical_monitor_matches: [], hypothetical_restrictions: {}, evaluation_errors: [],
          current_decision: "DENY", drifted: false,
          policy_changes: [{ policy_id: "pol_block", name: "Block credential exfiltration", change: "disabled", detail: "Disabled in this simulation" }],
          explanation: "Hypothetically REQUIRE_APPROVAL instead of the recorded DENY.",
          evidence: [{ field: "destination.identifier", present: true, value: "webhook.site", policies: ["Require approval"] }],
          after_hypothetical_block: false,
        },
      ],
      summary: { evaluated: 1, changed: 1, would_deny: 0, would_pause: 1, would_allow: 0, would_restrict: 0, drifted: 0, transitions: { "DENY→REQUIRE_APPROVAL": 1 } },
      caveats: [],
      not_evaluable_count: 0,
      not_evaluable: [],
      truncated: false,
    };
    renderUi(<CounterfactualResults result={result} sessionId="asn_1" />);
    expect(screen.getByText("Hypothetically REQUIRE_APPROVAL instead of the recorded DENY.")).toBeInTheDocument();
    expect(screen.getByText("Disabled in this simulation")).toBeInTheDocument();
    expect(screen.getByText('"webhook.site"')).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open this step in the player/ })).toHaveAttribute("href", "/replay/asn_1?decision=pdc_1");
  });
});
