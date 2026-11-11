import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { chainItems, WhatHappened } from "../detail/WhatHappened";
import { clearedParams, findingFiltersFrom, hasActiveFilters, selectedStatuses, toggleStatus, toggleValue, windowFrom, withStatuses } from "../filters";
import { confidenceWords, formatDuration } from "../meta";
import type { FindingDetail } from "../types";
import { TestRouter } from "@/test/router";

const qs = (s: string) => new URLSearchParams(s);

describe("finding filters (URL state)", () => {
  it("defaults to findings that still need attention", () => {
    expect(selectedStatuses(qs(""))).toEqual(["open", "acknowledged"]);
    expect(findingFiltersFrom(qs(""))).toEqual({ status: ["open", "acknowledged"] });
    expect(hasActiveFilters(qs(""))).toBe(false);
  });

  it("maps URL parameters to API filters", () => {
    const filters = findingFiltersFrom(qs("status=resolved&severity=critical&severity=high&category=exfiltration&agent=agt_1&session=ses_1&q=%20token%20&sim=1&sort=recent"));
    expect(filters).toEqual({
      status: ["resolved"],
      severity: ["critical", "high"],
      category: ["exfiltration"],
      agent_id: "agt_1",
      session_id: "ses_1",
      q: "token",
      include_simulated: true,
      sort: "recent",
    });
  });

  it("treats status=all as no status filter and ignores unknown sorts and windows", () => {
    expect(findingFiltersFrom(qs("status=all&sort=random")).status).toBeUndefined();
    expect(findingFiltersFrom(qs("sort=random")).sort).toBeUndefined();
    expect(windowFrom(qs("window=1y"))).toBe("7d");
    expect(windowFrom(qs("window=30d"))).toBe("30d");
  });

  it("stores the default status selection as no parameter and never an always-empty list", () => {
    expect(withStatuses(qs("status=open"), ["open", "acknowledged"]).getAll("status")).toEqual([]);
    expect(withStatuses(qs(""), []).getAll("status")).toEqual(["all"]);
    const resolvedAdded = toggleStatus(qs(""), "resolved");
    expect(resolvedAdded.getAll("status")).toEqual(["open", "acknowledged", "resolved"]);
    expect(toggleStatus(qs("status=all"), "open").getAll("status")).toEqual(["acknowledged", "resolved", "false_positive"]);
  });

  it("toggles repeated values and clears every filter but the window", () => {
    expect(toggleValue(qs("severity=high"), "severity", "critical").getAll("severity")).toEqual(["high", "critical"]);
    expect(toggleValue(qs("severity=high"), "severity", "high").getAll("severity")).toEqual([]);
    const cleared = clearedParams(qs("severity=high&q=x&source=src_1&window=30d&sim=1"));
    expect(cleared.toString()).toBe("window=30d&sim=1");
    expect(hasActiveFilters(qs("source=src_1"))).toBe(true);
  });
});

describe("presentation helpers", () => {
  it("shows confidence as words and a percentage", () => {
    expect(confidenceWords(0.92)).toMatchObject({ label: "High confidence", percent: "92%" });
    expect(confidenceWords(0.7)).toMatchObject({ label: "Medium confidence", percent: "70%" });
    expect(confidenceWords(0.2)).toMatchObject({ label: "Low confidence", percent: "20%" });
  });

  it("formats durations for mean time to resolve", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(42)).toBe("42s");
    expect(formatDuration(3 * 3600 + 120)).toBe("3h 2m");
    expect(formatDuration(3 * 86400)).toBe("3d");
  });
});

const baseFinding: FindingDetail = {
  id: "fnd_1",
  title: "Credential sent to an unknown destination",
  category: "exfiltration",
  rule_id: "CTX-CRED-FLOW-001",
  severity: "critical",
  confidence: 0.95,
  status: "open",
  agent: { id: "agt_1", name: "coder" },
  session: { id: "ses_1", external_session_id: "sess-x" },
  source: null,
  incident: null,
  occurrence_count: 1,
  first_seen_at: "2026-11-10T10:00:00Z",
  last_seen_at: "2026-11-10T10:00:00Z",
  is_simulation: false,
  explanation: "A credential read from .env was sent outbound.",
  remediation: "Rotate the token.",
  resolution_note: null,
  resolved_by: null,
  evidence: [],
  related: {
    agent: { id: "agt_1", name: "coder", framework: "claude_code", environment: "dev", status: "active" },
    session: { id: "ses_1", external_session_id: "sess-x", status: "active", started_at: "2026-11-10T09:59:00Z", risk_score: 80, risk_level: "critical", trifecta: true },
    source: null,
    context_item: null,
    tool_invocation: { id: "inv_1", session_id: "ses_1", tool_name: "WebFetch", tool_category: "network", status: "denied", decision: "DENY", enforcement: "enforced", requested_at: "2026-11-10T10:00:00Z" },
    decision: {
      id: "pd_1",
      session_id: "ses_1",
      decision: "DENY",
      enforcement: "enforced",
      explanation: "Credential exfiltration is blocked.",
      evaluated_at: "2026-11-10T10:00:00Z",
      matched_policies: [{ policy_id: "pol_1", name: "Block credential exfiltration", outcome: "DENY", mode: "enforce" }],
    },
    destination: { id: "dst_1", kind: "domain", identifier: "upload.unknown-collector.net", classification: "UNKNOWN" },
    incident: null,
    tasks: [],
  },
  history: [],
  allowed_transitions: ["acknowledged", "resolved", "false_positive"],
  incident_candidates: [],
  provenance_note: "These links are observed relationships, not causation.",
};

describe("What happened chain", () => {
  it("lists only the recorded steps, in order", () => {
    expect(chainItems(baseFinding).map((i) => i.id)).toEqual(["session", "tool_invocation", "decision", "destination"]);
  });

  it("states missing links plainly and keeps the provenance caveat", () => {
    render(
      <TestRouter>
        <WhatHappened finding={baseFinding} />
      </TestRouter>,
    );
    expect(screen.getByText(/No content source is linked/)).toBeInTheDocument();
    expect(screen.queryByText(/No tool call is linked/)).not.toBeInTheDocument();
    expect(screen.getByText("These links are observed relationships, not causation.")).toBeInTheDocument();
    expect(screen.getByText("Credential exfiltration is blocked.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Block credential exfiltration/ })).toHaveAttribute("href", "/policies?policy=pol_1");
    expect(screen.getByRole("link", { name: /Tool call WebFetch/ })).toHaveAttribute("href", "/sessions/ses_1?invocation=inv_1");
  });
});
