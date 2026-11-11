import { render, screen, within } from "@testing-library/react";
import { TooltipProvider } from "@/components/ui";
import { TestRouter } from "@/test/router";
import { AssessmentView } from "../AssessmentView";
import { CapabilityChips } from "../components";
import type { Assessment } from "../types";

const DESTINATION: Assessment = {
  scope: "destination",
  level: "SUSPICIOUS",
  capabilities: [],
  reasons: ["Matches trust rule 'Webhook.site' (pattern '*.webhook.site' on the domain), which classifies it as SUSPICIOUS."],
  canonical_identifier: "abc.webhook.site",
  domain: null,
  kind: "domain",
  matched_rule: { id: "trl_1", name: "Webhook.site", pattern: "*.webhook.site", match_field: "domain", applies_to: "destination", source_type: null, trust_level: "SUSPICIOUS", priority: 150, is_draft: false },
  matching_rules: [
    { id: "trl_1", name: "Webhook.site", pattern: "*.webhook.site", match_field: "domain", applies_to: "destination", source_type: null, trust_level: "SUSPICIOUS", priority: 150, is_draft: false },
    { id: null, name: "Draft allow", pattern: "abc.webhook.site", match_field: "domain", applies_to: "destination", source_type: null, trust_level: "APPROVED", priority: 100, is_draft: true },
  ],
  checks: [
    { check: "allowlist", result: "warn", detail: "Not on the organisation's destination allowlist." },
    { check: "exfiltration_service", result: "fail", detail: "Webhook.site is a request-capture service." },
    { check: "first_seen", result: "unknown", detail: "No destination history was supplied." },
  ],
  not_verified: ["Who operates this destination, or who will receive the data."],
};

const renderUi = (ui: React.ReactElement) => render(<TestRouter><TooltipProvider>{ui}</TooltipProvider></TestRouter>);

describe("AssessmentView", () => {
  it("shows the deciding rule, overridden rules, failing checks first and what was not verified", () => {
    renderUi(<AssessmentView assessment={DESTINATION} />);
    const rules = screen.getByRole("list", { name: "Matching rules in precedence order" });
    const items = within(rules).getAllByRole("listitem");
    expect(within(items[0]).getByText("Decides")).toBeInTheDocument();
    expect(within(items[1]).getByText("Overridden")).toBeInTheDocument();
    expect(within(items[1]).getByText("Draft")).toBeInTheDocument();
    const checkNames = screen.getAllByText(/allowlist|capture, tunnel|Seen before/i).map((n) => n.textContent);
    expect(checkNames[0]).toContain("Known capture, tunnel or paste service");
    expect(screen.getByText("What ContextOS did not verify")).toBeInTheDocument();
    expect(screen.getByText("Who operates this destination, or who will receive the data.")).toBeInTheDocument();
  });

  it("explains when a manual classification outranks every matching rule", () => {
    renderUi(<AssessmentView assessment={{ ...DESTINATION, scope: "source", matched_rule: null, checks: [], not_verified: [] }} />);
    expect(screen.getByText(/a manual classification takes precedence over rules/)).toBeInTheDocument();
    expect(screen.queryByText("Decides")).not.toBeInTheDocument();
  });
});

describe("CapabilityChips", () => {
  it("always states what content cannot do", () => {
    renderUi(<CapabilityChips capabilities={["read"]} />);
    expect(screen.getByLabelText("can read, cannot instruct, cannot execute")).toBeInTheDocument();
  });
});
