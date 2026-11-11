import { render, screen } from "@testing-library/react";
import { clearedParams, hasActiveFilters, itemFiltersFrom, sinceIso, sourceFiltersFrom, toggleValue } from "../filters";
import { describeSkew, receiptExport, receiptFilename, techniqueLabel } from "../meta";
import { VerificationBanner } from "../receipt/VerificationBanner";
import type { ContextReceipt } from "../types";

const receipt = (status: "valid" | "invalid" | "missing"): ContextReceipt => ({
  receipt: {
    receipt_version: "1",
    context_item_id: "ctx_01",
    organization_id: "org_01",
    source: { type: "web", identifier: "https://docs.example.com", trust_level_at_ingest: "EXTERNAL" },
    agent_id: "agt_01",
    session_id: "ses_01",
    event_id: "evt_01",
    collected_via: "claude_code:PostToolUse:WebFetch",
    collected_at: "2026-11-10T10:00:00Z",
    received_at: "2026-11-10T10:00:01Z",
    content_hash: "a".repeat(64),
    content_length: 120,
    content_type: "text/plain",
    sensitivity: "internal",
    contains_secrets: false,
    secret_fingerprint_count: 0,
    detection: { score: 0, max_severity: null, rule_ids: [] },
    tool_invocation_id: null,
  },
  signature: status === "missing" ? null : "b".repeat(64),
  signature_valid: status === "valid",
  verification: { status, algorithm: "HMAC-SHA256", purpose: "context-receipt-v1", explanation: `explanation for ${status}` },
  timestamps: { collected_at: "2026-11-10T10:00:00Z", received_at: "2026-11-10T10:00:01Z", skew_seconds: 1, explanation: "server is authoritative" },
  statement: { summary: "summary", proves: ["p"], does_not_prove: ["That the model acted on it."] },
  related: {
    source: { id: "src_01", source_type: "web", identifier: "https://docs.example.com", display_name: null, domain: "docs.example.com", trust_level: "EXTERNAL" },
    agent: { id: "agt_01", name: "coder" },
    session: { id: "ses_01", external_session_id: "sess-1", status: "active" },
    tool_invocation: null,
    findings: [],
    subsequent_events: [],
    more_subsequent_events: false,
    subsequent_events_note: "observed sequence only",
  },
  is_simulation: false,
  generated_at: "2026-11-10T10:05:00Z",
});

describe("context explorer URL filters", () => {
  it("maps URL params to API filters and drops empty values", () => {
    const params = new URLSearchParams("q=readme&trust=SUSPICIOUS&trust=UNKNOWN&detections=yes&secrets=yes&sim=1&type=file&item=ctx_1");
    expect(itemFiltersFrom(params)).toEqual({
      q: "readme",
      trust_level: ["SUSPICIOUS", "UNKNOWN"],
      has_detections: true,
      contains_secrets: true,
      include_simulated: true,
      source_type: "file",
    });
    expect(itemFiltersFrom(new URLSearchParams(""))).toEqual({});
  });

  it("reads source filters and ignores unknown sorts", () => {
    expect(sourceFiltersFrom(new URLSearchParams("view=sources&strust=BLOCKED&findings=no&sort=items"))).toEqual({ trust_level: "BLOCKED", has_findings: false, sort: "items" });
    expect(sourceFiltersFrom(new URLSearchParams("sort=random"))).toEqual({});
  });

  it("rounds the since window to the minute so query keys stay stable", () => {
    const now = Date.parse("2026-11-10T12:34:56.789Z");
    expect(sinceIso("1h", now)).toBe("2026-11-10T11:34:00.000Z");
    expect(sinceIso("bogus", now)).toBeUndefined();
  });

  it("toggles repeatable values and clears filters but keeps view, simulation and drawers", () => {
    let params = new URLSearchParams("trust=TRUSTED");
    params = toggleValue(params, "trust", "BLOCKED");
    expect(params.getAll("trust")).toEqual(["TRUSTED", "BLOCKED"]);
    params = toggleValue(params, "trust", "TRUSTED");
    expect(params.getAll("trust")).toEqual(["BLOCKED"]);

    const full = new URLSearchParams("view=sources&sim=1&src=src_1&q=x&strust=BLOCKED");
    expect(hasActiveFilters(full, "sources")).toBe(true);
    const cleared = clearedParams(full);
    expect(cleared.toString()).toBe("view=sources&sim=1&src=src_1");
    expect(hasActiveFilters(cleared, "sources")).toBe(false);
  });
});

describe("context explorer presentation helpers", () => {
  it("describes detection techniques and clock skew in words", () => {
    expect(techniqueLabel("html_comment")).toBe("Hidden in an HTML comment");
    expect(techniqueLabel("multilingual:de")).toBe("Non-English text (de)");
    expect(techniqueLabel("reflowed")).toBe("Hard-wrapped lines re-joined");
    expect(describeSkew(1.5)).toBe("Received 1.5 s after the reported collection time");
    expect(describeSkew(-300)).toContain("client clock ahead");
  });

  it("exports the signed fields with the signature and a safe filename", () => {
    const exported = JSON.parse(receiptExport(receipt("valid")));
    expect(exported.receipt.content_hash).toBe("a".repeat(64));
    expect(exported.signature).toBe("b".repeat(64));
    expect(exported.signature_algorithm).toBe("HMAC-SHA256");
    expect(exported.verification_at_export.status).toBe("valid");
    expect(receiptFilename("ctx_01/../x")).toBe("context-receipt-ctx_01____x.json");
  });
});

describe("VerificationBanner", () => {
  it("announces an invalid signature as an alert", () => {
    render(<VerificationBanner receipt={receipt("invalid")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Signature INVALID");
    expect(screen.getByText("explanation for invalid")).toBeInTheDocument();
  });

  it("shows a valid signature as a status", () => {
    render(<VerificationBanner receipt={receipt("valid")} />);
    expect(screen.getByRole("status")).toHaveTextContent("Signature valid");
  });
});
