import { useState } from "react";
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { TrifectaIndicator } from "../detail/SessionsTable";
import { ChipsInput } from "../forms/ChipsInput";
import { createInput, draftFromAgent, emptyDraft, patchFromDraft } from "../forms/AgentForm";
import { DeclaredToolsEditor } from "../forms/DeclaredToolsEditor";
import { DECISION_ORDER, durationLabel, relationshipLabel, sortedCounts, toolCategoryLabel } from "../meta";
import type { AgentDetail, DeclaredToolInput } from "../types";

function agent(overrides: Partial<AgentDetail> = {}): AgentDetail {
  return {
    id: "agent_1",
    name: "coder",
    description: "Builds things",
    framework: "claude_code",
    version: null,
    owner: "platform",
    environment: "production",
    labels: ["pci", "quarantined"],
    status: "quarantined",
    is_simulation: false,
    created_at: "2026-11-01T10:00:00Z",
    last_seen_at: null,
    risk_score: 0,
    risk_level: "low",
    session_count: 0,
    active_session_count: 0,
    open_findings: 0,
    max_open_severity: null,
    declared_tool_count: 2,
    observed_tool_count: 0,
    integration_kind: null,
    declared_capabilities: {
      tools: [
        { name: "Bash", category: "shell", risk_level: "high", category_hint: null },
        { name: "notes", category: "http", risk_level: "medium", category_hint: "http" },
      ],
      permissions: ["Bash(git:*)"],
      mcp_servers: [],
    },
    integration: null,
    findings_by_severity: {},
    recent_findings: [],
    relationships: [],
    decisions_by_enforcement: {},
    quarantine: {
      active: true,
      label: "quarantined",
      enforced: false,
      policies: [],
      explanation: "",
      suggested_policy: { name: "p", description: "", outcome: "DENY", mode: "enforce", enabled: true, priority: 1, severity: "high", conditions: {}, tags: [] },
    },
    ...overrides,
  };
}

describe("agent form helpers", () => {
  it("produces an empty patch when nothing changed, so guarded fields never need policy:manage", () => {
    const a = agent();
    expect(patchFromDraft(a, draftFromAgent(a))).toEqual({});
  });

  it("keeps the reserved quarantine label out of the editable labels", () => {
    expect(draftFromAgent(agent()).labels).toEqual(["pci"]);
  });

  it("sends only changed fields and clears blank text with null", () => {
    const a = agent();
    const draft = { ...draftFromAgent(a), owner: "  ", environment: "staging" as const };
    expect(patchFromDraft(a, draft)).toEqual({ owner: null, environment: "staging" });
  });

  it("sends a client category only as a hint and only when one was picked", () => {
    const a = agent();
    const draft = { ...draftFromAgent(a), tools: [...draftFromAgent(a).tools, { name: "Read", category: null }] };
    expect(patchFromDraft(a, draft).declared_capabilities?.tools).toEqual([{ name: "Bash" }, { name: "notes", category: "http" }, { name: "Read" }]);
  });

  it("trims the name and nulls empty optional fields on registration", () => {
    const input = createInput({ ...emptyDraft(), name: "  billing-bot ", tools: [{ name: "WebFetch", category: null }] });
    expect(input).toMatchObject({ name: "billing-bot", owner: null, version: null, description: null });
    expect(input.declared_capabilities?.tools).toEqual([{ name: "WebFetch" }]);
  });
});

describe("meta helpers", () => {
  it("orders decision counts most restrictive first and drops zeros", () => {
    expect(sortedCounts({ ALLOW: 3, DENY: 1, AUDIT: 0, CUSTOM: 2 }, DECISION_ORDER)).toEqual([
      ["DENY", 1],
      ["ALLOW", 3],
      ["CUSTOM", 2],
    ]);
  });

  it("labels relationships by direction and categories by name", () => {
    expect(relationshipLabel("delegates_to", "incoming")).toBe("Receives work from");
    expect(relationshipLabel("messages", "outgoing")).toBe("Sends messages to");
    expect(toolCategoryLabel("agent_delegation")).toBe("Agent delegation");
  });

  it("formats durations and rejects inverted ranges", () => {
    expect(durationLabel("2026-11-01T10:00:00Z", "2026-11-01T10:01:05Z")).toBe("1m 5s");
    expect(durationLabel("2026-11-01T10:00:00Z", "2026-11-01T09:00:00Z")).toBe("—");
  });
});

describe("TrifectaIndicator", () => {
  it("names the conditions present and calls the trifecta a condition, not proof", () => {
    render(<TrifectaIndicator session={{ sensitive_access: true, untrusted_exposure: true, outbound_channel: true, trifecta: true }} />);
    const img = screen.getByRole("img");
    expect(img).toHaveAccessibleName("Conditions present: sensitive data access, untrusted content, outbound channel");
    expect(img.getAttribute("title")).toContain("not proof of an attack");
  });

  it("says when no condition is present", () => {
    render(<TrifectaIndicator session={{ sensitive_access: false, untrusted_exposure: false, outbound_channel: false, trifecta: false }} />);
    expect(screen.getByRole("img")).toHaveAccessibleName("No trifecta condition present");
  });
});

function ChipsHarness({ initial = [] as string[] }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <ChipsInput id="labels" value={value} onChange={setValue} lowercase reserved={{ quarantined: "reserved label" }} />
      <output data-testid="value">{value.join("|")}</output>
    </>
  );
}

describe("ChipsInput", () => {
  it("adds lower-cased, de-duplicated entries and refuses reserved ones with a reason", () => {
    render(<ChipsHarness />);
    const input = screen.getByRole("textbox");
    fireEvent.change(input, { target: { value: "PCI, payments, pci" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByTestId("value").textContent).toBe("pci|payments");
    fireEvent.change(input, { target: { value: "Quarantined" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByRole("alert").textContent).toBe("reserved label");
    expect(screen.getByTestId("value").textContent).toBe("pci|payments");
  });

  it("removes the last entry with Backspace on an empty field", () => {
    render(<ChipsHarness initial={["a", "b"]} />);
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Backspace" });
    expect(screen.getByTestId("value").textContent).toBe("a");
  });
});

function ToolsHarness() {
  const [value, setValue] = useState<DeclaredToolInput[]>([{ name: "Read", category: null }]);
  return (
    <>
      <DeclaredToolsEditor value={value} onChange={setValue} />
      <output data-testid="tools">{value.map((t) => `${t.name}:${t.category ?? ""}`).join("|")}</output>
    </>
  );
}

describe("DeclaredToolsEditor", () => {
  it("adds several comma-separated tools, skips duplicates and records a category hint", () => {
    render(<ToolsHarness />);
    const input = screen.getByLabelText("Add tool names");
    fireEvent.change(input, { target: { value: "Bash, Read, mcp__github__create_issue" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByTestId("tools").textContent).toBe("Read:|Bash:|mcp__github__create_issue:");
    fireEvent.change(screen.getByLabelText("Category hint for Bash"), { target: { value: "shell" } });
    expect(screen.getByTestId("tools").textContent).toBe("Read:|Bash:shell|mcp__github__create_issue:");
    fireEvent.click(screen.getByRole("button", { name: "Remove Read" }));
    expect(screen.getByTestId("tools").textContent).toBe("Bash:shell|mcp__github__create_issue:");
  });
});
