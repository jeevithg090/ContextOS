import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { EvidenceLinks } from "../components/EvidenceLinks";
import { RunDetail } from "../components/RunDetail";
import { RUN } from "./fixtures";

describe("EvidenceLinks", () => {
  it("links records that have a page and shows the rest as plain ids", () => {
    render(
      <TestRouter>
        <EvidenceLinks
          sessionId="ses_1"
          evidence={[
            { type: "incident", id: "inc_1" },
            { type: "context_item", id: "ctx_1" },
            { type: "tool", id: "tool_1" },
            { type: "provenance_edge", id: "edge_1" },
            { type: "ingested_events", id: "evt_1" },
            { type: "finding", id: "" },
          ]}
        />
      </TestRouter>,
    );
    expect(screen.getByRole("link", { name: "Incident inc_1" })).toHaveAttribute("href", "/incidents/inc_1");
    expect(screen.getByRole("link", { name: "Context item ctx_1" })).toHaveAttribute("href", "/context/ctx_1");
    expect(screen.getAllByRole("link")).toHaveLength(2);
    expect(screen.getByText("Provenance edge")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
  });

  it("opens session-scoped records in the session they belong to", () => {
    render(
      <TestRouter>
        <EvidenceLinks
          sessionId="ses_parent"
          evidence={[
            { type: "tool_invocation", id: "tiv_child", session_id: "ses_child" },
            { type: "tool_invocation", id: "tiv_parent" },
          ]}
        />
      </TestRouter>,
    );
    const links = screen.getAllByRole("link");
    expect(links[0]).toHaveAttribute("href", "/sessions/ses_child?invocation=tiv_child");
    expect(links[1]).toHaveAttribute("href", "/sessions/ses_parent?invocation=tiv_parent");
  });

  it("renders nothing without evidence", () => {
    const { container } = render(<EvidenceLinks evidence={[]} sessionId={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("RunDetail", () => {
  it("explains a run that stopped early and never claims an advisory decision was enforced", () => {
    const run = {
      ...RUN,
      status: "failed",
      error: "pipeline error at step 'send-key'",
      session_id: null,
      suite_run_id: null,
      agent_id: "agt_1",
      agent_version: "2.0.0",
      results: [
        { kind: "observation" as const, step: "send-key", expectation: "Step", expected: null, actual: "DENY (advisory) — not run", passed: null, decision: "DENY", matched_policies: [null, "Block"], evidence: [], evidence_ids: [] },
        { kind: "observation" as const, step: "later", expectation: "Step", expected: null, actual: "not run (an earlier step failed)", passed: null, evidence: [], evidence_ids: [] },
      ],
      policy_snapshot: [],
    };
    const onShowSuite = vi.fn();
    render(
      <TestRouter>
        <RunDetail run={run} onShowSuite={onShowSuite} />
      </TestRouter>,
    );
    expect(screen.getByText("Stopped early")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("The run stopped early: pipeline error at step 'send-key'");
    expect(screen.queryByText("Denied before it ran.")).not.toBeInTheDocument();
    expect(screen.getByText(/Would have been denied, but the decision was advisory/)).toBeInTheDocument();
    expect(screen.getByText("Advisory")).toBeInTheDocument();
    expect(screen.getByText(/Not submitted — an earlier step failed/)).toBeInTheDocument();
    expect(screen.getByText("Matched policies: Block")).toBeInTheDocument();
    expect(screen.getByText(/no session or provenance graph to open/)).toBeInTheDocument();
    expect(screen.getByText("Single run")).toBeInTheDocument();
    expect(screen.getByText("2.0.0")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Agent agt_1" })).toHaveAttribute("href", "/agents/agt_1");
    const snapshot = screen.getByText(/^Policy snapshot/).closest("details") as HTMLElement;
    expect(within(snapshot).getByText(/had no policies when this run started/)).toBeInTheDocument();
  });

  it("links the suite back to its runs", () => {
    const onShowSuite = vi.fn();
    render(
      <TestRouter>
        <RunDetail run={RUN} onShowSuite={onShowSuite} />
      </TestRouter>,
    );
    screen.getByRole("button", { name: /show all runs/ }).click();
    expect(onShowSuite).toHaveBeenCalledWith("suite_01XYZ");
  });
});
