import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { EntityLink } from "../EntityLink";
import { entityHref } from "../entityRoutes";

const renderInRouter = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe("entityHref route map", () => {
  it.each([
    ["agent", "agt_1", undefined, "/agents/agt_1"],
    ["session", "ses_1", undefined, "/sessions/ses_1"],
    ["context_item", "ctx_1", undefined, "/context/ctx_1"],
    ["finding", "fnd_1", undefined, "/intelligence/fnd_1"],
    ["incident", "inc_1", undefined, "/incidents/inc_1"],
    ["task", "tsk_1", undefined, "/work/tasks/tsk_1"],
    ["policy", "pol_1", undefined, "/policies?policy=pol_1"],
    ["source", "src_1", undefined, "/trust?source=src_1"],
    ["destination", "dst_1", undefined, "/trust?tab=destinations&destination=dst_1"],
    ["tool_invocation", "tin_1", "ses_9", "/sessions/ses_9?invocation=tin_1"],
    ["approval", "apr_1", undefined, "/approvals?approval=apr_1"],
    ["policy_decision", "pdc_1", "ses_9", "/replay/ses_9?decision=pdc_1"],
    ["simulation_run", "sim_1", undefined, "/simulation?run=sim_1"],
  ])("%s %s → %s", (type, id, sessionId, expected) => {
    expect(entityHref(type, id, { sessionId })).toBe(expected);
  });

  it("returns null when context is missing or the entity has no page", () => {
    expect(entityHref("tool_invocation", "tin_1")).toBeNull();
    expect(entityHref("policy_decision", "pdc_1")).toBeNull();
    expect(entityHref("event", "evt_1")).toBeNull();
    expect(entityHref("something_else", "x_1")).toBeNull();
    expect(entityHref("agent", "")).toBeNull();
  });

  it("encodes ids so they cannot inject path segments or query params", () => {
    expect(entityHref("agent", "../admin?x=1")).toBe("/agents/..%2Fadmin%3Fx%3D1");
    expect(entityHref("policy", "a&tab=b")).toBe("/policies?policy=a%26tab%3Db");
  });
});

describe("EntityLink", () => {
  it("links with a label and keeps the full id in the title", () => {
    renderInRouter(<EntityLink type="agent" id="agt_01HZZZABCDEF123456" label="Billing bot" />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/agents/agt_01HZZZABCDEF123456");
    expect(link).toHaveTextContent("Billing bot");
    expect(link.getAttribute("title")).toContain("agt_01HZZZABCDEF123456");
  });

  it("shows a short id when there is no label", () => {
    renderInRouter(<EntityLink type="finding" id="fnd_01HZZZABCDEF123456" />);
    expect(screen.getByRole("link")).toHaveTextContent("fnd_123456");
  });

  it("falls back to plain text for tool calls without a session and for events", () => {
    renderInRouter(
      <>
        <EntityLink type="tool_invocation" id="tin_01HZZZABCDEF999999" />
        <EntityLink type="event" id="evt_01HZZZABCDEF888888" />
      </>,
    );
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    expect(screen.getByText("tin_999999")).toBeInTheDocument();
    expect(screen.getByText("evt_888888")).toBeInTheDocument();
  });

  it("links tool calls into their session when sessionId is provided", () => {
    renderInRouter(<EntityLink type="tool_invocation" id="tin_1" sessionId="ses_2" />);
    expect(screen.getByRole("link")).toHaveAttribute("href", "/sessions/ses_2?invocation=tin_1");
  });

  it("renders a dash for a missing id", () => {
    renderInRouter(<EntityLink type="agent" id={null} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("does not bubble clicks to a clickable parent row", () => {
    const onParent = vi.fn();
    renderInRouter(
      <div onClick={onParent}>
        <EntityLink type="incident" id="inc_1" />
      </div>,
    );
    fireEvent.click(screen.getByRole("link"));
    expect(onParent).not.toHaveBeenCalled();
  });
});
