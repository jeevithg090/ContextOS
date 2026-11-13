import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { currentLocation, hang, notFound, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { ProvenancePage } from "../ProvenancePage";
import type { ProvenanceGraph } from "../types";
import { EMPTY_GRAPH, GRAPH, SOURCE_DETAIL } from "./pageFixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

/**
 * React Flow needs real layout (ResizeObserver, DOMMatrix, element sizes) that jsdom does not have,
 * and its own rendering is covered by the layout/graphModel unit tests. The page is tested with a
 * stand-in canvas that exposes the same selection callbacks.
 */
vi.mock("../ProvenanceCanvas", () => ({
  ProvenanceCanvas: ({ graph, hiddenTypes, onSelectNode, onSelectEdge }: { graph: ProvenanceGraph; hiddenTypes: ReadonlySet<string>; onSelectNode: (id: string) => void; onSelectEdge: (id: string) => void }) => (
    <div data-testid="canvas">
      {graph.nodes
        .filter((n) => !hiddenTypes.has(n.type))
        .map((n) => (
          <button key={n.id} type="button" onClick={() => onSelectNode(n.id)}>{`Canvas node ${n.label}`}</button>
        ))}
      {graph.edges.map((e) => (
        <button key={e.id} type="button" onClick={() => onSelectEdge(e.id)}>{`Canvas edge ${e.id}`}</button>
      ))}
    </div>
  ),
}));

afterEach(() => vi.unstubAllGlobals());

function routes({ graph }: { graph?: Reply } = {}): ApiRoute {
  return (c) => {
    if (c.path === "/provenance/graph") return graph ?? { body: GRAPH };
    if (c.path === "/provenance/nodes/source/src_docs") return { body: SOURCE_DETAIL };
    if (c.path === "/provenance/scopes") return { body: { sessions: [], agents: [], findings: [] } };
    return undefined;
  };
}

const renderGraph = (query = "") => renderPage(<ProvenancePage />, { path: `/provenance${query}`, routePath: "/provenance" });

describe("ProvenancePage", () => {
  it("shows skeletons for the canvas and the path list while the graph loads", () => {
    stubApi(routes({ graph: hang }));
    renderGraph();
    expect(screen.getByRole("heading", { name: "Provenance graph" })).toBeInTheDocument();
    expect(screen.getByLabelText("Loading graph")).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByTestId("canvas")).not.toBeInTheDocument();
  });

  it("shows the server's error with a retry", async () => {
    stubApi(routes({ graph: serverError("Graph builder unavailable") }));
    renderGraph("?session=ses_main");
    expect(await screen.findByText("Graph builder unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("says a linked record is not available for an unknown or foreign id and offers the default scope", async () => {
    const api = stubApi((c) => (c.path === "/provenance/graph" && c.query.get("finding_id") === "fnd_foreign" ? notFound("Finding") : routes()(c)));
    renderGraph("?finding=fnd_foreign");
    expect(await screen.findByText("That record isn’t available")).toBeInTheDocument();
    expect(api.gets("/provenance/graph")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Show the most recent high-risk session" }));
    await waitFor(() => expect(currentLocation()).toBe("/provenance"));
    expect(await screen.findByText("Session sess-7f3a (payments-coder)")).toBeInTheDocument();
  });

  it("explains how the graph fills in when nothing is recorded", async () => {
    stubApi(routes({ graph: { body: EMPTY_GRAPH } }));
    renderGraph();
    expect(await screen.findByText("No provenance recorded yet")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open Simulation Lab" }));
    await waitFor(() => expect(currentLocation()).toBe("/simulation"));
  });

  it("summarises the scope, labels edges as observed and lists risky paths with honest outcomes", async () => {
    stubApi(routes());
    renderGraph();
    expect(await screen.findByText("Session sess-7f3a (payments-coder)")).toBeInTheDocument();
    expect(screen.getByText("Showing the most recent high-risk session.")).toBeInTheDocument();
    expect(screen.getByText("Nodes").nextSibling).toHaveTextContent("6");
    expect(screen.getByText("Edges").nextSibling).toHaveTextContent("4");
    expect(screen.getByRole("tab", { name: /Risky paths/ })).toHaveTextContent("Risky paths2");
    expect(screen.getByText("Inferred").nextSibling).toHaveTextContent("1");
    expect(screen.getByText(/Edges are relationships observed by ContextOS — they do not prove the content caused an action\./)).toBeInTheDocument();
    expect(within(screen.getByTestId("canvas")).getByRole("button", { name: "Canvas node collector.example" })).toBeInTheDocument();

    const paths = screen.getByRole("list", { name: "Risky paths" });
    const prevented = within(paths).getByText("Untrusted page reached a session that tried to send a credential out").closest("li") as HTMLElement;
    expect(within(prevented).getByText("Prevented")).toBeInTheDocument();
    expect(within(prevented).getByText("score 88")).toBeInTheDocument();
    const advisory = within(paths).getByText("Untrusted page reached a session that ran curl").closest("li") as HTMLElement;
    expect(within(advisory).getByText("Advisory only")).toBeInTheDocument();
    expect(within(advisory).queryByText("Prevented")).not.toBeInTheDocument();
    expect(paths.textContent).not.toMatch(/\bblocked\b/i);

    fireEvent.click(within(advisory).getByRole("button", { name: /ran curl/ }));
    expect(within(advisory).getByText("A denial was returned, but the integration may not have honoured it.")).toBeInTheDocument();
    expect(within(advisory).getByText(/order of events could not be verified/)).toBeInTheDocument();
  });

  it("inspects a node's recorded fields and an edge's confidence", async () => {
    stubApi(routes());
    renderGraph();
    fireEvent.click(await screen.findByRole("button", { name: "Canvas node docs.vendor.example" }));
    const aside = screen.getByRole("complementary", { name: "Graph details" });
    expect(await within(aside).findByText("Classified SUSPICIOUS by the trust rule “Vendor docs”.")).toBeInTheDocument();
    expect(within(aside).getByText("https://docs.vendor.example/setup")).toBeInTheDocument();
    expect(within(aside).getByRole("link", { name: "Source Open record" })).toHaveAttribute("href", "/trust?source=src_docs");
    expect(within(aside).getByRole("button", { name: "Vendor setup guide" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Canvas edge e4" }));
    expect(await within(aside).findByRole("heading", { name: "Targeted" })).toBeInTheDocument();
    expect(within(aside).getByText(/Inferred by ContextOS/)).toBeInTheDocument();
    expect(within(aside).getByText(/It does not prove the content caused the action\./)).toBeInTheDocument();
  });

  it("sends the URL scope to the API", async () => {
    const api = stubApi(routes());
    renderGraph("?agent=agt_payments");
    await screen.findByText("Session sess-7f3a (payments-coder)");
    expect(api.gets("/provenance/graph")[0].query.get("agent_id")).toBe("agt_payments");
  });
});
