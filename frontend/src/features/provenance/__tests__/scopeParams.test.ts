import { queryFromParams, withScope } from "../scopeParams";

const q = (search: string) => queryFromParams(new URLSearchParams(search));

describe("queryFromParams", () => {
  it("maps the short parameters other pages link with", () => {
    expect(q("session=asn_1")).toEqual({ session_id: "asn_1" });
    expect(q("agent=agt_1")).toEqual({ agent_id: "agt_1" });
    expect(q("item=ctx_1&depth=3")).toEqual({ context_item_id: "ctx_1", depth: 3 });
    expect(q("finding=fnd_1&depth=1&limit=1000")).toEqual({ finding_id: "fnd_1", depth: 1, limit: 1000 });
  });

  it("accepts the API field names as aliases", () => {
    expect(q("session_id=asn_1")).toEqual({ session_id: "asn_1" });
    expect(q("context_item_id=ctx_1")).toEqual({ context_item_id: "ctx_1" });
    expect(q("finding_id=fnd_1")).toEqual({ finding_id: "fnd_1" });
  });

  it("sends exactly one scope, so the API never rejects a link with several", () => {
    expect(q("finding=fnd_1&session=asn_1")).toEqual({ session_id: "asn_1" });
  });

  it("drops depth outside item/finding scopes and values the API would reject", () => {
    expect(q("session=asn_1&depth=3")).toEqual({ session_id: "asn_1" });
    expect(q("item=ctx_1&depth=9")).toEqual({ context_item_id: "ctx_1" });
    expect(q("item=ctx_1&depth=1.5")).toEqual({ context_item_id: "ctx_1" });
    expect(q("limit=5")).toEqual({});
    expect(q("session=%20%20")).toEqual({});
    expect(q("")).toEqual({});
  });
});

describe("withScope", () => {
  it("replaces the scope (aliases included), resets depth and keeps the node budget", () => {
    const next = withScope(new URLSearchParams("session_id=asn_1&depth=3&limit=1000"), "finding", "fnd_9");
    expect(next.toString()).toBe("limit=1000&finding=fnd_9");
  });

  it("clears the scope so the page falls back to the most recent high-risk session", () => {
    const next = withScope(new URLSearchParams("item=ctx_1&depth=2"), null, null);
    expect(next.toString()).toBe("");
    expect(queryFromParams(next)).toEqual({});
  });
});
