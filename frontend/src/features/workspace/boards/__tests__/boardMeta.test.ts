import { CARD_FIELDS } from "../../types";
import { cardFields, columnAccent, EMPTY_FILTERS, hasActiveFilters, matchesFilters, templateLabel, verificationGates } from "../boardMeta";
import { makeCard, makeColumn } from "./fixtures";

const ada = { user_id: "usr_ada", name: "Ada", email: "ada@example.com", role: "assignee" as const };
const rev = { user_id: "usr_rev", name: "Rev", email: "rev@example.com", role: "reviewer" as const };

describe("board filters", () => {
  const card = makeCard({ key: "CTX-12", title: "Block exfiltration to paste sites", assignees: [ada, rev], labels: [{ id: "lbl_1", name: "egress", color: "high" }] });

  it("matches on title or key, case-insensitively", () => {
    expect(matchesFilters(card, { ...EMPTY_FILTERS, q: "PASTE" }, null)).toBe(true);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, q: "ctx-12" }, null)).toBe(true);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, q: "unrelated" }, null)).toBe(false);
  });

  it("resolves the 'me' assignee and ignores reviewers", () => {
    expect(matchesFilters(card, { ...EMPTY_FILTERS, assignee: "me" }, "usr_ada")).toBe(true);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, assignee: "me" }, "usr_rev")).toBe(false);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, assignee: "me" }, null)).toBe(false);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, assignee: "none" }, null)).toBe(false);
    expect(matchesFilters(makeCard({ assignees: [rev] }), { ...EMPTY_FILTERS, assignee: "none" }, null)).toBe(true);
  });

  it("filters by label, priority and type", () => {
    expect(matchesFilters(card, { ...EMPTY_FILTERS, label: "lbl_1" }, null)).toBe(true);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, label: "lbl_2" }, null)).toBe(false);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, priority: "high" }, null)).toBe(true);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, priority: "low" }, null)).toBe(false);
    expect(matchesFilters(card, { ...EMPTY_FILTERS, type: "backend" }, null)).toBe(false);
  });

  it("knows when any filter is active", () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, q: "  " })).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, type: "feature" })).toBe(true);
  });
});

describe("board presentation", () => {
  it("shows every card field until the board chooses its own (an empty choice shows only titles)", () => {
    expect([...cardFields({})]).toEqual([...CARD_FIELDS]);
    expect(cardFields({ card_fields: [] }).size).toBe(0);
    expect([...cardFields({ card_fields: ["key", "priority"] })]).toEqual(["key", "priority"]);
  });

  it("mirrors the server's verification gate, including done columns after a gate", () => {
    const gates = verificationGates([
      makeColumn({ id: "c1", name: "Backlog", position: 0 }),
      makeColumn({ id: "c0", name: "Early done", position: 1, is_done_column: true, status_key: "done" }),
      makeColumn({ id: "c2", name: "Verified", position: 2, requires_verification: true }),
      makeColumn({ id: "c3", name: "Done", position: 3, is_done_column: true, status_key: "done" }),
    ]);
    expect(gates).toEqual({ c1: null, c0: null, c2: "Verified", c3: "Verified" });
  });

  it("renders token and hex colours and names templates", () => {
    expect(columnAccent("blocked").dot).toContain("trust-blocked");
    expect(columnAccent("#3b82f6").style).toEqual({ background: "#3b82f6" });
    expect(columnAccent("not-a-colour").dot).toContain("bg-fg-faint");
    expect(templateLabel("incident_response")).toBe("Incident response");
    expect(templateLabel("custom")).toBe("Custom");
  });
});
