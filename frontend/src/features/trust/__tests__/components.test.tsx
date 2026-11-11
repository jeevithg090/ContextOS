import { fireEvent, render, screen } from "@testing-library/react";
import { CapabilityPicker, CheckList, LevelDistribution } from "../components";
import type { Capability } from "../types";

describe("CapabilityPicker", () => {
  it("disables capabilities a data-only level cannot grant and explains why", () => {
    render(<CapabilityPicker level="EXTERNAL" appliesTo="source" value={["read"]} onChange={() => {}} />);
    expect(screen.getByRole("checkbox", { name: /Read/ })).toBeEnabled();
    expect(screen.getByRole("checkbox", { name: /Instruct/ })).toBeDisabled();
    expect(screen.getAllByText("External content is data only.").length).toBeGreaterThan(0);
  });

  it("toggles a capability and says when the level's defaults will apply", () => {
    const changes: Capability[][] = [];
    const { rerender } = render(<CapabilityPicker level="APPROVED" appliesTo="source" value={["read"]} onChange={(c) => changes.push(c)} />);
    fireEvent.click(screen.getByRole("checkbox", { name: /Instruct/ }));
    expect(changes.at(-1)).toEqual(["read", "instruct"]);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    rerender(<CapabilityPicker level="APPROVED" appliesTo="source" value={[]} onChange={() => {}} />);
    expect(screen.getByRole("note")).toHaveTextContent("Nothing selected: the Approved defaults apply (Read).");
  });

  it("grants nothing at BLOCKED and does not claim defaults", () => {
    render(<CapabilityPicker level="BLOCKED" appliesTo="both" value={[]} onChange={() => {}} />);
    screen.getAllByRole("checkbox").forEach((box) => expect(box).toBeDisabled());
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});

describe("CheckList", () => {
  it("lists failures before warnings and passes", () => {
    render(
      <CheckList
        checks={[
          { check: "allowlist", result: "pass", detail: "On the allowlist." },
          { check: "lookalike", result: "fail", detail: "Looks like api.anthropic.com." },
          { check: "first_seen", result: "warn", detail: "First time this destination is seen." },
        ]}
      />,
    );
    const items = screen.getAllByRole("listitem").map((li) => li.textContent ?? "");
    expect(items[0]).toContain("Lookalike of an allowlisted domain");
    expect(items[1]).toContain("Seen before");
    expect(items[2]).toContain("Destination allowlist");
  });
});

describe("LevelDistribution", () => {
  it("offers a filter for every non-empty level only", () => {
    const picked: string[] = [];
    render(<LevelDistribution byLevel={{ TRUSTED: 2, SUSPICIOUS: 1 }} total={3} label="Sources" onSelect={(l) => picked.push(l)} />);
    fireEvent.click(screen.getByRole("button", { name: "Show 1 Suspicious sources" }));
    expect(picked).toEqual(["SUSPICIOUS"]);
    expect(screen.queryByRole("button", { name: /Blocked/ })).not.toBeInTheDocument();
    expect(screen.getByRole("img")).toHaveAccessibleName(/2 Trusted, 0 Approved/);
  });
});
