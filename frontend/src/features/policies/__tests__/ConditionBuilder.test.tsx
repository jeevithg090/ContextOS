import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { TooltipProvider } from "@/components/ui";
import { ConditionBuilder } from "../ConditionBuilder";
import type { FieldSpec, OperatorSpec } from "../types";

const CATALOG: FieldSpec[] = [
  { path: "tool.category", type: "enum", description: "Server-side classification of what the tool does.", example: "http", values: ["shell", "http", "email"], ordered: false, ops: ["eq", "neq", "in", "not_in", "glob", "exists"] },
  { path: "session.trifecta", type: "boolean", description: "Lethal trifecta observed.", example: true, ops: ["is_true", "is_false", "eq", "neq", "exists"] },
];
const OPERATORS: OperatorSpec[] = [
  { op: "eq", label: "equals", value: "scalar" },
  { op: "neq", label: "does not equal", value: "scalar" },
  { op: "in", label: "is one of", value: "list" },
  { op: "not_in", label: "is not one of", value: "list" },
  { op: "glob", label: "matches glob", value: "glob" },
  { op: "exists", label: "is present", value: "none" },
  { op: "is_true", label: "is true", value: "none" },
  { op: "is_false", label: "is false", value: "none" },
];

function Harness({ initial, onValue }: { initial: unknown; onValue: (v: unknown) => void }) {
  const [value, setValue] = useState<unknown>(initial);
  return (
    <TooltipProvider>
      <ConditionBuilder
        conditions={value}
        catalog={CATALOG}
        operators={OPERATORS}
        onChange={(v) => {
          setValue(v);
          onValue(v);
        }}
      />
    </TooltipProvider>
  );
}

describe("ConditionBuilder", () => {
  it("builds a leaf from the field picker with type-appropriate operators and values", () => {
    const onValue = vi.fn();
    render(<Harness initial={{}} onValue={onValue} />);
    fireEvent.change(screen.getByLabelText("Field"), { target: { value: "tool.category" } });
    expect(onValue).toHaveBeenLastCalledWith({ field: "tool.category", op: "eq", value: "shell" });
    expect(screen.getByText("Server-side classification of what the tool does.")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Operator"), { target: { value: "in" } });
    expect(onValue).toHaveBeenLastCalledWith({ field: "tool.category", op: "in", value: ["shell"] });
    fireEvent.click(within(screen.getByRole("group", { name: "Values" })).getByRole("checkbox", { name: "http" }));
    expect(onValue).toHaveBeenLastCalledWith({ field: "tool.category", op: "in", value: ["shell", "http"] });
  });

  it("adds conditions, switches to ANY and negates", () => {
    const onValue = vi.fn();
    render(<Harness initial={{ field: "session.trifecta", op: "is_true" }} onValue={onValue} />);
    fireEvent.click(screen.getByRole("button", { name: "Condition" }));
    const fields = screen.getAllByLabelText("Field");
    fireEvent.change(fields[1], { target: { value: "tool.category" } });
    fireEvent.click(screen.getByRole("radio", { name: "any" }));
    expect(onValue).toHaveBeenLastCalledWith({
      any: [
        { field: "session.trifecta", op: "is_true" },
        { field: "tool.category", op: "eq", value: "shell" },
      ],
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Negate this condition" })[0]);
    expect(onValue).toHaveBeenLastCalledWith({
      any: [{ not: { field: "session.trifecta", op: "is_true" } }, { field: "tool.category", op: "eq", value: "shell" }],
    });
  });

  it("explains JSON it cannot show instead of rewriting it", () => {
    render(<Harness initial={{ all: [] }} onValue={vi.fn()} />);
    expect(screen.getByText(/can’t be shown in the visual builder/)).toBeInTheDocument();
  });
});
