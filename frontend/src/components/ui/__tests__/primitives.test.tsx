import { render, screen } from "@testing-library/react";
import { FilterSelect } from "@/components/data";
import { Dialog, Field, Input, Select } from "@/components/ui";

const classes = (el: HTMLElement) => el.className.split(/\s+/);

describe("form control overrides", () => {
  it("lets className replace the built-in height, width and text size", () => {
    render(<Input aria-label="Branch" className="h-7 w-24 text-xs" />);
    const input = classes(screen.getByLabelText("Branch"));
    expect(input).toEqual(expect.arrayContaining(["h-7", "w-24", "text-xs"]));
    expect(input).not.toEqual(expect.arrayContaining(["h-8"]));
    expect(input).not.toContain("w-full");
    expect(input).not.toContain("text-[13px]");
  });

  it("keeps the select's chevron padding when a caller overrides horizontal padding", () => {
    render(
      <Select aria-label="Type" className="h-7 px-2">
        <option>a</option>
      </Select>,
    );
    const select = classes(screen.getByLabelText("Type"));
    expect(select).toContain("h-7");
    expect(select).toContain("px-2");
    expect(select.at(-1)).toBe("pr-7");
  });

  it("FilterSelect is compact without !important overrides and highlights an active filter", () => {
    render(<FilterSelect label="Severity" value="high" onChange={() => undefined} options={[{ value: "high", label: "High" }]} />);
    const select = classes(screen.getByLabelText("Severity"));
    expect(select).toEqual(expect.arrayContaining(["h-7", "w-auto", "text-xs", "border-accent/50"]));
    expect(select.some((c) => c.startsWith("!"))).toBe(false);
    expect(select).not.toContain("border-border-strong");
    expect(select).not.toContain("h-8");
  });
});

describe("Dialog", () => {
  it("animates with a keyframe that keeps the centring translate", () => {
    render(
      <Dialog open onOpenChange={() => undefined} title="Create task">
        body
      </Dialog>,
    );
    const dialog = classes(screen.getByRole("dialog"));
    expect(dialog).toContain("-translate-x-1/2");
    expect(dialog).toContain("animate-dialog-in");
    expect(dialog).not.toContain("animate-slide-up");
  });

  it("lets className widen the dialog", () => {
    render(
      <Dialog open onOpenChange={() => undefined} title="Wide" className="w-[min(860px,calc(100vw-32px))]">
        body
      </Dialog>,
    );
    const dialog = classes(screen.getByRole("dialog"));
    expect(dialog).toContain("w-[min(860px,calc(100vw-32px))]");
    expect(dialog).not.toContain("w-[min(560px,calc(100vw-32px))]");
  });
});

describe("Field", () => {
  it("describes the control with its hint", () => {
    render(
      <Field label="Password" htmlFor="pw" hint="At least 10 characters.">
        <Input id="pw" />
      </Field>,
    );
    const input = screen.getByLabelText("Password");
    expect(input).toHaveAccessibleDescription("At least 10 characters.");
    expect(input).not.toHaveAttribute("aria-invalid");
  });

  it("marks the control invalid and announces the error instead of the hint", () => {
    render(
      <Field label="Email" htmlFor="em" hint="Your login." error="Enter your email address.">
        <Input id="em" />
      </Field>,
    );
    const input = screen.getByLabelText("Email");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("Enter your email address.");
    expect(screen.queryByText("Your login.")).not.toBeInTheDocument();
  });
});
