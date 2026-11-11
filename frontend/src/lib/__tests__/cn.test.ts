import { cn } from "@/lib/format";

describe("cn", () => {
  it("joins truthy parts and drops falsy ones", () => {
    expect(cn("a", false, null, undefined, 0, "b")).toBe("a b");
    expect(cn()).toBe("");
  });

  it("lets a later size, width, padding or text size override the built-in one", () => {
    expect(cn("w-full rounded px-2.5 text-[13px]", "h-8", "h-7 w-auto text-xs")).toBe("rounded px-2.5 h-7 w-auto text-xs");
    expect(cn("px-2.5 py-2", "px-1 py-0.5")).toBe("px-1 py-0.5");
    expect(cn("text-[13px]", "text-2xs")).toBe("text-2xs");
    expect(cn("min-w-0 max-w-md", "min-w-[96px]")).toBe("max-w-md min-w-[96px]");
  });

  it("applies shorthand-over-longhand precedence like Tailwind", () => {
    expect(cn("px-3 pt-1", "p-2")).toBe("p-2");
    expect(cn("p-2", "px-3")).toBe("p-2 px-3");
    expect(cn("pl-2 pr-7", "px-4")).toBe("px-4");
    expect(cn("w-4 h-4", "size-5")).toBe("size-5");
    expect(cn("-mx-2", "m-1")).toBe("m-1");
    expect(cn("overflow-x-auto", "overflow-hidden")).toBe("overflow-hidden");
  });

  it("keeps text colour, size and alignment independent", () => {
    expect(cn("text-xs text-fg-muted text-left", "text-fg")).toBe("text-xs text-left text-fg");
    expect(cn("text-fg", "text-sm")).toBe("text-fg text-sm");
    expect(cn("text-[#123456]", "text-[13px]")).toBe("text-[#123456] text-[13px]");
  });

  it("resolves background and border colours without touching other bg/border utilities", () => {
    expect(cn("bg-surface-2 bg-no-repeat bg-[length:12px]", "bg-surface")).toBe("bg-no-repeat bg-[length:12px] bg-surface");
    expect(cn("border border-border-strong", "border-accent/50")).toBe("border border-accent/50");
    expect(cn("border-b-2 border-transparent", "border-accent")).toBe("border-b-2 border-accent");
    expect(cn("border-t border-l-accent", "border-dashed")).toBe("border-t border-l-accent border-dashed");
  });

  it("scopes conflicts by variant and by the important modifier", () => {
    expect(cn("h-8 hover:h-9", "h-7")).toBe("hover:h-9 h-7");
    expect(cn("sm:px-6 px-4", "sm:px-2")).toBe("px-4 sm:px-2");
    expect(cn("data-[state=active]:text-fg text-fg-muted", "data-[state=active]:text-accent")).toBe("text-fg-muted data-[state=active]:text-accent");
    expect(cn("h-8", "!h-7")).toBe("h-8 !h-7");
    expect(cn("[&>svg]:h-4 h-6")).toBe("[&>svg]:h-4 h-6");
  });

  it("resolves display, position, font and alignment groups", () => {
    expect(cn("inline-flex items-center", "hidden")).toBe("items-center hidden");
    expect(cn("relative", "absolute")).toBe("absolute");
    expect(cn("font-semibold font-sans", "font-medium font-mono")).toBe("font-medium font-mono");
    expect(cn("justify-between items-start", "items-center")).toBe("justify-between items-center");
    expect(cn("z-40", "z-50")).toBe("z-50");
  });

  it("never drops classes it does not understand", () => {
    expect(cn("panel label-caps num animate-fade-in", "panel shadow-pop")).toBe("panel label-caps num animate-fade-in panel shadow-pop");
    expect(cn("flex-1 shrink-0 truncate", "grow")).toBe("flex-1 shrink-0 truncate grow");
  });
});
