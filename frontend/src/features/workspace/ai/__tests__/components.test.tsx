import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { useState, type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { ChipsInput, PRIVACY_HEADLINE, PrivacyNote, TokenBudgetMeter } from "../controls";
import { ModeCards } from "../ModeCards";
import { OptionsFields } from "../OptionsFields";
import { PackItemsTable } from "../PackItemsTable";
import { PromptPreview, viewFromDraft, viewFromSaved } from "../PromptPreview";
import { SectionCard } from "../SectionCard";
import type { GenerationOptions } from "../types";
import { CATALOGUE, DRAFT, OPTIONS, PACK, SAVED, SECTIONS } from "./fixtures";

const calls: Array<{ url: string; method: string; body?: unknown }> = [];
let respond: (url: string, method: string) => { status?: number; body?: unknown };

beforeEach(() => {
  calls.length = 0;
  respond = () => ({ body: {} });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const { status = 200, body } = respond(url, method);
      return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TooltipProvider>
          <ToastProvider>{ui}</ToastProvider>
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("PrivacyNote", () => {
  it("always states that nothing goes to an external AI provider", () => {
    render(<PrivacyNote detail="Generated on the server." />);
    expect(screen.getByRole("note", { name: "Privacy" })).toHaveTextContent(PRIVACY_HEADLINE);
  });
});

describe("ModeCards", () => {
  it("shows all eight modes as radios with their file access and supports arrow keys", () => {
    const onChange = vi.fn();
    render(<ModeCards modes={CATALOGUE.modes} value="implement_fix" onChange={onChange} />);
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(8);
    const investigate = screen.getByRole("radio", { name: /Investigate only/ });
    expect(investigate).toHaveTextContent("Read-only");
    const implement = screen.getByRole("radio", { name: /Implement fix/ });
    expect(implement).toHaveAttribute("aria-checked", "true");
    expect(implement).toHaveTextContent("May modify files");
    fireEvent.keyDown(implement, { key: "ArrowRight" });
    expect(onChange).toHaveBeenLastCalledWith("security_harden");
    fireEvent.click(investigate);
    expect(onChange).toHaveBeenLastCalledWith("investigate_only");
  });
});

describe("ChipsInput", () => {
  function Harness() {
    const [values, setValues] = useState<string[]>(["Keep the public API"]);
    return <ChipsInput label="Constraints" values={values} onChange={setValues} maxLength={20} />;
  }

  it("adds on Enter, refuses duplicates and over-long entries, removes chips", () => {
    render(<Harness />);
    const input = screen.getByLabelText("Constraints");
    fireEvent.change(input, { target: { value: "No new deps" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByText("No new deps")).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "no new deps" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByText("That entry is already in the list.")).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "x".repeat(21) } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByText("Each entry can be at most 20 characters.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove “Keep the public API”" }));
    expect(screen.queryByText("Keep the public API")).not.toBeInTheDocument();
  });
});

describe("OptionsFields", () => {
  function Harness({ modeKey }: { modeKey: string }) {
    const [options, setOptions] = useState<GenerationOptions>(OPTIONS);
    return <OptionsFields catalogue={CATALOGUE} mode={CATALOGUE.modes.find((m) => m.key === modeKey)} options={options} onChange={(p) => setOptions((o) => ({ ...o, ...p }))} />;
  }

  it("forces code changes off in a read-only mode and explains why", () => {
    render(<Harness modeKey="investigate_only" />);
    const code = screen.getByRole("switch", { name: "Allow code changes" });
    expect(code).toBeDisabled();
    expect(code).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText(/Investigate only is read-only, so code changes are always off/)).toBeInTheDocument();
    expect(screen.getByLabelText("Autonomy")).toBeDisabled();
  });

  it("lets writable modes turn changes on and off, with architecture depending on code changes", () => {
    render(<Harness modeKey="implement_fix" />);
    const code = screen.getByRole("switch", { name: "Allow code changes" });
    const arch = screen.getByRole("switch", { name: "Allow architecture changes" });
    expect(code).toHaveAttribute("aria-checked", "true");
    expect(arch).not.toBeDisabled();
    fireEvent.click(code);
    expect(code).toHaveAttribute("aria-checked", "false");
    expect(arch).toBeDisabled();
    expect(screen.getByLabelText("Autonomy")).toBeDisabled();
  });
});

describe("TokenBudgetMeter", () => {
  it("says when a pack is over budget", () => {
    render(<TokenBudgetMeter estimate={9000} budget={8000} />);
    const meter = screen.getByRole("meter", { name: "Context pack budget" });
    expect(meter).toHaveAttribute("aria-valuetext", expect.stringContaining("over budget"));
    expect(screen.getByText(/over budget/)).toBeInTheDocument();
  });
});

describe("PackItemsTable", () => {
  it("lists sensitive files separately, never includable, and toggles other items through the API", async () => {
    respond = (_url, method) => (method === "PATCH" ? { body: { ...PACK, items: PACK.items.map((i) => (i.key.startsWith("doc:") ? { ...i, included: true, status: "included" } : i)) } } : { body: PACK });
    wrap(<PackItemsTable pack={PACK} canEdit />);
    const safety = screen.getByText(/Excluded for safety \(1\)/).closest("div")!.parentElement!;
    expect(within(safety).getByText(".env")).toBeInTheDocument();
    expect(within(safety).getByText(/Sensitive files are never read/)).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /\.env/ })).not.toBeInTheDocument();

    const doc = screen.getByRole("checkbox", { name: "Include Data model" });
    expect(doc).not.toBeChecked();
    fireEvent.click(doc);
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.url).toBe("/api/v1/workspace/ai/context-packs/cpk_1");
    expect(patch.body).toEqual({ items: [{ key: "doc:docs/DATA_MODEL.md", included: true }] });
  });

  it("is read-only without write access and filters by category", () => {
    wrap(<PackItemsTable pack={PACK} canEdit={false} />);
    expect(screen.getByRole("checkbox", { name: "Exclude webhooks.py" })).toBeDisabled();
    fireEvent.click(screen.getByRole("radio", { name: /Not included/ }));
    expect(screen.queryByText("webhooks.py")).not.toBeInTheDocument();
    expect(screen.getByText("Data model")).toBeInTheDocument();
  });
});

describe("SectionCard", () => {
  it("shows the kind of each section and blocks edits until the prompt is saved", () => {
    wrap(<SectionCard section={SECTIONS[1]} promptId={null} canWrite />);
    expect(screen.getByText("Hypothesis")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Edit/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Regenerate/ })).toBeDisabled();
  });

  it("saves an edited section of a saved prompt as a new version", async () => {
    respond = () => ({ body: { ...SAVED, version: 2, notes: [] } });
    wrap(<SectionCard section={SECTIONS[1]} promptId="gpr_1" canWrite />);
    fireEvent.click(screen.getByRole("button", { name: /Edit/ }));
    fireEvent.change(screen.getByLabelText(/Edit Root-cause hypotheses/), { target: { value: "1. Headers are logged raw." } });
    fireEvent.click(screen.getByRole("button", { name: "Save section" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({ method: "PATCH", url: "/api/v1/workspace/ai/prompts/gpr_1", body: { sections: [{ key: "root_cause_hypotheses", content: "1. Headers are logged raw." }] } });
  });

  it("cannot remove a section the mode requires", () => {
    wrap(<SectionCard section={SECTIONS[0]} promptId="gpr_1" canWrite />);
    expect(screen.getByRole("button", { name: /Remove/ })).toBeDisabled();
    expect(screen.getByText("Required")).toBeInTheDocument();
  });
});

describe("PromptPreview", () => {
  const base = {
    taskId: "tsk_1",
    catalogueSections: CATALOGUE.sections,
    stale: false,
    optionsOnlyChange: false,
    onGenerateAgain: vi.fn(),
    generating: false,
    onApplyOptions: vi.fn(),
    applying: false,
    onSave: vi.fn(),
    saving: false,
    onStartFix: vi.fn(),
    fixAttempt: null,
  };

  it("offers saving for a draft and cannot export a pack that was never stored", () => {
    const onSave = vi.fn();
    wrap(<PromptPreview {...base} onSave={onSave} view={viewFromDraft(DRAFT)} canWrite />);
    expect(screen.getByText("Unsaved preview")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Export context pack JSON/ })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /Save to task/ }));
    expect(onSave).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /Save & start fix attempt/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Root-cause hypotheses" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Available evidence/ })).toBeDisabled();
  });

  it("shows the saved version, the stale warning and the final prompt", () => {
    const onApply = vi.fn();
    wrap(<PromptPreview {...base} stale optionsOnlyChange onApplyOptions={onApply} view={viewFromSaved(SAVED)} canWrite />);
    expect(screen.getByText("Saved to task · v1")).toBeInTheDocument();
    expect(screen.getByText(/changed since this prompt was generated/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Apply options to saved prompt" }));
    expect(onApply).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("radio", { name: "Final prompt" }));
    expect(screen.getByText(/# CTX-12: Redact bearer tokens/)).toBeInTheDocument();
  });

  it("hides write actions for read-only users", () => {
    wrap(<PromptPreview {...base} view={viewFromDraft(DRAFT)} canWrite={false} />);
    expect(screen.queryByRole("button", { name: /Save to task/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /fix attempt/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy prompt/ })).toBeInTheDocument();
  });
});
