import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { budgetLevel, defaultOptions, effectiveOptions, formatTokens, mayModify, optionsEqual, safeFilename, suggestedProfile } from "../meta";
import { buildRequest, initialFixState, useFixContextState } from "../useFixContextState";
import type { ModeInfo } from "../types";
import { CATALOGUE, OPTIONS, PACK, SAVED, TASK, TEMPLATES } from "./fixtures";

const modes = new Map<string, ModeInfo>(CATALOGUE.modes.map((m) => [m.key, m]));
const readOnly = modes.get("investigate_only");
const writable = modes.get("implement_fix");

describe("option rules", () => {
  it("read-only modes can never request code or architecture changes", () => {
    const asked = { ...OPTIONS, allow_code_changes: true, allow_architecture_changes: true };
    const out = effectiveOptions(asked, readOnly);
    expect(out.allow_code_changes).toBe(false);
    expect(out.allow_architecture_changes).toBe(false);
    expect(mayModify(readOnly, asked)).toBe(false);
  });

  it("architecture changes need code changes, even in a writable mode", () => {
    const out = effectiveOptions({ ...OPTIONS, allow_code_changes: false, allow_architecture_changes: true }, writable);
    expect(out.allow_architecture_changes).toBe(false);
    expect(mayModify(writable, out)).toBe(false);
    expect(mayModify(writable, OPTIONS)).toBe(true);
  });

  it("takes defaults from the catalogue and compares options by value", () => {
    const defaults = defaultOptions(CATALOGUE);
    expect(defaults.testing_requirements).toBe("unit");
    expect(defaults.constraints).toEqual([]);
    expect(optionsEqual({ ...OPTIONS, constraints: [" a "], extra_instructions: "x " }, { ...OPTIONS, constraints: ["a"], extra_instructions: "x" })).toBe(true);
    expect(optionsEqual(OPTIONS, { ...OPTIONS, technical_depth: "deep" })).toBe(false);
  });
});

describe("profile suggestion (mirrors the server's default_profile)", () => {
  it("prefers security-critical for security work and deep for autonomous remediation", () => {
    expect(suggestedProfile({ task_type: "backend", related_finding_id: null }, "implement_fix")).toBe("standard");
    expect(suggestedProfile({ task_type: "prompt_injection", related_finding_id: null }, "implement_fix")).toBe("security_critical");
    expect(suggestedProfile({ task_type: "backend", related_finding_id: "fnd_1" }, "refactor")).toBe("security_critical");
    expect(suggestedProfile({ task_type: "backend", related_finding_id: null }, "security_harden")).toBe("security_critical");
    expect(suggestedProfile({ task_type: "backend", related_finding_id: null }, "full_autonomous_remediation")).toBe("deep");
  });
});

describe("number and file helpers", () => {
  it("formats token estimates without false precision", () => {
    expect(formatTokens(null)).toBe("—");
    expect(formatTokens(950)).toBe("~950 tokens");
    expect(formatTokens(1200, false)).toBe("~1.2k");
    expect(formatTokens(2000, false)).toBe("~2k");
    expect(formatTokens(24_400, false)).toBe("~24k");
  });

  it("classifies budget use", () => {
    expect(budgetLevel(100, 8000)).toBe("ok");
    expect(budgetLevel(7000, 8000)).toBe("near");
    expect(budgetLevel(9000, 8000)).toBe("over");
    expect(budgetLevel(0, 0)).toBe("ok");
  });

  it("builds safe download names", () => {
    expect(safeFilename("CTX-12/../x y", "md")).toBe("CTX-12_.._x_y.md");
    expect(safeFilename("///", "json")).toBe("export.json");
  });
});

describe("initial state and requests", () => {
  it("starts a saved prompt with its settings and stored pack, and builds a pack request", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, prompt: SAVED, pack: PACK, templates: TEMPLATES });
    expect(init.config.mode).toBe("implement_fix");
    expect(init.pack).toEqual({ id: "cpk_1", profile: "standard" });
    expect(init.preview?.promptId).toBe("gpr_1");
    expect(init.preview?.request).toMatchObject({ task_id: "tsk_1", context_pack_id: "cpk_1" });
    expect(init.preview?.request.profile).toBeUndefined();
  });

  it("applies a template from the link and sends a profile when no pack is stored", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, template: TEMPLATES[1], templates: TEMPLATES });
    expect(init.config).toMatchObject({ mode: "security_harden", preset: "claude_code", templateId: "pt_1", profile: "security_critical" });
    const req = buildRequest(TASK.id, init.config, init.pack, modes.get(init.config.mode));
    expect(req).toMatchObject({ template_id: "pt_1", profile: "security_critical" });
    expect(req.context_pack_id).toBeUndefined();
  });

  it("ignores a pack from another task", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, pack: { ...PACK, task_id: "tsk_other" }, templates: [] });
    expect(init.pack).toBeNull();
  });

  it("never forwards a template id that no longer exists", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, prompt: { ...SAVED, template_id: "pt_deleted" }, templates: TEMPLATES });
    expect(init.config.templateId).toBeNull();
  });
});

describe("useFixContextState", () => {
  it("marks a saved preview stale when settings change and offers to apply option-only changes", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, prompt: SAVED, pack: PACK, templates: TEMPLATES });
    const { result } = renderHook(() => useFixContextState(init, TASK, modes));
    expect(result.current.stale).toBe(false);

    act(() => result.current.setOptions({ technical_depth: "deep" }));
    expect(result.current.stale).toBe(true);
    expect(result.current.optionsOnlyChange).toBe(true);

    act(() => result.current.setOptions({ technical_depth: "standard" }));
    expect(result.current.stale).toBe(false);

    act(() => result.current.setMode("investigate_only"));
    expect(result.current.stale).toBe(true);
    expect(result.current.optionsOnlyChange).toBe(false);
    expect(result.current.request.options?.allow_code_changes).toBe(false);
  });

  it("detaches the stored pack when the profile changes and follows the suggestion until a profile is chosen", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, templates: [] });
    const { result } = renderHook(() => useFixContextState(init, TASK, modes));
    expect(result.current.config.profile).toBe("standard");
    act(() => result.current.setMode("full_autonomous_remediation"));
    expect(result.current.config.profile).toBe("deep");

    act(() => result.current.selectPack({ id: "cpk_9", profile: "deep" }));
    expect(result.current.request.context_pack_id).toBe("cpk_9");
    act(() => result.current.setProfile("minimal"));
    expect(result.current.pack).toBeNull();
    expect(result.current.request).toMatchObject({ profile: "minimal" });

    act(() => result.current.setMode("implement_fix"));
    expect(result.current.config.profile).toBe("minimal");
  });

  it("keeps a just-saved draft current when the server stored the pack it used", () => {
    const init = initialFixState({ catalogue: CATALOGUE, task: TASK, templates: [] });
    const { result } = renderHook(() => useFixContextState(init, TASK, modes));
    const used = result.current.request;
    act(() => result.current.showDraft({ ...SAVED, prompt_id: null } as never, used));
    expect(result.current.stale).toBe(false);
    act(() => {
      result.current.selectPack({ id: "cpk_new", profile: "standard" }, { silent: true });
      result.current.showSaved("gpr_new", { id: "cpk_new", profile: "standard" });
    });
    expect(result.current.preview?.promptId).toBe("gpr_new");
    expect(result.current.stale).toBe(false);

    act(() => result.current.packChanged());
    expect(result.current.stale).toBe(true);
  });
});
