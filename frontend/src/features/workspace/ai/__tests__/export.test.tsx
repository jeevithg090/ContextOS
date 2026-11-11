import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { packExportFilename, useExportContextPack } from "../hooks";
import { PACK } from "./fixtures";

vi.mock("@/features/auth/AuthProvider", () => ({
  useAuth: () => ({ me: null, loading: false, can: () => true, refresh: async () => undefined, logout: async () => undefined }),
}));

const EXPORT = {
  context_pack: { ...PACK, items: [] },
  task: { id: "tsk_1", key: "CTX-12", title: "Redact bearer tokens in webhook logs" },
  exported_at: "2026-11-11T10:00:00Z",
  generated_by: "ContextOS context-pack builder (deterministic; no external AI provider involved)",
  external_transfer: false,
};

const urls: string[] = [];
const downloads: Array<{ name: string; blob: Blob }> = [];

beforeEach(() => {
  urls.length = 0;
  downloads.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify(EXPORT), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  let blob: Blob | null = null;
  vi.stubGlobal("URL", Object.assign(Object.create(URL), { createObjectURL: (b: Blob) => ((blob = b), "blob:test"), revokeObjectURL: () => undefined }));
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    downloads.push({ name: this.download, blob: blob! });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const readBlob = (blob: Blob) =>
  new Promise<string>((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.readAsText(blob);
  });

const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>;

describe("context pack export", () => {
  it("downloads through the audited export endpoint, not the plain pack read", async () => {
    const { result } = renderHook(() => useExportContextPack(), { wrapper });
    act(() => result.current.mutate("cpk_1"));
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(urls).toEqual(["/api/v1/workspace/ai/context-packs/cpk_1/export"]);
    expect(downloads).toHaveLength(1);
    expect(downloads[0].name).toBe(`context-pack-CTX-12-${PACK.profile}.json`);
    const body = JSON.parse(await readBlob(downloads[0].blob));
    expect(body.generated_by).toMatch(/no external AI provider/);
    expect(body.task.key).toBe("CTX-12");
  });

  it("names exports of packs whose task was deleted after the pack id", () => {
    expect(packExportFilename({ context_pack: { id: "cpk_9", profile: "deep" }, task: null })).toBe("context-pack-cpk_9-deep.json");
  });
});
