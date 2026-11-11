import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReactNode } from "react";
import { act, renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { COALESCE_MS, createInvalidationBatcher, INVALIDATIONS, MARK_STALE, onLiveMessage, useLiveEvents } from "@/hooks/useLiveEvents";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(
    public url: string,
    public init?: EventSourceInit,
  ) {
    FakeEventSource.instances.push(this);
  }
  close() {
    this.closed = true;
  }
  emit(data: unknown) {
    this.onmessage?.({ data: typeof data === "string" ? data : JSON.stringify(data) });
  }
}

function setup() {
  const client = new QueryClient();
  const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue(undefined);
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const hook = renderHook(() => useLiveEvents(true), { wrapper });
  const source = FakeEventSource.instances.at(-1)!;
  return { client, invalidate, hook, source };
}

const keysOf = (spy: { mock: { calls: unknown[][] } }) => spy.mock.calls.map((c) => JSON.stringify((c[0] as { queryKey?: unknown } | undefined)?.queryKey));

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useLiveEvents", () => {
  it("connects with credentials and reports live once open", () => {
    const { hook, source } = setup();
    expect(source.url).toBe("/api/v1/stream");
    expect(source.init).toEqual({ withCredentials: true });
    expect(hook.result.current).toBe("connecting");
    act(() => source.onopen?.());
    expect(hook.result.current).toBe("live");
  });

  it("coalesces one ingest batch into a single invalidation per key", () => {
    const { invalidate, source } = setup();
    act(() => {
      source.emit({ type: "event.ingested", id: "evt_1", session_id: "ses_1" });
      source.emit({ type: "session.updated", id: "ses_1" });
      source.emit({ type: "agent.updated", id: "agt_1" });
    });
    expect(invalidate).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(COALESCE_MS));
    const keys = keysOf(invalidate);
    expect(keys.filter((k) => k === '["overview"]')).toHaveLength(1);
    expect(keys.filter((k) => k === '["sessions"]')).toHaveLength(1);
    expect(keys).toContain('["integrations"]');
    // ["provenance"] (from event.ingested) covers session.updated's ["provenance","scopes"].
    expect(keys).not.toContain('["provenance","scopes"]');
    const integrations = invalidate.mock.calls.find((c) => JSON.stringify((c[0] as { queryKey: unknown }).queryKey) === '["integrations"]');
    expect(integrations?.[0]).toMatchObject({ refetchType: "none" });
  });

  it("refreshes the overview on session.updated and the integrations on event.ingested", () => {
    expect(INVALIDATIONS["session.updated"]).toContainEqual(["overview"]);
    expect(MARK_STALE["event.ingested"]).toContainEqual(["integrations"]);
    expect(INVALIDATIONS["simulation.completed"]).toContainEqual(["simulations"]);
  });

  it("refreshes the remediation pipeline and engineering analytics when findings or incidents change", () => {
    // The workspace analytics hooks rely on this map; they no longer subscribe on their own.
    for (const type of ["finding.created", "finding.updated", "incident.updated"]) {
      expect(INVALIDATIONS[type]).toContainEqual(["workspace", "remediation"]);
      expect(INVALIDATIONS[type]).toContainEqual(["workspace", "analytics"]);
    }
  });

  it("forwards messages to subscribers immediately and ignores keep-alives and malformed frames", () => {
    const { invalidate, source } = setup();
    const seen: string[] = [];
    const off = onLiveMessage((m) => seen.push(m.type));
    act(() => {
      source.emit("");
      source.emit("not json");
      source.emit({ id: "x" });
      source.emit({ type: "policy.updated", id: "pol_1" });
    });
    off();
    expect(seen).toEqual(["policy.updated"]);
    act(() => vi.advanceTimersByTime(COALESCE_MS));
    expect(keysOf(invalidate)).toContain('["policies"]');
  });

  it("reconnects with backoff and refreshes everything after a reconnect", () => {
    const { invalidate, hook, source } = setup();
    act(() => source.onopen?.());
    act(() => source.onerror?.());
    expect(hook.result.current).toBe("offline");
    expect(source.closed).toBe(true);
    act(() => vi.advanceTimersByTime(2000));
    const next = FakeEventSource.instances.at(-1)!;
    expect(next).not.toBe(source);
    act(() => next.onopen?.());
    expect(hook.result.current).toBe("live");
    expect(invalidate).toHaveBeenCalledWith();
  });

  it("closes the stream and drops pending invalidations on unmount", () => {
    const { invalidate, hook, source } = setup();
    act(() => source.emit({ type: "finding.created", id: "fnd_1" }));
    hook.unmount();
    act(() => vi.advanceTimersByTime(COALESCE_MS * 2));
    expect(source.closed).toBe(true);
    expect(invalidate).not.toHaveBeenCalled();
  });
});

describe("createInvalidationBatcher", () => {
  it("does not mark a key stale-only when the same flush refetches it", () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue(undefined);
    const batcher = createInvalidationBatcher(client);
    batcher.add("event.ingested");
    batcher.add("unknown.type");
    batcher.flush();
    expect(invalidate.mock.calls.every((c) => (c[0] as { queryKey: unknown[] }).queryKey.length > 0)).toBe(true);
    expect(keysOf(invalidate).filter((k) => k === '["context"]')).toHaveLength(1);
  });
});

const BACKEND = join(ROOT, "backend/app");
const FEATURES = join(ROOT, "frontend/src/features");

function files(dir: string, ext: RegExp): string[] {
  return (readdirSync(dir, { recursive: true }) as string[])
    .filter((f) => ext.test(f) && !f.includes("__tests__") && !f.includes("__pycache__"))
    .map((f) => join(dir, f));
}

describe.skipIf(!existsSync(BACKEND) || !existsSync(FEATURES))("live notification map stays in sync", () => {
  it("handles every notification type the backend emits", () => {
    const emitted = new Set<string>();
    for (const file of files(BACKEND, /\.py$/)) {
      for (const m of readFileSync(file, "utf8").matchAll(/\bnotify\(\s*[\w.]+\s*,\s*[\w.]+\s*,\s*"([a-z_]+\.[a-z_]+)"/g)) emitted.add(m[1]);
    }
    expect(emitted.size).toBeGreaterThan(5);
    const unmapped = [...emitted].filter((t) => !INVALIDATIONS[t]);
    expect(unmapped).toEqual([]);
  });

  it("only invalidates key roots that some feature actually queries", () => {
    const roots = new Set<string>();
    for (const file of files(FEATURES, /\.tsx?$/)) {
      for (const m of readFileSync(file, "utf8").matchAll(/\[\s*"([a-z][a-z-]*)"(?=\s*[,\]])/g)) roots.add(m[1]);
    }
    const used = [...Object.values(INVALIDATIONS), ...Object.values(MARK_STALE)].flat().map((key) => String(key[0]));
    const unknown = [...new Set(used)].filter((root) => !roots.has(root));
    expect(unknown).toEqual([]);
  });
});
