/**
 * Live updates over Server-Sent Events (GET /api/v1/stream, cookie-authenticated).
 * Messages are small notifications: {type: "<entity>.<verb>", id?, ...ids}. On each message we
 * invalidate the TanStack Query keys whose data the change can affect — details are always
 * refetched through the API, so no sensitive payloads travel over the stream.
 *
 * The notification types are the `notify(db, org_id, "<type>", ...)` calls in backend/app/services;
 * the keys are the roots used by `src/features/<feature>/api.ts`. Messages arriving within
 * COALESCE_MS are merged, so one ingest batch (event.ingested + session.updated + agent.updated)
 * triggers a single refetch per key instead of three.
 */
import { useEffect, useState } from "react";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";

export type LiveStatus = "connecting" | "live" | "offline";
export interface LiveMessage {
  type: string;
  [k: string]: unknown;
}

const WORK_PIPELINE: QueryKey[] = [["workspace", "remediation"], ["workspace", "analytics"]];

/** Notification type → query keys to invalidate (active queries refetch, inactive ones go stale). */
export const INVALIDATIONS: Record<string, QueryKey[]> = {
  "event.ingested": [
    ["overview"], ["context"], ["sessions"], ["agents"], ["provenance"],
    ["trust", "summary"], ["trust", "sources"], ["trust", "destinations"],
  ],
  "decision.made": [
    ["overview"], ["sessions"], ["replay"], ["agents"], ["provenance"],
    ["policies", "decisions"], ["policies", "recent-decisions"],
  ],
  "finding.created": [["findings"], ["overview"], ["agents"], ["sessions"], ...WORK_PIPELINE],
  "finding.updated": [["findings"], ["overview"], ["agents"], ["sessions"], ["incidents"], ...WORK_PIPELINE],
  "approval.created": [["approvals"], ["overview"], ["sessions"], ["replay"]],
  "approval.decided": [["approvals"], ["overview"], ["sessions"], ["replay"], ["incidents", "timeline"]],
  "incident.created": [["incidents"], ["overview"], ["findings"]],
  "incident.updated": [["incidents"], ["overview"], ["findings"], ...WORK_PIPELINE],
  "session.updated": [["sessions"], ["agents"], ["overview"], ["replay"], ["provenance", "scopes"]],
  "agent.updated": [["agents"], ["overview"], ["sessions"], ["provenance", "scopes"]],
  "task.updated": [["workspace"], ["findings"], ["incidents"]],
  "simulation.completed": [
    ["simulations"], ["overview"], ["findings"], ["agents"], ["sessions"], ["incidents"], ["approvals"],
    ["context"], ["provenance"], ["workspace", "remediation"],
  ],
  "policy.updated": [["policies"], ["agents"], ["overview"]],
  "trust.updated": [["trust"], ["context"], ["agents"], ["overview"], ["provenance"]],
  // `contextos-server purge` deleted expired event data (backend/app/services/retention.py); rare,
  // so every view that shows recorded events refreshes. Tasks re-read their (now missing) refs.
  "retention.purged": [
    ["overview"], ["context"], ["sessions"], ["agents"], ["provenance"], ["findings"], ["approvals"], ["incidents"],
    ["replay"], ["trust"], ["policies", "decisions"], ["policies", "recent-decisions"], ["workspace"],
  ],
};

/**
 * Keys whose ACTIVE queries refresh through their own throttled subscriber (the integrations
 * overview, see features/integrations/liveRefresh.ts). Live events only mark them stale, so the
 * next visit refetches without defeating the page's throttle during an event burst.
 */
export const MARK_STALE: Record<string, QueryKey[]> = {
  "event.ingested": [["integrations"]],
  "decision.made": [["integrations"]],
  "simulation.completed": [["integrations"]],
  "retention.purged": [["integrations"]],
};

export const COALESCE_MS = 150;

let listeners: Array<(msg: LiveMessage) => void> = [];
export function onLiveMessage(fn: (msg: LiveMessage) => void) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

const isPrefix = (prefix: QueryKey, key: QueryKey) => prefix.length <= key.length && prefix.every((part, i) => part === key[i]);

/** Drop keys already covered by a shorter pending key (["workspace"] covers ["workspace", "remediation"]). */
function minimalKeys(keys: QueryKey[]): QueryKey[] {
  return keys.filter((key, i) => !keys.some((other, j) => j !== i && isPrefix(other, key) && (other.length < key.length || j < i)));
}

/** Collects invalidations for COALESCE_MS, then applies each distinct key once. */
export function createInvalidationBatcher(qc: QueryClient, delayMs = COALESCE_MS) {
  let refetch: QueryKey[] = [];
  let stale: QueryKey[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;

  const flush = () => {
    timer = undefined;
    const active = minimalKeys(refetch);
    const staleOnly = minimalKeys(stale).filter((key) => !active.some((a) => isPrefix(a, key)));
    refetch = [];
    stale = [];
    for (const queryKey of active) void qc.invalidateQueries({ queryKey });
    for (const queryKey of staleOnly) void qc.invalidateQueries({ queryKey, refetchType: "none" });
  };

  return {
    add(type: string) {
      const keys = INVALIDATIONS[type];
      const marks = MARK_STALE[type];
      if (!keys && !marks) return;
      if (keys) refetch.push(...keys);
      if (marks) stale.push(...marks);
      if (timer === undefined) timer = setTimeout(flush, delayMs);
    },
    flush() {
      if (timer !== undefined) clearTimeout(timer);
      flush();
    },
    cancel() {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      refetch = [];
      stale = [];
    },
  };
}

function parseMessage(data: unknown): LiveMessage | null {
  if (typeof data !== "string" || !data) return null;
  try {
    const msg: unknown = JSON.parse(data);
    return msg && typeof msg === "object" && typeof (msg as LiveMessage).type === "string" ? (msg as LiveMessage) : null;
  } catch {
    return null; // keep-alive comments and malformed frames carry nothing to act on
  }
}

export function useLiveEvents(enabled: boolean): LiveStatus {
  const qc = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");

  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let retry: number | undefined;
    let attempts = 0;
    const batcher = createInvalidationBatcher(qc);

    const connect = () => {
      setStatus("connecting");
      source = new EventSource("/api/v1/stream", { withCredentials: true });
      source.onopen = () => {
        // After a reconnect, anything that changed while offline was missed: refresh what is on screen.
        if (attempts > 0) void qc.invalidateQueries();
        attempts = 0;
        setStatus("live");
      };
      source.onmessage = (e) => {
        const msg = parseMessage(e.data);
        if (!msg) return;
        batcher.add(msg.type);
        listeners.forEach((l) => l(msg));
      };
      source.onerror = () => {
        setStatus("offline");
        source?.close();
        attempts += 1;
        retry = window.setTimeout(connect, Math.min(30_000, 1000 * 2 ** attempts));
      };
    };
    connect();
    return () => {
      source?.close();
      window.clearTimeout(retry);
      batcher.cancel();
    };
  }, [enabled, qc]);

  return status;
}
