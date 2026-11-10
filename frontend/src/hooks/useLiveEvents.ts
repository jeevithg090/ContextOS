/**
 * Live updates over Server-Sent Events (GET /api/v1/stream, cookie-authenticated).
 * Messages are small notifications: {type: "<entity>.<verb>", id?, ...}. On each message we
 * invalidate the TanStack Query keys for the affected feature — details are always refetched
 * through the API, so no sensitive payloads travel over the stream.
 */
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

export type LiveStatus = "connecting" | "live" | "offline";

const INVALIDATIONS: Record<string, string[][]> = {
  "event.ingested": [["overview"], ["context"], ["sessions"], ["agents"], ["provenance"]],
  "decision.made": [["overview"], ["sessions"], ["replay"], ["agents"]],
  "finding.created": [["findings"], ["overview"], ["agents"], ["workspace", "remediation"]],
  "finding.updated": [["findings"], ["overview"]],
  "approval.created": [["approvals"], ["overview"]],
  "approval.decided": [["approvals"], ["overview"], ["sessions"]],
  "incident.created": [["incidents"], ["overview"]],
  "incident.updated": [["incidents"], ["overview"]],
  "session.updated": [["sessions"], ["agents"]],
  "agent.updated": [["agents"], ["overview"]],
  "task.updated": [["workspace"]],
  "simulation.completed": [["simulations"], ["overview"], ["findings"], ["agents"]],
  "policy.updated": [["policies"]],
  "trust.updated": [["trust"], ["context"]],
};

let listeners: Array<(msg: { type: string; [k: string]: unknown }) => void> = [];
export function onLiveMessage(fn: (msg: { type: string; [k: string]: unknown }) => void) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

export function useLiveEvents(enabled: boolean): LiveStatus {
  const qc = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");

  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let retry: number | undefined;
    let attempts = 0;

    const connect = () => {
      setStatus("connecting");
      source = new EventSource("/api/v1/stream", { withCredentials: true });
      source.onopen = () => {
        attempts = 0;
        setStatus("live");
      };
      source.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data) as { type: string };
          (INVALIDATIONS[msg.type] ?? []).forEach((key) => qc.invalidateQueries({ queryKey: key }));
          listeners.forEach((l) => l(msg));
        } catch {
          /* ignore malformed keep-alives */
        }
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
    };
  }, [enabled, qc]);

  return status;
}
