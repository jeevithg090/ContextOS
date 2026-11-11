import { useEffect, useRef } from "react";
import { useQueryClient, type QueryKey } from "@tanstack/react-query";
import { onLiveMessage } from "@/hooks";

/**
 * Refetch `queryKey` when a matching live notification arrives, at most once per `minIntervalMs`.
 * Notifications carry ids only; the data is always re-read through the API.
 * `types` = null matches every notification except those listed in `exclude`.
 */
export function useThrottledLiveRefresh(
  queryKey: QueryKey,
  { types, exclude = [], enabled = true, minIntervalMs = 4000 }: { types: string[] | null; exclude?: string[]; enabled?: boolean; minIntervalMs?: number },
) {
  const qc = useQueryClient();
  const keyRef = useRef(queryKey);
  keyRef.current = queryKey;
  const typesKey = types ? types.join(",") : "*";
  const excludeKey = exclude.join(",");

  useEffect(() => {
    if (!enabled) return;
    const accept = typesKey === "*" ? null : new Set(typesKey.split(","));
    const reject = new Set(excludeKey ? excludeKey.split(",") : []);
    let last = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = onLiveMessage((msg) => {
      if (reject.has(msg.type) || (accept && !accept.has(msg.type)) || timer !== undefined) return;
      const wait = Math.max(0, last + minIntervalMs - Date.now());
      timer = setTimeout(() => {
        timer = undefined;
        last = Date.now();
        void qc.invalidateQueries({ queryKey: keyRef.current });
      }, wait);
    });
    return () => {
      off();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [qc, enabled, typesKey, excludeKey, minIntervalMs]);
}
