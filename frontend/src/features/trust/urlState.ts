/** URL-backed view state for the Trust Centre (tabs, drawers, filters), so every view is a link. */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

export type ParamUpdate = Record<string, string | null | undefined>;
export type SetParams = (updates: ParamUpdate, opts?: { push?: boolean }) => void;

export function useTrustParams(): { params: URLSearchParams; set: SetParams } {
  const [params, setSearchParams] = useSearchParams();
  const set = useCallback<SetParams>(
    (updates, opts) =>
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(updates)) {
            if (value) next.set(key, value);
            else next.delete(key);
          }
          return next;
        },
        { replace: !opts?.push },
      ),
    [setSearchParams],
  );
  return { params, set };
}

/** Page-wide "include simulated" switch (`?sim=1`): Simulation Lab-only sources and destinations are hidden by default. */
export function includeSimulatedParam(params: URLSearchParams): boolean {
  return params.get("sim") === "1";
}

export function boolParam(value: string | null): boolean | undefined {
  if (value === "yes") return true;
  if (value === "no") return false;
  return undefined;
}
