import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Filter state kept in the URL query string so filtered views can be shared and survive reloads.
 * `set` merges a patch; empty values remove the key. Updates replace the history entry.
 */
export function useUrlState() {
  const [params, setParams] = useSearchParams();
  const get = useCallback((key: string) => params.get(key) ?? "", [params]);
  const set = useCallback(
    (patch: Record<string, string | null | undefined>) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(patch)) {
            if (value === null || value === undefined || value === "") next.delete(key);
            else next.set(key, value);
          }
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );
  return { params, get, set };
}

/** `value` when it is one of `allowed`, else `fallback`. */
export function oneOf<T extends string>(value: string, allowed: readonly T[], fallback: T): T;
export function oneOf<T extends string>(value: string, allowed: readonly T[]): T | undefined;
export function oneOf<T extends string>(value: string, allowed: readonly T[], fallback?: T): T | undefined {
  return (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}
