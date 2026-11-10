import { useCallback, useMemo, useState } from "react";

export interface PaginationState {
  limit: number;
  offset: number;
  /** Jump to an absolute row offset (what <Pagination onChange> emits). Negative values clamp to 0. */
  setOffset: (offset: number) => void;
  /** Change the page size; returns to the first page so the user never lands past the end. */
  setLimit: (limit: number) => void;
  /** Back to the first page — call whenever filters or search change. */
  reset: () => void;
  /** Ready to spread into an API query: `api.get(path, { ...filters, ...params })`. */
  params: { limit: number; offset: number };
}

/** Offset/limit pagination state matching the backend `Page[T]` contract. */
export function usePagination(initialLimit = 25): PaginationState {
  const [limit, setLimitState] = useState(() => Math.max(1, Math.floor(initialLimit)));
  const [offset, setOffsetState] = useState(0);

  const setOffset = useCallback((next: number) => {
    setOffsetState(Number.isFinite(next) ? Math.max(0, Math.floor(next)) : 0);
  }, []);

  const setLimit = useCallback((next: number) => {
    setLimitState(Number.isFinite(next) ? Math.max(1, Math.floor(next)) : 1);
    setOffsetState(0);
  }, []);

  const reset = useCallback(() => setOffsetState(0), []);

  const params = useMemo(() => ({ limit, offset }), [limit, offset]);

  return { limit, offset, setOffset, setLimit, reset, params };
}
