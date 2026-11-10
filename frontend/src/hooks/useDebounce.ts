import { useEffect, useState } from "react";

/**
 * Returns `value` after it has stopped changing for `ms` milliseconds.
 * Use for search boxes and other inputs that drive API queries.
 */
export function useDebounce<T>(value: T, ms = 250): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    if (ms <= 0) {
      setDebounced(value);
      return;
    }
    const timer = window.setTimeout(() => setDebounced(value), ms);
    return () => window.clearTimeout(timer);
  }, [value, ms]);

  return debounced;
}
