import { useEffect, useMemo, useState } from "react";

/**
 * Local, editable copy of a slice of server settings.
 * - Adopts fresh server values while the user has no unsaved edits (e.g. another admin saved).
 * - Keeps unsaved edits when the server value changes underneath them.
 * - `changes` contains only the fields that differ from the server, ready for a PATCH.
 */
export function useSettingsDraft<T extends Record<string, unknown>>(source: T | undefined) {
  const sourceKey = source ? JSON.stringify(source) : "";
  const [draft, setDraft] = useState<T | undefined>(source);
  const [baseKey, setBaseKey] = useState(sourceKey);

  useEffect(() => {
    if (!source) return;
    setDraft((prev) => (prev === undefined || JSON.stringify(prev) === baseKey ? source : prev));
    setBaseKey(sourceKey);
    // `source` is represented by `sourceKey`; re-running on object identity would discard edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceKey]);

  const changes = useMemo(() => {
    const out: Partial<T> = {};
    if (!draft || !source) return out;
    for (const key of Object.keys(draft) as Array<keyof T>) {
      if (draft[key] !== source[key]) out[key] = draft[key];
    }
    return out;
  }, [draft, source]);

  return {
    draft,
    dirty: Object.keys(changes).length > 0,
    changes,
    set: <K extends keyof T>(key: K, value: T[K]) => setDraft((d) => (d ? { ...d, [key]: value } : d)),
    reset: () => setDraft(source),
  };
}
