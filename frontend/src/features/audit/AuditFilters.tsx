import { useEffect, useId, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { X } from "lucide-react";
import { FilterBar, FilterSelect } from "@/components/data";
import { Input } from "@/components/ui";
import { useDebounce } from "@/hooks";
import { formatDateTime, formatNumber, shortId } from "@/lib/format";
import { ACTION_FAMILIES, ACTOR_TYPE_LABELS, TIME_WINDOWS, actorTypeLabel } from "./meta";
import type { AuditActorType, AuditFilters } from "./types";

const FILTER_KEYS = ["action", "actor_type", "actor_id", "target_type", "target_id", "window", "since", "until"] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

/** Filters live in the URL (?action=policy.&actor_type=user&window=24h …) so every view is a link. */
export function useAuditFilterParams() {
  const [params, setParams] = useSearchParams();
  const raw = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""])) as Record<FilterKey, string>;
  const windowMs = TIME_WINDOWS.find((w) => w.value === raw.window)?.ms;
  // A preset window is resolved once per selection so the query key stays stable between renders.
  const presetSince = useMemo(() => (windowMs ? new Date(Date.now() - windowMs).toISOString() : undefined), [windowMs]);
  const actorType = (Object.keys(ACTOR_TYPE_LABELS) as AuditActorType[]).find((t) => t === raw.actor_type);

  const filters: AuditFilters = {
    action: raw.action || undefined,
    actor_type: actorType,
    actor_id: raw.actor_id || undefined,
    target_type: raw.target_type || undefined,
    target_id: raw.target_id || undefined,
    since: presetSince ?? (raw.since || undefined),
    until: windowMs ? undefined : raw.until || undefined,
  };

  const set = (patch: Partial<Record<FilterKey, string | null>>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(patch)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next, { replace: true });
  };
  const clear = () => set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])));
  const active = FILTER_KEYS.some((k) => raw[k]);
  return { raw, filters, set, clear, active };
}

function Chip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex h-7 items-center gap-1 rounded border border-accent/40 bg-accent/10 pl-2 pr-1 text-xs text-fg">
      {label}
      <button type="button" onClick={onRemove} aria-label={`Remove filter: ${label}`} className="inline-flex h-5 w-5 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg">
        <X className="h-3 w-3" aria-hidden />
      </button>
    </span>
  );
}

export function AuditFilterBar({ state, total }: { state: ReturnType<typeof useAuditFilterParams>; total: number | undefined }) {
  const { raw, set, clear, active } = state;
  const [action, setAction] = useState(raw.action);
  const debounced = useDebounce(action, 300);
  const inputId = useId();
  const listId = useId();

  useEffect(() => setAction(raw.action), [raw.action]);
  useEffect(() => {
    if (debounced.trim() !== raw.action) set({ action: debounced.trim() || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only react to the debounced text
  }, [debounced]);

  return (
    <FilterBar
      onClear={clear}
      canClear={active}
      aria-label="Audit log filters"
      actions={total !== undefined ? <span className="num text-xs text-fg-muted">{formatNumber(total)} {total === 1 ? "entry" : "entries"}</span> : undefined}
    >
      <div className="inline-flex items-center gap-1.5">
        <label htmlFor={inputId} className="text-xs text-fg-faint">
          Action
        </label>
        <Input
          id={inputId}
          list={listId}
          value={action}
          onChange={(e) => setAction(e.target.value)}
          placeholder="starts with… e.g. policy."
          maxLength={64}
          spellCheck={false}
          className="!h-7 !w-56 font-mono !text-xs"
        />
        <datalist id={listId}>
          {ACTION_FAMILIES.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </datalist>
      </div>
      <FilterSelect
        label="Actor"
        value={raw.actor_type}
        onChange={(v) => set({ actor_type: v || null })}
        options={Object.entries(ACTOR_TYPE_LABELS).map(([value, label]) => ({ value, label }))}
        allLabel="Anyone"
      />
      <FilterSelect
        label="Time"
        value={raw.window}
        onChange={(v) => set({ window: v || null, since: null, until: null })}
        options={TIME_WINDOWS.map(({ value, label }) => ({ value, label }))}
        allLabel={raw.since || raw.until ? "Custom range" : "Any time"}
      />
      {raw.actor_id && <Chip label={`${raw.actor_type ? actorTypeLabel(raw.actor_type) : "Actor"} ${shortId(raw.actor_id)}`} onRemove={() => set({ actor_id: null })} />}
      {(raw.target_type || raw.target_id) && (
        <Chip
          label={`Target ${raw.target_type ? raw.target_type.replace(/_/g, " ") : ""} ${raw.target_id ? shortId(raw.target_id) : ""}`.replace(/\s+/g, " ").trim()}
          onRemove={() => set({ target_type: null, target_id: null })}
        />
      )}
      {!raw.window && (raw.since || raw.until) && (
        <Chip
          label={`${raw.since ? `from ${formatDateTime(raw.since)}` : ""} ${raw.until ? `until ${formatDateTime(raw.until)}` : ""}`.trim()}
          onRemove={() => set({ since: null, until: null })}
        />
      )}
    </FilterBar>
  );
}
