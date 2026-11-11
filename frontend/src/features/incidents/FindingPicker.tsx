/**
 * Choose open findings that are not yet part of an incident. Simulated and real findings cannot be
 * grouped together (the API refuses it), so once one kind is selected the other is disabled.
 */
import { useMemo, useState } from "react";
import { Checkbox, ErrorState, LoadingRows, SeverityBadge, SimulationBadge } from "@/components/ui";
import { FINDING_CATEGORY_LABELS } from "@/lib/domain";
import { cn, timeAgo } from "@/lib/format";
import { useFindingOptions } from "./api";
import type { FindingOption } from "./types";

export interface FindingPickerProps {
  selected: string[];
  onChange: (ids: string[]) => void;
  enabled: boolean;
  /** Restrict to simulated (true) or real (false) findings, e.g. when linking to an existing incident. */
  simulation?: boolean;
}

export function FindingPicker({ selected, onChange, enabled, simulation }: FindingPickerProps) {
  const [showSimulated, setShowSimulated] = useState(simulation === true);
  const [filter, setFilter] = useState("");
  const options = useFindingOptions(simulation === true || showSimulated, enabled);

  const rows = useMemo(() => {
    const all = (options.data ?? []).filter((f) => simulation === undefined || f.is_simulation === simulation);
    const q = filter.trim().toLowerCase();
    return q ? all.filter((f) => `${f.title} ${f.category} ${f.agent?.name ?? ""}`.toLowerCase().includes(q)) : all;
  }, [options.data, filter, simulation]);

  // Remember each selected finding's kind, so the lock holds even if the list is re-filtered.
  const [kinds, setKinds] = useState<Record<string, boolean>>({});
  const lockedKind = selected.length ? kinds[selected[0]] : undefined;

  const toggle = (f: FindingOption, on: boolean) => {
    if (on) setKinds((k) => ({ ...k, [f.id]: f.is_simulation }));
    onChange(on ? [...selected, f.id] : selected.filter((id) => id !== f.id));
  };

  if (options.isLoading) return <LoadingRows rows={3} />;
  if (options.error) return <ErrorState error={options.error} onRetry={() => void options.refetch()} />;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <input
          type="search"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter findings"
          aria-label="Filter findings"
          className="h-7 w-56 rounded border border-border-strong bg-surface-2 px-2 text-xs text-fg placeholder:text-fg-faint focus:border-accent/60 focus:outline-none"
        />
        {simulation === undefined && (
          <Checkbox label={<span className="text-xs text-fg-muted">Show simulated findings</span>} checked={showSimulated} onChange={setShowSimulated} />
        )}
      </div>
      {rows.length === 0 ? (
        <p className="rounded border border-dashed border-border px-3 py-4 text-center text-xs text-fg-muted">
          {filter ? "No open finding matches the filter." : "Every open finding is already part of an incident."}
        </p>
      ) : (
        <ul className="max-h-64 divide-y divide-border overflow-y-auto rounded border border-border" aria-label="Open findings without an incident">
          {rows.map((f) => {
            const checked = selected.includes(f.id);
            const disabled = !checked && lockedKind !== undefined && lockedKind !== f.is_simulation;
            return (
              <li key={f.id} className={cn("flex items-start gap-2 px-3 py-2", disabled && "opacity-50")} title={disabled ? "Simulated and real findings cannot be grouped together" : undefined}>
                <Checkbox
                  checked={checked}
                  disabled={disabled}
                  onChange={(on) => toggle(f, on)}
                  label={
                    <span className="flex min-w-0 flex-col gap-0.5">
                      <span className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={f.severity} />
                        <span className="min-w-0 break-words text-[13px] text-fg">{f.title}</span>
                        {f.is_simulation && <SimulationBadge />}
                      </span>
                      <span className="text-2xs text-fg-faint">
                        {FINDING_CATEGORY_LABELS[f.category] ?? f.category}
                        {f.agent ? ` · ${f.agent.name}` : ""}
                        {f.session ? ` · ${f.session.external_session_id}` : ""} · last seen {timeAgo(f.last_seen_at)}
                      </span>
                    </span>
                  }
                />
              </li>
            );
          })}
        </ul>
      )}
      {selected.length > 0 && <p className="text-2xs text-fg-muted">{selected.length} selected</p>}
    </div>
  );
}
