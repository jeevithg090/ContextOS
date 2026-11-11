/**
 * Build the hypothetical policy set: start from the saved policies (or none), switch policies off,
 * override outcome/mode, set the no-match default and add validated drafts.
 */
import { useMemo, useState } from "react";
import { RotateCcw, Trash2 } from "lucide-react";
import { Badge, Button, Checkbox, DecisionBadge, EmptyState, ErrorState, LoadingRows, Mono, Select } from "@/components/ui";
import { SearchInput, SegmentedControl } from "@/components/data";
import { DECISION_META, DECISIONS, type Decision } from "@/lib/domain";
import { cn, truncate } from "@/lib/format";
import { useReplayPolicies } from "../api";
import { isEnabled, setEnabled, setOverride, type PolicySetState } from "../policySet";
import type { DefaultDecision, PolicyBase, PolicyMode, ReplayPolicy } from "../types";
import { DraftEditor } from "./DraftEditor";

const DEFAULTS: DefaultDecision[] = ["ALLOW", "AUDIT", "REQUIRE_APPROVAL", "DENY"];

export function PolicySetEditor({ state, onChange }: { state: PolicySetState; onChange: (next: PolicySetState) => void }) {
  const policies = useReplayPolicies();
  const [q, setQ] = useState("");
  const [onlyChanged, setOnlyChanged] = useState(false);
  const rows = useMemo(() => {
    const all = policies.data?.items ?? [];
    const needle = q.trim().toLowerCase();
    return all.filter((p) => {
      if (needle && !p.name.toLowerCase().includes(needle)) return false;
      if (onlyChanged && !state.disabled.includes(p.id) && !state.overrides[p.id]) return false;
      return true;
    });
  }, [policies.data, q, onlyChanged, state.disabled, state.overrides]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div className="space-y-1.5">
          <div className="text-xs font-medium text-fg-muted">Start from</div>
          <SegmentedControl<PolicyBase>
            aria-label="Policy set base"
            value={state.base}
            onChange={(base) => onChange({ ...state, base })}
            options={[
              { value: "current", label: "Saved policies (as configured now)" },
              { value: "none", label: "No saved policies" },
            ]}
          />
        </div>
        <label className="space-y-1.5">
          <span className="block text-xs font-medium text-fg-muted">When no policy matches</span>
          <Select
            value={state.defaultDecision ?? ""}
            onChange={(e) => onChange({ ...state, defaultDecision: (e.target.value || null) as DefaultDecision | null })}
            className="!h-7 !w-56 !text-xs"
          >
            <option value="">Organisation default</option>
            {DEFAULTS.map((d) => (
              <option key={d} value={d}>
                {DECISION_META[d].label}
              </option>
            ))}
          </Select>
        </label>
      </div>

      {state.base === "current" ? (
        <section aria-label="Saved policies" className="rounded-md border border-border">
          <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2">
            <h3 className="mr-auto text-[13px] font-semibold text-fg">Saved policies</h3>
            <SearchInput value={q} onChange={setQ} placeholder="Filter policies…" label="Filter policies" shortcut={false} className="w-48" />
            <Checkbox label="Changed only" checked={onlyChanged} onChange={setOnlyChanged} />
          </div>
          {policies.isLoading ? (
            <LoadingRows rows={4} />
          ) : policies.error ? (
            <ErrorState error={policies.error} onRetry={() => policies.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyState title={q || onlyChanged ? "No policies match" : "This organisation has no saved policies"} description={q || onlyChanged ? undefined : "Add a draft below to evaluate one."} className="py-8" />
          ) : (
            <ul className="max-h-[420px] divide-y divide-border/60 overflow-y-auto">
              {rows.map((p) => (
                <PolicyRow key={p.id} policy={p} state={state} onChange={onChange} />
              ))}
            </ul>
          )}
        </section>
      ) : (
        <p className="rounded-md border border-border bg-surface-2/50 px-3 py-2 text-xs text-fg-muted">
          Saved policies are left out. Only the drafts below are evaluated, and anything they do not match falls back to the default.
        </p>
      )}

      <section aria-label="Draft policies" className="space-y-3">
        <h3 className="text-[13px] font-semibold text-fg">Draft policies</h3>
        {state.drafts.length > 0 && (
          <ul className="space-y-1.5">
            {state.drafts.map((d, i) => (
              <li key={`${d.name}-${i}`} className="flex flex-wrap items-center gap-2 rounded border border-border px-3 py-2 text-[13px]">
                <Badge tone="accent">Draft</Badge>
                <span className="font-medium text-fg">{d.name}</span>
                <DecisionBadge decision={d.outcome} />
                {d.mode === "monitor" && <Badge>Monitor</Badge>}
                {d.id && <span className="text-xs text-fg-faint">replaces <Mono>{d.id}</Mono></span>}
                <Button
                  size="xs"
                  variant="ghost"
                  className="ml-auto"
                  icon={<Trash2 className="h-3 w-3" aria-hidden />}
                  aria-label={`Remove draft ${d.name}`}
                  onClick={() => onChange({ ...state, drafts: state.drafts.filter((_, j) => j !== i) })}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
        <DraftEditor existingNames={state.drafts.map((d) => d.name.trim())} onAdd={(draft) => onChange({ ...state, drafts: [...state.drafts, draft] })} />
      </section>
    </div>
  );
}

function PolicyRow({ policy: p, state, onChange }: { policy: ReplayPolicy; state: PolicySetState; onChange: (next: PolicySetState) => void }) {
  const enabled = isEnabled(state, p);
  const override = state.overrides[p.id] ?? {};
  const outcome = override.outcome ?? p.outcome;
  const mode = override.mode ?? p.mode;
  const changed = state.disabled.includes(p.id) || Boolean(state.overrides[p.id]);
  const hasRestrictions = Object.keys(p.restrictions ?? {}).length > 0;
  return (
    <li className={cn("flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2", changed && "bg-accent/[0.05]")}>
      <Checkbox label={<span className="sr-only">Enable {p.name} in this simulation</span>} checked={enabled} onChange={(v) => onChange(setEnabled(state, p, v))} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={cn("text-[13px]", enabled ? "text-fg" : "text-fg-faint line-through")}>{p.name}</span>
          {p.is_builtin && <Badge>Built-in</Badge>}
          {!p.enabled && <Badge title="Disabled in the saved configuration">Saved as disabled</Badge>}
          {changed && <Badge tone="accent">Changed</Badge>}
        </div>
        <p className="truncate text-2xs text-fg-faint" title={p.explanation}>
          {truncate(p.explanation, 140)}
        </p>
      </div>
      <label className="inline-flex items-center gap-1.5 text-2xs text-fg-faint">
        Outcome
        <Select
          value={outcome}
          onChange={(e) => onChange(setOverride(state, p, { outcome: e.target.value as Decision }))}
          className={cn("!h-7 !w-40 !text-xs", override.outcome && "border-accent/60")}
          aria-label={`Outcome for ${p.name}`}
        >
          {DECISIONS.map((d) => (
            <option key={d} value={d} disabled={d === "RESTRICT" && !hasRestrictions && p.outcome !== "RESTRICT"}>
              {DECISION_META[d].label}
              {d === "RESTRICT" && !hasRestrictions && p.outcome !== "RESTRICT" ? " (needs restrictions)" : ""}
            </option>
          ))}
        </Select>
      </label>
      <label className="inline-flex items-center gap-1.5 text-2xs text-fg-faint">
        Mode
        <Select
          value={mode}
          onChange={(e) => onChange(setOverride(state, p, { mode: e.target.value as PolicyMode }))}
          className={cn("!h-7 !w-28 !text-xs", override.mode && "border-accent/60")}
          aria-label={`Mode for ${p.name}`}
        >
          <option value="enforce">Enforce</option>
          <option value="monitor">Monitor</option>
        </Select>
      </label>
      <Button
        size="xs"
        variant="ghost"
        disabled={!changed}
        icon={<RotateCcw className="h-3 w-3" aria-hidden />}
        aria-label={`Reset ${p.name} to its saved configuration`}
        onClick={() => {
          const overrides = { ...state.overrides };
          delete overrides[p.id];
          onChange({ ...state, disabled: state.disabled.filter((id) => id !== p.id), overrides });
        }}
      >
        Reset
      </Button>
    </li>
  );
}
