/** Scope controls: what the graph is centred on (session / agent / finding, or a context item reached
 * from another page), hop depth and which optional node types are drawn. */
import { useId, useState, type KeyboardEvent, type ReactNode } from "react";
import * as Popover from "@radix-ui/react-popover";
import { ChevronDown, FlaskConical, Search, X } from "lucide-react";
import { SegmentedControl } from "@/components/data";
import { Badge, IconButton, Select, SeverityBadge, Spinner } from "@/components/ui";
import { useDebounce } from "@/hooks";
import { FINDING_CATEGORY_LABELS, humanize } from "@/lib/domain";
import { cn, timeAgo } from "@/lib/format";
import { useProvenanceScopes } from "./api";
import { NODE_TYPE_META, OPTIONAL_TYPES, riskTone } from "./nodeMeta";
import type { GraphScope, ScopeOptions } from "./types";

export type PickerMode = "session" | "agent" | "finding";

interface Option {
  id: string;
  title: string;
  meta: string;
  badge: ReactNode;
  simulation: boolean;
}

const MODE_TEXT: Record<PickerMode, { noun: string; trigger: string; input: string }> = {
  session: { noun: "session", trigger: "Search sessions by agent or id…", input: "Agent name or session id" },
  agent: { noun: "agent", trigger: "Search agents by name…", input: "Agent name" },
  finding: { noun: "finding", trigger: "Search findings by title, rule or id…", input: "Finding title, rule id or finding id" },
};

function riskBadge(score: number, level: string | null) {
  return (
    <Badge tone={level ? riskTone(level) : "neutral"} title="Risk score (0–100) computed by ContextOS">
      Risk {score}
    </Badge>
  );
}

function optionsFor(mode: PickerMode, data: ScopeOptions | undefined): Option[] {
  if (!data) return [];
  if (mode === "session") {
    return data.sessions.map((s) => ({
      id: s.id,
      title: s.agent_name,
      meta: `${s.external_session_id} · ${timeAgo(s.last_event_at ?? s.started_at)}`,
      badge: riskBadge(s.risk_score, s.risk_level),
      simulation: s.is_simulation,
    }));
  }
  if (mode === "agent") {
    return data.agents.map((a) => ({
      id: a.id,
      title: a.name,
      meta: `${a.framework} · ${a.environment} · ${a.session_count} session${a.session_count === 1 ? "" : "s"}`,
      badge: riskBadge(a.risk_score, null),
      simulation: a.is_simulation,
    }));
  }
  return (data.findings ?? []).map((f) => ({
    id: f.id,
    title: f.title,
    meta: [FINDING_CATEGORY_LABELS[f.category] ?? humanize(f.category), f.agent_name, humanize(f.status), timeAgo(f.last_seen_at)]
      .filter(Boolean)
      .join(" · "),
    badge: <SeverityBadge severity={f.severity} />,
    simulation: f.is_simulation,
  }));
}

function ScopeCombobox({ mode, currentLabel, onPick }: { mode: PickerMode; currentLabel: string | null; onPick: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const query = useDebounce(text.trim(), 200);
  const scopes = useProvenanceScopes(query, open);
  const listId = useId();
  const options = optionsFor(mode, scopes.data);
  const { noun, trigger, input } = MODE_TEXT[mode];

  const activeIndex = Math.min(active, options.length - 1);

  const pick = (id: string) => {
    onPick(id);
    setOpen(false);
    setText("");
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive(Math.min(activeIndex + 1, options.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive(Math.max(activeIndex - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (options[activeIndex]) pick(options[activeIndex].id);
    }
  };
  return (
    <Popover.Root open={open} onOpenChange={(v) => { setOpen(v); setActive(0); }}>
      <Popover.Trigger asChild>
        <button
          type="button"
          aria-label={`Choose ${noun}`}
          className="inline-flex h-8 w-full min-w-0 items-center gap-2 rounded border border-border-strong bg-surface-2 px-2.5 text-left text-[13px] text-fg transition-colors hover:border-accent/50 sm:w-[340px]"
        >
          <Search className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
          <span className={cn("min-w-0 flex-1 truncate", !currentLabel && "text-fg-faint")}>{currentLabel ?? trigger}</span>
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={4} className="z-50 w-[min(420px,calc(100vw-32px))] rounded-md border border-border-strong bg-surface shadow-pop animate-fade-in">
          <div className="flex items-center gap-2 border-b border-border px-2.5">
            <Search className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
            <input
              autoFocus
              role="combobox"
              aria-expanded
              aria-controls={listId}
              aria-activedescendant={options[activeIndex] ? `${listId}-${options[activeIndex].id}` : undefined}
              aria-label={`Search ${noun}s`}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setActive(0);
              }}
              onKeyDown={onKeyDown}
              placeholder={input}
              className="h-9 flex-1 bg-transparent text-[13px] text-fg placeholder:text-fg-faint focus:outline-none"
            />
            {scopes.isFetching && <Spinner className="h-3.5 w-3.5" />}
          </div>
          <ul id={listId} role="listbox" aria-label={`${noun}s`} className="max-h-[320px] overflow-y-auto py-1">
            {scopes.isError && <li className="px-3 py-3 text-xs text-danger">Couldn’t load {noun}s: {(scopes.error as Error).message}</li>}
            {!scopes.isError && scopes.data && options.length === 0 && (
              <li className="px-3 py-3 text-xs text-fg-muted">{query ? `No ${noun}s match “${query}”.` : `No ${noun}s recorded yet.`}</li>
            )}
            {!scopes.data && scopes.isLoading && <li className="px-3 py-3 text-xs text-fg-muted">Loading…</li>}
            {options.map((option, i) => (
              <li
                key={option.id}
                id={`${listId}-${option.id}`}
                role="option"
                aria-selected={i === activeIndex}
                onMouseEnter={() => setActive(i)}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(option.id)}
                className={cn("flex cursor-pointer items-center gap-2 px-3 py-1.5", i === activeIndex && "bg-surface-2")}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 truncate text-[13px] text-fg" title={option.title}>
                    {option.title}
                    {option.simulation && <FlaskConical className="h-3 w-3 shrink-0 text-accent" aria-label="Simulation data" />}
                  </div>
                  <div className="truncate font-mono text-2xs text-fg-faint">{option.meta}</div>
                </div>
                <span className="shrink-0">{option.badge}</span>
              </li>
            ))}
          </ul>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

interface ScopeBarProps {
  scope: GraphScope | null;
  pickerMode: PickerMode;
  onPickerModeChange: (mode: PickerMode) => void;
  onPick: (mode: PickerMode, id: string) => void;
  onClearScope: () => void;
  depth: number;
  onDepthChange: (depth: number) => void;
  hiddenTypes: ReadonlySet<string>;
  onToggleType: (type: string) => void;
  /** Node counts per type in the current graph (null while no graph is loaded). */
  typeCounts: Record<string, number> | null;
}

export function ScopeBar({ scope, pickerMode, onPickerModeChange, onPick, onClearScope, depth, onDepthChange, hiddenTypes, onToggleType, typeCounts }: ScopeBarProps) {
  const hopScope = scope?.kind === "context_item" || scope?.kind === "finding";
  // An explicitly chosen scope (not the automatic "most recent high-risk session") can be cleared.
  const explicit = !!scope && scope.kind !== "none" && !scope.auto_selected;
  const pickerLabel = scope && scope.kind === pickerMode && !scope.auto_selected ? scope.label : null;
  const clearLabel = "Clear scope (show the most recent high-risk session)";
  return (
    <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2.5 px-3 py-2.5">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="label-caps">Scope</span>
        <SegmentedControl
          aria-label="Scope type"
          value={pickerMode}
          onChange={onPickerModeChange}
          options={[
            { value: "session", label: "Session" },
            { value: "agent", label: "Agent" },
            { value: "finding", label: "Finding" },
          ]}
        />
        {scope?.kind === "context_item" ? (
          // Context-item scopes arrive from other pages (?item=); they have no picker of their own.
          <span className="inline-flex h-8 min-w-0 max-w-[420px] items-center gap-2 rounded border border-accent/40 bg-accent/10 pl-2.5 pr-1 text-[13px] text-fg">
            <span className="shrink-0 text-2xs uppercase tracking-[0.06em] text-accent">Context item</span>
            <span className="truncate" title={scope.label}>
              {scope.label}
            </span>
            <IconButton label={clearLabel} className="h-6 w-6" onClick={onClearScope}>
              <X className="h-3.5 w-3.5" />
            </IconButton>
          </span>
        ) : (
          <>
            <ScopeCombobox mode={pickerMode} currentLabel={pickerLabel} onPick={(id) => onPick(pickerMode, id)} />
            {explicit && (
              <IconButton label={clearLabel} className="h-7 w-7" onClick={onClearScope}>
                <X className="h-3.5 w-3.5" />
              </IconButton>
            )}
          </>
        )}
        {hopScope && (
          <label className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
            Hops
            <Select aria-label="Hops to expand" value={depth} onChange={(e) => onDepthChange(Number(e.target.value))} className="h-7 w-16 text-xs">
              {[1, 2, 3, 4].map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </Select>
          </label>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 lg:ml-auto" role="group" aria-label="Optional node types">
        <span className="label-caps mr-1">Show</span>
        {OPTIONAL_TYPES.map((type) => {
          const shown = !hiddenTypes.has(type);
          return (
            <button
              key={type}
              type="button"
              aria-pressed={shown}
              onClick={() => onToggleType(type)}
              className={cn(
                "inline-flex h-7 items-center gap-1.5 rounded border px-2 text-xs transition-colors",
                shown ? "border-accent/40 bg-accent/10 text-fg" : "border-border-strong text-fg-muted hover:text-fg",
              )}
            >
              {NODE_TYPE_META[type].plural}
              {typeCounts && <span className="num text-2xs text-fg-faint">{typeCounts[type] ?? 0}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}
