/** Canvas legend: what node types, colours and edge styles mean. Collapsible to keep the canvas clear. */
import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { toneColor } from "@/components/data";
import { TONE_CLASSES, TRUST_META, type TrustLevel } from "@/lib/domain";
import { cn } from "@/lib/format";
import { NODE_TYPE_META } from "./nodeMeta";

const EDGE_STYLES = [
  { label: "Observed relationship", dash: undefined, color: "rgb(var(--fg-muted))" },
  { label: "Inferred by ContextOS", dash: "6 4", color: "rgb(var(--fg-muted))" },
  { label: "Linked by a finding record", dash: "2 4", color: "rgb(var(--fg-muted))" },
  { label: "Selected risky path", dash: "5 5", color: toneColor("critical") },
];

const LEGEND_TYPES = ["source", "context_item", "session", "tool_invocation", "resource", "destination", "finding", "policy_decision", "tool", "agent"];

export function Legend({ visibleTypes }: { visibleTypes: ReadonlySet<string> }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="w-60 rounded-md border border-border bg-surface/95 text-xs shadow-panel backdrop-blur-sm">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 px-2.5 py-1.5 text-left font-medium text-fg-muted hover:text-fg"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
        Legend
      </button>
      {open && (
        <div className="space-y-3 border-t border-border px-2.5 py-2.5">
          <div>
            <div className="label-caps mb-1.5">Nodes</div>
            <ul className="space-y-1">
              {LEGEND_TYPES.filter((t) => visibleTypes.has(t)).map((type) => {
                const meta = NODE_TYPE_META[type];
                const Icon = meta.icon;
                return (
                  <li key={type} className="flex items-center gap-1.5 text-fg-muted" title={meta.description}>
                    <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
                    <span className="text-fg">{meta.label}</span>
                  </li>
                );
              })}
            </ul>
          </div>
          <div>
            <div className="label-caps mb-1.5">Accent colour</div>
            <p className="text-fg-muted">Trust for sources, content and destinations · severity for findings · decision for tool calls · risk for sessions.</p>
            <div className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1">
              {(Object.keys(TRUST_META) as TrustLevel[]).map((level) => (
                <span key={level} className="inline-flex items-center gap-1 text-2xs text-fg-muted">
                  <span className={cn("h-2 w-2 rounded-full", TONE_CLASSES[TRUST_META[level].tone].dot)} aria-hidden />
                  {TRUST_META[level].label}
                </span>
              ))}
            </div>
          </div>
          <div>
            <div className="label-caps mb-1.5">Edges</div>
            <ul className="space-y-1">
              {EDGE_STYLES.map((style) => (
                <li key={style.label} className="flex items-center gap-2 text-fg-muted">
                  <svg width="28" height="6" aria-hidden>
                    <line x1="0" y1="3" x2="28" y2="3" stroke={style.color} strokeWidth="2" strokeDasharray={style.dash} />
                  </svg>
                  {style.label}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
