/** The six numbers that answer "what needs my attention right now?". Each tile links to the list
 * behind it and carries a one-line explanation of exactly what it counts. */
import type { MouseEvent } from "react";
import { Link } from "react-router-dom";
import { Skeleton } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn } from "@/lib/format";
import { buildKpis, type Kpi } from "./meta";
import type { Overview } from "./types";

const TILE = "flex min-w-0 flex-col bg-surface px-4 py-3.5 text-left transition-colors hover:bg-surface-2 focus-visible:bg-surface-2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-accent/50";

function TileBody({ kpi }: { kpi: Kpi }) {
  return (
    <>
      <span className="label-caps truncate">{kpi.label}</span>
      <span className={cn("num mt-1 text-2xl font-semibold leading-none", kpi.tone ? TONE_CLASSES[kpi.tone].text : "text-fg")}>{kpi.value}</span>
      <span className="mt-1.5 truncate text-xs text-fg-muted">{kpi.hint}</span>
    </>
  );
}

function scrollToAnchor(e: MouseEvent<HTMLAnchorElement>, id: string) {
  const target = document.getElementById(id);
  if (!target) return;
  e.preventDefault();
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  target.focus({ preventScroll: true });
}

function Tile({ kpi }: { kpi: Kpi }) {
  const describedBy = `kpi-${kpi.key}-explanation`;
  const common = { className: TILE, title: kpi.explanation, "aria-describedby": describedBy };
  return (
    <>
      {kpi.href.startsWith("#") ? (
        <a href={kpi.href} onClick={(e) => scrollToAnchor(e, kpi.href.slice(1))} {...common}>
          <TileBody kpi={kpi} />
        </a>
      ) : (
        <Link to={kpi.href} {...common}>
          <TileBody kpi={kpi} />
        </Link>
      )}
      <span id={describedBy} className="sr-only">
        {kpi.explanation}
      </span>
    </>
  );
}

export function KpiStrip({ data }: { data: Overview | undefined }) {
  // gap-px over a border-coloured background draws hairline dividers at every breakpoint.
  const grid = "grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border shadow-panel sm:grid-cols-3 xl:grid-cols-6";
  if (!data) {
    return (
      <div className={grid} aria-busy="true" aria-label="Loading security summary">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="space-y-2 bg-surface px-4 py-3.5">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-6 w-12" />
            <Skeleton className="h-3 w-32" />
          </div>
        ))}
      </div>
    );
  }
  return (
    <section aria-label="Security summary" className={grid}>
      {buildKpis(data).map((kpi) => (
        <Tile key={kpi.key} kpi={kpi} />
      ))}
    </section>
  );
}
