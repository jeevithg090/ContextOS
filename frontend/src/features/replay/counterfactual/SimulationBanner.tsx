import { FlaskConical } from "lucide-react";
import { SIMULATION_BANNER } from "../meta";

/** Persistent, unmistakable label for every counterfactual view (stays visible while scrolling). */
export function SimulationBanner({ caveats }: { caveats: string[] }) {
  return (
    <div role="note" aria-label="Simulation notice" className="sticky top-0 z-10 rounded-md border border-accent/40 bg-surface px-4 py-2.5 shadow-panel">
      <div className="flex items-center gap-2 text-[13px] font-semibold tracking-wide text-accent">
        <FlaskConical className="h-4 w-4 shrink-0" aria-hidden />
        {SIMULATION_BANNER}
      </div>
      <ul className="mt-1 list-disc space-y-0.5 pl-6 text-xs text-fg-muted">
        {caveats.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
    </div>
  );
}

/** The server's caveats, shown before a run has returned its own copy. */
export const DEFAULT_CAVEATS = [
  "Steps after a hypothetically denied action might not have occurred; their recorded inputs are evaluated as observed.",
  "Events with no recorded policy decision cannot be evaluated.",
];
