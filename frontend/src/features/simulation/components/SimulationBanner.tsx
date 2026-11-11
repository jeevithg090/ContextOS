import { FlaskConical } from "lucide-react";

/** Persistent, calm statement of what a simulation does — shown above every Simulation Lab view. */
export function SimulationBanner() {
  return (
    <div role="note" aria-label="About simulations" className="mb-4 flex items-start gap-3 rounded-md border border-accent/25 bg-accent/[0.05] px-3.5 py-3 text-xs leading-5 text-fg-muted">
      <FlaskConical className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
      <p>
        <span className="font-medium text-fg">Runs are simulations.</span> Each scenario submits synthetic, inert events to the real ingestion and
        policy pipeline. Nothing is executed and no network request is made. Every row a run creates is flagged as a simulation and is excluded
        from real metrics by default.
      </p>
    </div>
  );
}
