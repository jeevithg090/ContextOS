import { Badge } from "@/components/ui";
import type { Tone } from "@/lib/domain";
import { runVerdict, VERDICT_META, type Verdict } from "../logic";
import type { SimulationRun } from "../types";

const VERDICT_TONE: Record<Verdict, Tone> = { passed: "ok", failed: "danger", stopped: "warn", running: "accent" };
const VERDICT_SHORT: Record<Verdict, string> = { passed: "Passed", failed: "Failed", stopped: "Stopped early", running: "Running" };

/** Overall verdict of a run (all checks passed / some failed / stopped early / running). */
export function VerdictBadge({ run, className }: { run: Pick<SimulationRun, "status" | "passed">; className?: string }) {
  const verdict = runVerdict(run);
  return (
    <Badge tone={VERDICT_TONE[verdict]} dot className={className} title={VERDICT_META[verdict].description}>
      {VERDICT_SHORT[verdict]}
    </Badge>
  );
}
