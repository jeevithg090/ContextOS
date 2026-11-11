import { Drawer, EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { shortId } from "@/lib/format";
import { isNotFound, useRun } from "../api";
import { RunDetail } from "./RunDetail";

/** Side panel for one run, opened from `?run=<id>` so every run result is a link. */
export function RunDrawer({ runId, onClose, onShowSuite }: { runId: string | null; onClose: () => void; onShowSuite: (suiteRunId: string) => void }) {
  const run = useRun(runId);
  return (
    <Drawer
      open={!!runId}
      onOpenChange={(open) => !open && onClose()}
      title={run.data?.scenario_name ?? "Simulation run"}
      subtitle={runId ? `Simulation run ${shortId(runId)} — synthetic events through the real pipeline` : undefined}
    >
      {run.isLoading ? (
        <LoadingRows rows={6} />
      ) : run.error && !run.data ? (
        isNotFound(run.error) ? (
          <EmptyState title="Simulation run not found" description="This run does not exist in your organisation. Pick a run from the history instead." />
        ) : (
          <ErrorState error={run.error} onRetry={() => void run.refetch()} />
        )
      ) : run.data ? (
        <RunDetail run={run.data} onShowSuite={onShowSuite} />
      ) : null}
    </Drawer>
  );
}
