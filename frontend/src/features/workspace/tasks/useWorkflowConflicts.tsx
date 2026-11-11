/**
 * Report workflow-gate refusals (HTTP 409) in plain language. A WIP-limit refusal that can be
 * retried with an explicit override opens a confirmation dialog; everything else becomes a toast
 * carrying the server's own explanation.
 */
import { useCallback, useState } from "react";
import { ConfirmDialog } from "@/components/data";
import { useToast } from "@/components/ui";
import { workflowConflict } from "../api";
import type { WorkflowConflict } from "../types";

const REASON_TITLES: Record<string, string> = {
  wip_limit_exceeded: "WIP limit reached",
  verification_required: "Passed verification required",
  column_not_empty: "Column still has tasks",
  dependency_cycle: "That would create a dependency cycle",
  parent_cycle: "That would create a parent cycle",
};

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed. Please try again.";
}

interface PendingOverride {
  title: string;
  conflict: WorkflowConflict;
  override: () => Promise<unknown>;
}

export interface ConflictContext {
  /** What failed, e.g. "CTX-12 was not moved". */
  title: string;
  /** Retry with `override_wip: true`. Offered only when the refusal is a WIP limit. */
  override?: () => Promise<unknown>;
}

export function useWorkflowConflicts() {
  const toast = useToast();
  const [pending, setPending] = useState<PendingOverride | null>(null);

  const report = useCallback(
    (error: unknown, ctx: ConflictContext) => {
      const conflict = workflowConflict(error);
      if (conflict?.reason === "wip_limit_exceeded" && ctx.override) {
        setPending({ title: ctx.title, conflict, override: ctx.override });
        return;
      }
      const reasonTitle = conflict?.reason ? REASON_TITLES[conflict.reason] : undefined;
      toast.error(reasonTitle ? `${ctx.title}: ${reasonTitle.toLowerCase()}` : ctx.title, conflict?.message ?? errorMessage(error));
    },
    [toast],
  );

  const dialog = (
    <ConfirmDialog
      open={pending !== null}
      onOpenChange={(open) => !open && setPending(null)}
      title={pending ? `${pending.title}: WIP limit reached` : "WIP limit reached"}
      description="Work-in-progress limits keep a stage from silently piling up."
      confirmLabel="Override WIP limit"
      onConfirm={async () => {
        if (!pending) return;
        await pending.override();
        toast.success("WIP limit overridden", "The override is recorded in the task's activity history.");
      }}
    >
      <p className="rounded border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-fg">{pending?.conflict.message}</p>
      <p className="text-xs">Overriding moves the task anyway. The column will show as over its limit and the override is recorded on the task.</p>
    </ConfirmDialog>
  );

  return { report, dialog };
}
