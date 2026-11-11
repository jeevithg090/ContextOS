/** Shared triage controller for the list and the detail page: acknowledge instantly, ask for a note
 * before resolving, marking false positive or reopening. */
import { useCallback, useState } from "react";
import { useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useUpdateFinding } from "./api";
import { ACTION_META, type TriageAction } from "./meta";
import { TriageDialog } from "./TriageDialog";
import type { FindingDetail } from "./types";

interface Target {
  id: string;
  title: string;
}

export function useTriage(onDone?: (detail: FindingDetail) => void) {
  const [pending, setPending] = useState<{ finding: Target; action: TriageAction } | null>(null);
  const update = useUpdateFinding();
  const toast = useToast();

  const start = useCallback(
    (action: TriageAction, finding: Target) => {
      if (action !== "acknowledged") {
        setPending({ finding, action });
        return;
      }
      update.mutate(
        { id: finding.id, body: { status: "acknowledged" } },
        {
          onSuccess: (detail) => {
            toast.success(ACTION_META.acknowledged.done, finding.title);
            onDone?.(detail);
          },
          onError: (err) => toast.error("Could not acknowledge the finding", err instanceof ApiError ? err.message : undefined),
        },
      );
    },
    [onDone, toast, update],
  );

  const dialog = (
    <TriageDialog
      finding={pending?.finding ?? null}
      action={pending?.action ?? null}
      onOpenChange={(open) => !open && setPending(null)}
      onDone={onDone}
    />
  );

  return { start, dialog, busyId: update.isPending ? update.variables?.id ?? null : null };
}
