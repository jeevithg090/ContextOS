import { useState } from "react";
import { Link } from "react-router-dom";
import { FileJson, Sparkles, Trash2 } from "lucide-react";
import { ConfirmDialog } from "@/components/data";
import { Button, Drawer, ErrorState, LoadingRows, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useAiCatalogue, useContextPack, useDeleteContextPack } from "./api";
import { mutationMessage, useCanWrite, useExportContextPack } from "./hooks";
import { PackDetail } from "./PackDetail";

/** A stored context pack: budget, counts, notes and items with inclusion toggles; export or delete it. */
export function PackDrawer({ packId, onOpenChange }: { packId: string | null; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const canWrite = useCanWrite();
  const catalogue = useAiCatalogue();
  const pack = useContextPack(packId);
  const exportPack = useExportContextPack();
  const remove = useDeleteContextPack();
  const [confirming, setConfirming] = useState(false);
  const data = pack.data;

  return (
    <Drawer
      open={!!packId}
      onOpenChange={onOpenChange}
      width="w-[min(960px,100vw)]"
      title={data ? `${data.task_key ?? "Deleted task"} · ${data.profile_label} pack` : "Context pack"}
      subtitle={data ? `Built ${formatDateTime(data.created_at)}` : undefined}
      actions={
        data ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              size="sm"
              variant="ghost"
              icon={<FileJson className="h-3.5 w-3.5" aria-hidden />}
              loading={exportPack.isPending}
              onClick={() => exportPack.mutate(data.id, { onError: (err) => toast.error("Export failed", mutationMessage(err)) })}
            >
              Export JSON
            </Button>
            {data.task_id && (
              <Link
                to={`/work/fix-context/${encodeURIComponent(data.task_id)}?pack=${encodeURIComponent(data.id)}`}
                className="inline-flex h-7 items-center gap-1.5 rounded bg-accent px-2.5 text-xs font-medium text-accent-fg hover:bg-accent-strong"
              >
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                Use in Fix Context
              </Link>
            )}
            {canWrite && (
              <Button size="sm" variant="ghost" className="hover:text-danger" icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />} onClick={() => setConfirming(true)}>
                Delete
              </Button>
            )}
          </div>
        ) : undefined
      }
    >
      {pack.isLoading ? (
        <LoadingRows rows={8} />
      ) : pack.error ? (
        <ErrorState error={pack.error instanceof ApiError && pack.error.status === 404 ? new Error("This context pack no longer exists.") : pack.error} onRetry={() => void pack.refetch()} />
      ) : data ? (
        <div className="p-5">
          <PackDetail pack={data} canEdit={canWrite} repositoryConfigured={catalogue.data?.repository_configured} />
        </div>
      ) : null}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Delete this context pack?"
        description="The stored pack and its item choices are removed. This cannot be undone."
        confirmLabel="Delete pack"
        destructive
        onConfirm={() =>
          new Promise<void>((resolve, reject) => {
            if (!data) return resolve();
            remove.mutate(
              { packId: data.id, taskId: data.task_id },
              {
                onSuccess: () => {
                  toast.success("Context pack deleted", `${data.task_key ?? ""} ${data.profile_label}`.trim());
                  onOpenChange(false);
                  resolve();
                },
                onError: (err) => reject(new Error(mutationMessage(err))),
              },
            );
          })
        }
      >
        <p className="text-xs text-fg-muted">Saved prompts that used it keep their content. If one of their sections is regenerated later, a fresh, unsaved pack is built instead.</p>
      </ConfirmDialog>
    </Drawer>
  );
}
