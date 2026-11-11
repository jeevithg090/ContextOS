/** Board actions menu (open, duplicate, make default, archive / restore) and their confirmations. */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Archive, ArchiveRestore, Copy, ExternalLink, MoreHorizontal, Star } from "lucide-react";
import { ConfirmDialog } from "@/components/data";
import { useToast } from "@/components/ui";
import { cn, pluralize } from "@/lib/format";
import { useArchiveBoard, useDuplicateBoard, useUpdateBoard } from "../api";
import type { BoardSummary } from "../types";
import { errorMessage } from "../tasks/useWorkflowConflicts";

const ITEM =
  "flex h-7 cursor-pointer select-none items-center gap-2 rounded px-2 text-xs text-fg outline-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-40 data-[highlighted]:bg-surface-3 [&>svg]:h-3.5 [&>svg]:w-3.5 [&>svg]:text-fg-muted";

export function BoardActions({ board, canWrite }: { board: BoardSummary; canWrite: boolean }) {
  const navigate = useNavigate();
  const toast = useToast();
  const duplicate = useDuplicateBoard();
  const archive = useArchiveBoard();
  const update = useUpdateBoard();
  const [confirmArchive, setConfirmArchive] = useState(false);
  const archived = board.archived_at !== null;

  const runDuplicate = () =>
    duplicate.mutate(
      { boardId: board.id },
      {
        onSuccess: (copy) => {
          toast.success(`Board duplicated as “${copy.name}”`, "Columns, gates and automation were copied; tasks were not.");
          navigate(`/work/boards/${encodeURIComponent(copy.id)}`);
        },
        onError: (e) => toast.error("Board not duplicated", errorMessage(e)),
      },
    );

  const patch = (body: { is_default?: boolean; archived?: boolean }, success: string) =>
    update.mutate({ boardId: board.id, patch: body }, { onSuccess: () => toast.success(success), onError: (e) => toast.error("Board not updated", errorMessage(e)) });

  // Stop clicks (including those inside the portalled menu and dialog) from reaching a clickable row.
  return (
    <span className="contents" onClick={(e) => e.stopPropagation()}>
      <Menu.Root>
        <Menu.Trigger asChild>
          <button
            type="button"
            aria-label={`Actions for board ${board.name}`}
            title="Board actions"
            className="inline-flex h-7 w-7 items-center justify-center rounded text-fg-faint transition-colors hover:bg-surface-3 hover:text-fg data-[state=open]:bg-surface-3"
          >
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </button>
        </Menu.Trigger>
        <Menu.Portal>
          <Menu.Content align="end" sideOffset={4} className="z-50 min-w-[190px] rounded-md border border-border-strong bg-surface p-1 shadow-pop animate-fade-in">
            <Menu.Item className={ITEM} onSelect={() => navigate(`/work/boards/${encodeURIComponent(board.id)}`)}>
              <ExternalLink aria-hidden />
              Open board
            </Menu.Item>
            {canWrite && (
              <>
                <Menu.Item className={ITEM} disabled={duplicate.isPending} onSelect={runDuplicate}>
                  <Copy aria-hidden />
                  Duplicate
                </Menu.Item>
                {!archived && !board.is_default && (
                  <Menu.Item className={ITEM} onSelect={() => patch({ is_default: true }, `“${board.name}” is now the default board`)}>
                    <Star aria-hidden />
                    Make default
                  </Menu.Item>
                )}
                <Menu.Separator className="my-1 h-px bg-border" />
                {archived ? (
                  <Menu.Item className={ITEM} onSelect={() => patch({ archived: false }, `“${board.name}” restored`)}>
                    <ArchiveRestore aria-hidden />
                    Restore
                  </Menu.Item>
                ) : (
                  <Menu.Item
                    className={cn(ITEM, "text-danger")}
                    disabled={board.is_default}
                    onSelect={() => setConfirmArchive(true)}
                    title={board.is_default ? "The default board cannot be archived. Make another board the default first." : undefined}
                  >
                    <Archive aria-hidden />
                    {board.is_default ? "Archive (default board)" : "Archive…"}
                  </Menu.Item>
                )}
              </>
            )}
          </Menu.Content>
        </Menu.Portal>
      </Menu.Root>
      <ConfirmDialog
        open={confirmArchive}
        onOpenChange={setConfirmArchive}
        destructive
        title={`Archive “${board.name}”?`}
        description="Archived boards are hidden and read-only. You can restore it later from “Show archived”."
        confirmLabel="Archive board"
        onConfirm={async () => {
          await archive.mutateAsync(board.id);
          toast.success(`“${board.name}” archived`);
        }}
      >
        {board.open_task_count > 0 && <p className="text-xs">It still has {pluralize(board.open_task_count, "open task")}. They stay on the board and reappear when it is restored.</p>}
      </ConfirmDialog>
    </span>
  );
}
