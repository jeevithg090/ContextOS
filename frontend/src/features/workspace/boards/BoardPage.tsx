/**
 * Kanban board (/work/boards/:boardId) — "where is every piece of work on this board, and what is
 * stopping it from moving?". Columns, drag and drop, filters (kept in the URL), column and board
 * configuration, and the task drawer (?task=<id>, deep-linkable).
 */
import { useCallback, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArchiveRestore, ArrowLeft, KanbanSquare, Plus, Settings2 } from "lucide-react";
import { InlineStat } from "@/components/data";
import { Badge, Button, EmptyState, ErrorState, PageHeader, Skeleton, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { useMembers } from "@/features/settings/api";
import { useDocumentTitle } from "@/hooks";
import { ApiError } from "@/lib/api";
import { pluralize } from "@/lib/format";
import { useBoard, useLabels, useUpdateBoard } from "../api";
import { CreateTaskDialog } from "../analytics/CreateTaskDialog";
import { oneOf, useUrlState } from "../analytics/useUrlState";
import { TaskDrawer } from "../tasks/TaskDrawer";
import { errorMessage, useWorkflowConflicts } from "../tasks/useWorkflowConflicts";
import { TASK_PRIORITIES, TASK_TYPES, type Column } from "../types";
import { BoardFilters } from "./BoardFilters";
import { BoardSettingsDialog } from "./BoardSettingsDialog";
import { ColumnSettingsDialog } from "./ColumnSettingsDialog";
import { DeleteColumnDialog } from "./DeleteColumnDialog";
import { KanbanBoard } from "./KanbanBoard";
import { EMPTY_FILTERS, templateLabel, type BoardFilterState } from "./boardMeta";

type ColumnDialog = { kind: "add" } | { kind: "edit"; column: Column } | { kind: "delete"; column: Column } | null;

function BoardSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading board">
      <Skeleton className="mb-2 h-4 w-32" />
      <Skeleton className="mb-6 h-7 w-72" />
      <div className="flex gap-3 overflow-hidden">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="w-[288px] shrink-0 space-y-2 rounded-lg border border-border p-2">
            <Skeleton className="h-5 w-24" />
            {Array.from({ length: 3 - (i % 2) }).map((__, j) => (
              <Skeleton key={j} className="h-20 w-full" />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function BoardPage() {
  const { boardId = "" } = useParams();
  const { me, can } = useAuth();
  const toast = useToast();
  const board = useBoard(boardId);
  useDocumentTitle(board.data?.name);
  const labels = useLabels();
  const members = useMembers();
  const restore = useUpdateBoard();
  const { get, set, params } = useUrlState();
  const { report, dialog: conflictDialog } = useWorkflowConflicts();
  const [columnDialog, setColumnDialog] = useState<ColumnDialog>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [creating, setCreating] = useState(false);

  const filters: BoardFilterState = {
    q: get("q"),
    assignee: get("assignee"),
    label: get("label"),
    priority: oneOf(get("priority"), TASK_PRIORITIES) ?? "",
    type: oneOf(get("type"), TASK_TYPES) ?? "",
  };
  const taskId = params.get("task");
  const openTask = useCallback((id: string) => set({ task: id }), [set]);
  const memberOptions = useMemo(() => (members.data?.items ?? []).filter((m) => m.is_active).map((m) => ({ user_id: m.user_id, name: m.name })), [members.data]);

  if (board.isLoading) return <BoardSkeleton />;
  if (board.error instanceof ApiError && board.error.status === 404) {
    return (
      <EmptyState
        icon={<KanbanSquare className="h-5 w-5" aria-hidden />}
        title="Board not found"
        description="It may belong to another organisation, or the link is wrong."
        action={
          <Link to="/work/boards" className="text-xs text-accent hover:underline">
            Back to boards
          </Link>
        }
      />
    );
  }
  if (board.error || !board.data) return <ErrorState error={board.error} onRetry={() => void board.refetch()} />;

  const data = board.data;
  const archived = data.archived_at !== null;
  const canWrite = can("write") && !archived;
  const columns = [...data.columns].sort((a, b) => a.position - b.position);

  return (
    <div className="flex flex-col">
      <PageHeader
        eyebrow={
          <Link to="/work/boards" className="inline-flex items-center gap-1 hover:text-fg">
            <ArrowLeft className="h-3 w-3" aria-hidden />
            Kanban boards
          </Link>
        }
        title={
          <span className="inline-flex items-center gap-2">
            {data.name}
            {data.is_default && <Badge tone="accent">Default</Badge>}
            {archived && <Badge tone="warn">Archived</Badge>}
          </span>
        }
        description={data.description || undefined}
        actions={
          can("write") && !archived ? (
            <>
              <Button size="sm" variant="ghost" icon={<Settings2 className="h-3.5 w-3.5" aria-hidden />} onClick={() => setSettingsOpen(true)}>
                Board settings
              </Button>
              <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
                New task
              </Button>
            </>
          ) : undefined
        }
      />

      <div className="-mt-2 mb-3 flex flex-wrap items-center gap-x-5 gap-y-1">
        <InlineStat label="Template" value={templateLabel(data.template)} />
        <InlineStat label="Open" value={data.open_task_count} hint="Tasks not in a done column" />
        <InlineStat label="Total" value={data.task_count} hint="Non-archived tasks on this board" />
        <InlineStat label="Columns" value={data.column_count} />
      </div>

      {archived && (
        <div role="status" className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-fg">
          <span>This board is archived. Tasks cannot be moved or added until it is restored.</span>
          {can("write") && (
            <Button
              size="xs"
              variant="outline"
              icon={<ArchiveRestore className="h-3 w-3" aria-hidden />}
              loading={restore.isPending}
              onClick={() =>
                restore.mutate(
                  { boardId: data.id, patch: { archived: false } },
                  { onSuccess: () => toast.success("Board restored"), onError: (e) => toast.error("Board not restored", errorMessage(e)) },
                )
              }
            >
              Restore board
            </Button>
          )}
        </div>
      )}

      <BoardFilters
        value={filters}
        onChange={(patch) => set(patch)}
        onClear={() => set({ ...Object.fromEntries(Object.keys(EMPTY_FILTERS).map((k) => [k, null])) })}
        members={memberOptions}
        labels={labels.data ?? []}
        actions={<span className="text-2xs text-fg-faint">{pluralize(data.task_count, "task")}</span>}
      />

      <div style={{ height: "calc(100vh - 250px)" }} className="min-h-[440px]">
        {columns.length === 0 ? (
          <EmptyState title="This board has no columns" description="Add a column to start placing work on it." action={canWrite ? <Button size="sm" onClick={() => setColumnDialog({ kind: "add" })}>Add column</Button> : undefined} />
        ) : (
          <KanbanBoard
            board={data}
            filters={filters}
            meId={me?.user.id ?? null}
            canWrite={canWrite}
            onOpenTask={openTask}
            onAddColumn={() => setColumnDialog({ kind: "add" })}
            onEditColumn={(column) => setColumnDialog({ kind: "edit", column })}
            onDeleteColumn={(column) => setColumnDialog({ kind: "delete", column })}
            report={report}
          />
        )}
      </div>

      {columnDialog?.kind === "add" && (
        <ColumnSettingsDialog
          boardId={data.id}
          column={null}
          columns={columns}
          onClose={() => setColumnDialog(null)}
          onSaved={(name) => toast.success(`Column “${name}” added`)}
        />
      )}
      {columnDialog?.kind === "edit" && (
        <ColumnSettingsDialog
          boardId={data.id}
          column={columnDialog.column}
          columns={columns}
          onClose={() => setColumnDialog(null)}
          onSaved={(name) => toast.success(`Column “${name}” saved`)}
        />
      )}
      {columnDialog?.kind === "delete" && <DeleteColumnDialog boardId={data.id} column={columnDialog.column} columns={columns} onClose={() => setColumnDialog(null)} />}
      {settingsOpen && <BoardSettingsDialog board={data} onClose={() => setSettingsOpen(false)} />}
      <CreateTaskDialog open={creating} onOpenChange={setCreating} boardId={data.id} onCreated={openTask} />
      <TaskDrawer taskId={taskId} onClose={() => set({ task: null })} />
      {conflictDialog}
    </div>
  );
}
