/** Task side panel opened from a board card (deep-linkable through `?task=<id>`). */
import { Link } from "react-router-dom";
import { Maximize2, SquareCheck } from "lucide-react";
import { Drawer, EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useTask } from "../api";
import { TaskDetailView } from "./TaskDetailView";

export function TaskDrawer({ taskId, onClose }: { taskId: string | null; onClose: () => void }) {
  const task = useTask(taskId);
  const notFound = task.error instanceof ApiError && task.error.status === 404;

  return (
    <Drawer
      open={!!taskId}
      onOpenChange={(open) => !open && onClose()}
      width="w-[min(1040px,100vw)]"
      title={task.data ? <span className="font-mono">{task.data.key}</span> : "Task"}
      subtitle={task.data ? `${task.data.board_name} · ${task.data.column_name}` : undefined}
      actions={
        taskId ? (
          <Link
            to={`/work/tasks/${encodeURIComponent(taskId)}`}
            className="inline-flex h-7 items-center gap-1.5 rounded px-2 text-xs text-fg-muted hover:bg-surface-2 hover:text-fg"
            title="Open as a full page"
          >
            <Maximize2 className="h-3.5 w-3.5" aria-hidden />
            Full page
          </Link>
        ) : undefined
      }
    >
      {task.isLoading ? (
        <LoadingRows rows={8} />
      ) : notFound ? (
        <EmptyState icon={<SquareCheck className="h-5 w-5" aria-hidden />} title="Task not found" description="It may have been removed, belong to another organisation, or the link is wrong." />
      ) : task.error || !task.data ? (
        <ErrorState error={task.error} onRetry={() => void task.refetch()} />
      ) : (
        <TaskDetailView task={task.data} variant="drawer" />
      )}
    </Drawer>
  );
}
