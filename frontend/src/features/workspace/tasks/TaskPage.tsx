/**
 * Task page (/work/tasks/:taskId) — "what is this work, what evidence is it about, and is the fix
 * proven?". Same content as the board drawer, full width, with a link back to the board.
 */
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, SquareCheck } from "lucide-react";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui";
import { useDocumentTitle } from "@/hooks";
import { ApiError } from "@/lib/api";
import { useTask } from "../api";
import { TaskDetailView } from "./TaskDetailView";

export function TaskPage() {
  const { taskId = "" } = useParams();
  const task = useTask(taskId);
  useDocumentTitle(task.data ? `${task.data.key} ${task.data.title}` : null);

  if (task.isLoading) return <LoadingRows rows={10} />;
  if (task.error instanceof ApiError && task.error.status === 404) {
    return (
      <EmptyState
        icon={<SquareCheck className="h-5 w-5" aria-hidden />}
        title="Task not found"
        description="It may belong to another organisation, or the link is wrong."
        action={
          <Link to="/work/tasks" className="text-xs text-accent hover:underline">
            Back to all tasks
          </Link>
        }
      />
    );
  }
  if (task.error || !task.data) return <ErrorState error={task.error} onRetry={() => void task.refetch()} />;

  const data = task.data;
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-3 flex items-center gap-1.5 text-xs text-fg-muted">
        <Link to={`/work/boards/${encodeURIComponent(data.board_id)}`} className="inline-flex items-center gap-1 hover:text-fg">
          <ArrowLeft className="h-3 w-3" aria-hidden />
          {data.board_name}
        </Link>
        <span aria-hidden>/</span>
        <span className="font-mono text-fg">{data.key}</span>
      </nav>
      <TaskDetailView task={data} variant="page" />
    </>
  );
}
