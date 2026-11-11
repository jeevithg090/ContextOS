import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeftRight, ExternalLink, SearchX } from "lucide-react";
import { Button, EmptyState, ErrorState, LoadingRows, PageHeader, SeverityBadge, Skeleton } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useTask } from "../api";
import { PriorityBadge, taskTypeLabel } from "../analytics/taskMeta";
import type { TaskDetail } from "../types";
import { useAiCatalogue, useContextPack, usePrompt, useTemplates } from "./api";
import { PrivacyNote } from "./controls";
import { mutationMessage } from "./hooks";
import { FixContextWorkspace } from "./FixContextWorkspace";
import { TaskPicker } from "./TaskPicker";
import { initialFixState } from "./useFixContextState";

const is404 = (err: unknown) => err instanceof ApiError && err.status === 404;

function TaskStrip({ task }: { task: TaskDetail }) {
  return (
    <div className="panel mb-4 flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
      <span className="font-mono text-xs text-fg-muted">{task.key}</span>
      <h2 className="min-w-0 max-w-full truncate text-[14px] font-semibold text-fg" title={task.title}>
        {task.title}
      </h2>
      {task.severity && (
        <span className="inline-flex items-center gap-1 text-2xs text-fg-faint">
          Severity <SeverityBadge severity={task.severity} />
        </span>
      )}
      <span className="inline-flex items-center gap-1 text-2xs text-fg-faint">
        Priority <PriorityBadge priority={task.priority} />
      </span>
      <span className="text-xs text-fg-muted">
        {taskTypeLabel(task.task_type)} · {task.column_name}
        {task.is_done ? " · done" : ""}
      </span>
      <div className="ml-auto flex items-center gap-1.5">
        <Link to={`/work/tasks/${encodeURIComponent(task.id)}`} className="inline-flex h-7 items-center gap-1.5 rounded px-2 text-xs text-fg-muted hover:bg-surface-2 hover:text-fg">
          <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          Open task
        </Link>
        <Link to="/work/fix-context" className="inline-flex h-7 items-center gap-1.5 rounded px-2 text-xs text-fg-muted hover:bg-surface-2 hover:text-fg">
          <ArrowLeftRight className="h-3.5 w-3.5" aria-hidden />
          Change task
        </Link>
      </div>
    </div>
  );
}

interface Bootstrap {
  key: number;
  promptId: string | null;
  templateId: string | null;
  packId: string | null;
}

/** Loads everything the workspace starts from (task, catalogue, templates and URL-requested records). */
function FixContextLoader({ taskId }: { taskId: string }) {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const promptParam = params.get("prompt");
  const ownPrompt = useRef<string | null>(promptParam);
  const [boot, setBoot] = useState<Bootstrap>(() => ({ key: 0, promptId: promptParam, templateId: params.get("template"), packId: params.get("pack") }));

  // The URL's prompt changed from outside the workspace (history navigation): start over from it.
  useEffect(() => {
    if (promptParam !== ownPrompt.current) {
      ownPrompt.current = promptParam;
      setBoot((b) => ({ key: b.key + 1, promptId: promptParam, templateId: null, packId: null }));
    }
  }, [promptParam]);

  const catalogue = useAiCatalogue();
  const task = useTask(taskId);
  const templates = useTemplates();
  const prompt = usePrompt(boot.promptId);
  const packId = boot.packId ?? prompt.data?.context_pack_id ?? null;
  const pack = useContextPack(packId);

  // A saved prompt opened under the wrong task URL: go to its own task.
  const promptTask = prompt.data?.task_id;
  useEffect(() => {
    if (promptTask && promptTask !== taskId) navigate(`/work/fix-context/${encodeURIComponent(promptTask)}?prompt=${encodeURIComponent(prompt.data!.id)}`, { replace: true });
  }, [promptTask, taskId, navigate, prompt.data]);

  const onPromptChange = useCallback(
    (id: string | null) => {
      ownPrompt.current = id;
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (id) next.set("prompt", id);
          else next.delete("prompt");
          next.delete("template");
          next.delete("pack");
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  const waitingPrompt = !!boot.promptId && prompt.isLoading;
  const waitingPack = !!packId && pack.isLoading;
  const ready = !!catalogue.data && !!task.data && !templates.isLoading && !waitingPrompt && !waitingPack;
  const wrongTask = !!promptTask && promptTask !== taskId;

  const initial = useMemo(() => {
    if (!ready || !catalogue.data || !task.data) return null;
    const templateList = templates.data ?? [];
    return initialFixState({
      catalogue: catalogue.data,
      task: task.data,
      prompt: prompt.data && prompt.data.task_id === taskId ? prompt.data : null,
      template: boot.templateId ? templateList.find((t) => t.id === boot.templateId) ?? null : null,
      pack: pack.data ?? null,
      templates: templateList,
    });
    // Computed once per bootstrap; later query updates must not reset the user's work.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, boot.key]);

  if (catalogue.error) return <ErrorState error={catalogue.error} onRetry={() => void catalogue.refetch()} className="panel" />;
  if (task.error) {
    return is404(task.error) ? (
      <EmptyState
        className="panel"
        icon={<SearchX className="h-4 w-4" />}
        title="Task not found"
        description="It may have been deleted, or it belongs to another organisation."
        action={
          <Button size="sm" variant="primary" onClick={() => navigate("/work/fix-context")}>
            Choose a task
          </Button>
        }
      />
    ) : (
      <ErrorState error={task.error} onRetry={() => void task.refetch()} className="panel" />
    );
  }

  const notices: string[] = [];
  if (boot.promptId && prompt.error) notices.push(is404(prompt.error) ? "The saved prompt in the link no longer exists; starting from the default settings." : `The saved prompt could not be loaded: ${mutationMessage(prompt.error)}`);
  if (prompt.data && !prompt.data.task_id) notices.push("The task this saved prompt was generated for no longer exists.");
  if (packId && pack.error) notices.push(is404(pack.error) ? "The context pack it used has been deleted; generation will build a fresh one." : `The context pack could not be loaded: ${mutationMessage(pack.error)}`);
  if (pack.data && pack.data.task_id !== taskId) notices.push("The context pack in the link was built for a different task, so it is not used here.");
  if (boot.templateId && templates.data && !templates.data.some((t) => t.id === boot.templateId)) notices.push("The template in the link no longer exists.");

  return (
    <>
      {task.data ? <TaskStrip task={task.data} /> : <Skeleton className="mb-4 h-12 w-full" />}
      {notices.map((n) => (
        <p key={n} role="status" className="mb-3 rounded-md border border-warn/30 bg-warn/[0.07] px-3 py-2 text-xs text-fg">
          {n}
        </p>
      ))}
      {!initial || wrongTask || !task.data || !catalogue.data ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(360px,420px)_minmax(0,1fr)]">
          <div className="panel">
            <LoadingRows rows={8} />
          </div>
          <div className="panel">
            <LoadingRows rows={6} />
          </div>
        </div>
      ) : (
        <FixContextWorkspace key={`${taskId}:${boot.key}`} task={task.data} catalogue={catalogue.data} initial={initial} onPromptChange={onPromptChange} />
      )}
    </>
  );
}

/**
 * "Give a coding agent everything it needs to fix this." Pick a task, choose how the agent should
 * work, inspect the context pack, generate and refine the prompt, then copy it into the agent.
 */
export function FixContextPage() {
  const { taskId } = useParams();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const catalogue = useAiCatalogue();
  const template = params.get("template");

  return (
    <>
      <PageHeader
        eyebrow="Engineering Workspace"
        title="AI Fix Context"
        description="Turn a task and its recorded evidence into a precise prompt for a coding agent. Facts, evidence and hypotheses are kept apart, and every file reference says whether it was verified."
        actions={
          <Link to="/work/prompts" className="inline-flex h-8 items-center rounded border border-border-strong px-3 text-[13px] text-fg hover:bg-surface-2">
            Prompt Library
          </Link>
        }
      />
      <PrivacyNote detail={catalogue.data?.privacy_note} className="mb-4" />
      {taskId ? (
        <FixContextLoader taskId={taskId} />
      ) : (
        <section className="panel p-4" aria-labelledby="fix-context-pick">
          <h2 id="fix-context-pick" className="text-[13px] font-semibold text-fg">
            Choose a task
          </h2>
          <p className="mb-3 mt-0.5 text-xs text-fg-muted">The prompt is built from this task’s description, acceptance criteria, linked findings and incidents, and related files.</p>
          <TaskPicker autoFocus onSelect={(t) => navigate(`/work/fix-context/${encodeURIComponent(t.id)}${template ? `?template=${encodeURIComponent(template)}` : ""}`)} listClassName="max-h-[60vh]" />
        </section>
      )}
    </>
  );
}
