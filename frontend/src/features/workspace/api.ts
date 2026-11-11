/**
 * Engineering Workspace data hooks — boards, columns, tasks and task evidence.
 * Backend contract: backend/app/api/routes/workspace_boards.py and workspace_tasks.py.
 *
 *   GET    /workspace/boards[?include_archived]          -> Page<BoardSummary> (seeds default boards on first use)
 *   POST   /workspace/boards                             -> BoardDetail (201)
 *   GET    /workspace/boards/templates                   -> BoardTemplate[]
 *   GET    /workspace/boards/{id}                        -> BoardDetail (columns ordered, task cards per column)
 *   PATCH  /workspace/boards/{id}                        -> BoardDetail ({archived:false} restores)
 *   DELETE /workspace/boards/{id}                        -> 204 (archive; the default board cannot be archived)
 *   POST   /workspace/boards/{id}/duplicate              -> BoardDetail (201)
 *   POST   /workspace/boards/{id}/columns                -> Column (201)
 *   PATCH  /workspace/boards/{id}/columns/{cid}          -> Column
 *   DELETE /workspace/boards/{id}/columns/{cid}[?move_to&override_wip] -> ColumnDeleteResult
 *   POST   /workspace/boards/{id}/columns/reorder        -> Column[]
 *   GET    /workspace/tasks                              -> Page<TaskCard> (TaskFilters)
 *   POST   /workspace/tasks                              -> TaskDetail (201)
 *   GET    /workspace/tasks/labels | POST                -> LabelWithUsage[] | Label
 *   POST   /workspace/tasks/from-finding                 -> FromFindingResult (201 created / 200 existing)
 *   (POST /workspace/tasks/from-incident is called by features/incidents/api.ts useCreateRemediationTasks)
 *   GET|PATCH|DELETE /workspace/tasks/{id}               -> TaskDetail | TaskDetail | 204 (archive)
 *   POST   /workspace/tasks/{id}/move                    -> TaskCard (409 on WIP / verification gates)
 *   PUT    /workspace/tasks/{id}/assignees               -> Assignee[]
 *   POST   /workspace/tasks/{id}/comments, PATCH|DELETE /workspace/tasks/comments/{cid}
 *   POST   /workspace/tasks/{id}/dependencies, DELETE /workspace/tasks/dependencies/{did}
 *   POST   /workspace/tasks/{id}/refs, DELETE /workspace/tasks/refs/{rid}
 *   POST   /workspace/tasks/{id}/attachments, DELETE /workspace/tasks/attachments/{aid}
 *   POST   /workspace/tasks/{id}/links, DELETE /workspace/tasks/{id}/links/{kind}/{index} -> TaskLinks
 *   POST   /workspace/tasks/{id}/fix-attempts, PATCH /workspace/tasks/fix-attempts/{fid}
 *   POST   /workspace/tasks/{id}/verifications, POST /workspace/tasks/{id}/verify-with-simulation
 *
 * Query keys start with "workspace" so the `task.updated` live event refreshes them. Workflow gate
 * refusals (HTTP 409) can be read with `workflowConflict(error)`.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { api, ApiError, type Page } from "@/lib/api";
import type {
  Assignee,
  AssigneeInput,
  AttachmentInput,
  BoardCreateInput,
  BoardDetail,
  BoardPatch,
  BoardSummary,
  BoardTemplate,
  Column,
  ColumnDeleteResult,
  ColumnInput,
  ColumnPatch,
  DependencyKind,
  FixAttempt,
  FixAttemptInput,
  FixAttemptPatch,
  FromFindingResult,
  Label,
  LabelWithUsage,
  LinkInput,
  LinkKind,
  RefInput,
  TaskAttachment,
  TaskCard,
  TaskComment,
  TaskCreateInput,
  TaskDependency,
  TaskDetail,
  TaskFilters,
  TaskLinks,
  TaskMoveInput,
  TaskPatch,
  TaskRef,
  VerificationInput,
  VerificationRun,
  WorkflowConflict,
} from "./types";

const enc = encodeURIComponent;
const BOARDS = "/workspace/boards";
const TASKS = "/workspace/tasks";

export const workspaceKeys = {
  all: ["workspace"] as const,
  boards: ["workspace", "boards"] as const,
  boardList: (includeArchived: boolean) => ["workspace", "boards", "list", { includeArchived }] as const,
  board: (id: string) => ["workspace", "boards", "detail", id] as const,
  templates: ["workspace", "boards", "templates"] as const,
  tasks: ["workspace", "tasks"] as const,
  taskList: (filters: TaskFilters) => ["workspace", "tasks", "list", filters] as const,
  task: (id: string) => ["workspace", "tasks", "detail", id] as const,
  labels: ["workspace", "tasks", "labels"] as const,
};

const notFound = (err: unknown) => err instanceof ApiError && err.status === 404;
const retryUnlessNotFound = (count: number, err: unknown) => !notFound(err) && count < 2;

/** Server-side validation messages from a 422 envelope ({details: {errors: [...]}} or field errors). */
export function validationErrors(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.status !== 422) return [];
  const details = error.details as { errors?: unknown } | Array<{ loc?: unknown[]; msg?: string }> | null | undefined;
  if (details && !Array.isArray(details) && Array.isArray(details.errors)) return details.errors.map(String);
  if (Array.isArray(details)) return details.map((d) => `${(d.loc ?? []).slice(1).join(".") || "request"}: ${d.msg ?? "invalid"}`);
  return [error.message];
}

/**
 * A workflow gate refusal (HTTP 409): WIP limit reached, verification evidence missing, column not
 * empty, dependency or parent cycle. `message` is a plain-language explanation from the server.
 */
export function workflowConflict(error: unknown): WorkflowConflict | null {
  if (!(error instanceof ApiError) || error.status !== 409) return null;
  const details = (error.details && typeof error.details === "object" ? error.details : {}) as Record<string, unknown>;
  return { reason: typeof details.reason === "string" ? details.reason : null, message: error.message, details };
}

/** Refresh everything a single task appears in (its detail, task lists and boards). */
function invalidateTask(qc: QueryClient, taskId?: string) {
  if (taskId) void qc.invalidateQueries({ queryKey: workspaceKeys.task(taskId) });
  void qc.invalidateQueries({ queryKey: ["workspace", "tasks", "list"] });
  void qc.invalidateQueries({ queryKey: workspaceKeys.boards });
}

function invalidateBoard(qc: QueryClient, boardId?: string) {
  if (boardId) void qc.invalidateQueries({ queryKey: workspaceKeys.board(boardId) });
  void qc.invalidateQueries({ queryKey: ["workspace", "boards", "list"] });
}

// ---------------------------------------------------------------------------- boards

export function useBoardTemplates() {
  return useQuery({
    queryKey: workspaceKeys.templates,
    queryFn: () => api.get<BoardTemplate[]>(`${BOARDS}/templates`),
    staleTime: Infinity,
  });
}

export function useBoards(includeArchived = false) {
  return useQuery({
    queryKey: workspaceKeys.boardList(includeArchived),
    queryFn: () => api.get<Page<BoardSummary>>(BOARDS, { include_archived: includeArchived, limit: 500 }),
  });
}

export function useBoard(id: string | null | undefined) {
  return useQuery({
    queryKey: workspaceKeys.board(id ?? ""),
    queryFn: () => api.get<BoardDetail>(`${BOARDS}/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessNotFound,
  });
}

export function useCreateBoard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BoardCreateInput) => api.post<BoardDetail>(BOARDS, body),
    onSuccess: (board) => {
      qc.setQueryData(workspaceKeys.board(board.id), board);
      invalidateBoard(qc);
    },
  });
}

export function useUpdateBoard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, patch }: { boardId: string; patch: BoardPatch }) =>
      api.patch<BoardDetail>(`${BOARDS}/${enc(boardId)}`, patch),
    onSuccess: (board) => {
      qc.setQueryData(workspaceKeys.board(board.id), board);
      invalidateBoard(qc);
    },
  });
}

/** Archive a board (soft delete). Restore with `useUpdateBoard` and `{ archived: false }`. */
export function useArchiveBoard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (boardId: string) => api.delete<void>(`${BOARDS}/${enc(boardId)}`),
    onSuccess: (_void, boardId) => invalidateBoard(qc, boardId),
  });
}

export function useDuplicateBoard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, name }: { boardId: string; name?: string }) =>
      api.post<BoardDetail>(`${BOARDS}/${enc(boardId)}/duplicate`, name ? { name } : {}),
    onSuccess: (board) => {
      qc.setQueryData(workspaceKeys.board(board.id), board);
      invalidateBoard(qc);
    },
  });
}

// ---------------------------------------------------------------------------- columns

export function useAddColumn() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, column }: { boardId: string; column: ColumnInput }) =>
      api.post<Column>(`${BOARDS}/${enc(boardId)}/columns`, column),
    onSuccess: (_col, { boardId }) => invalidateBoard(qc, boardId),
  });
}

export function useUpdateColumn() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, columnId, patch }: { boardId: string; columnId: string; patch: ColumnPatch }) =>
      api.patch<Column>(`${BOARDS}/${enc(boardId)}/columns/${enc(columnId)}`, patch),
    onSuccess: (_col, { boardId }) => invalidateBoard(qc, boardId),
  });
}

/** Delete a column. While it holds tasks the server refuses (409 column_not_empty) unless `moveTo` is given. */
export function useDeleteColumn() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, columnId, moveTo, overrideWip }: { boardId: string; columnId: string; moveTo?: string; overrideWip?: boolean }) =>
      api.delete<ColumnDeleteResult>(
        `${BOARDS}/${enc(boardId)}/columns/${enc(columnId)}${moveTo || overrideWip ? `?${new URLSearchParams({
          ...(moveTo ? { move_to: moveTo } : {}),
          ...(overrideWip ? { override_wip: "true" } : {}),
        }).toString()}` : ""}`,
      ),
    onSuccess: (_res, { boardId }) => {
      invalidateBoard(qc, boardId);
      invalidateTask(qc);
    },
  });
}

export function useReorderColumns() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ boardId, columnIds }: { boardId: string; columnIds: string[] }) =>
      api.post<Column[]>(`${BOARDS}/${enc(boardId)}/columns/reorder`, { column_ids: columnIds }),
    onMutate: async ({ boardId, columnIds }) => {
      const key = workspaceKeys.board(boardId);
      await qc.cancelQueries({ queryKey: key });
      const previous = qc.getQueryData<BoardDetail>(key);
      if (previous) {
        const byId = new Map(previous.columns.map((c) => [c.id, c]));
        const columns = columnIds.flatMap((id, position) => {
          const col = byId.get(id);
          return col ? [{ ...col, position }] : [];
        });
        if (columns.length === previous.columns.length) qc.setQueryData<BoardDetail>(key, { ...previous, columns });
      }
      return { previous };
    },
    onError: (_err, { boardId }, ctx) => {
      if (ctx?.previous) qc.setQueryData(workspaceKeys.board(boardId), ctx.previous);
    },
    onSettled: (_cols, _err, { boardId }) => invalidateBoard(qc, boardId),
  });
}

// ---------------------------------------------------------------------------- tasks

export function useTasks(filters: TaskFilters, options: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: workspaceKeys.taskList(filters),
    queryFn: () => api.get<Page<TaskCard>>(TASKS, { ...filters }),
    placeholderData: keepPreviousData,
    enabled: options.enabled ?? true,
  });
}

export function useTask(id: string | null | undefined) {
  return useQuery({
    queryKey: workspaceKeys.task(id ?? ""),
    queryFn: () => api.get<TaskDetail>(`${TASKS}/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessNotFound,
  });
}

export function useCreateTask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TaskCreateInput) => api.post<TaskDetail>(TASKS, body),
    onSuccess: (task) => {
      qc.setQueryData(workspaceKeys.task(task.id), task);
      invalidateTask(qc);
    },
  });
}

export function useUpdateTask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ taskId, patch }: { taskId: string; patch: TaskPatch }) =>
      api.patch<TaskDetail>(`${TASKS}/${enc(taskId)}`, patch),
    onSuccess: (task) => {
      qc.setQueryData(workspaceKeys.task(task.id), task);
      invalidateTask(qc);
    },
  });
}

/** Archive a task (soft delete). Restore with `useUpdateTask` and `{ archived: false }`. */
export function useArchiveTask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (taskId: string) => api.delete<void>(`${TASKS}/${enc(taskId)}`),
    onSuccess: (_void, taskId) => invalidateTask(qc, taskId),
  });
}

/** Optimistically move a card on a cached board; returns the previous board for rollback. */
function moveCardInCache(qc: QueryClient, boardId: string, taskId: string, input: TaskMoveInput) {
  const key = workspaceKeys.board(boardId);
  const previous = qc.getQueryData<BoardDetail>(key);
  if (!previous) return undefined;
  const source = previous.columns.find((c) => c.tasks.some((t) => t.id === taskId));
  const target = previous.columns.find((c) => c.id === input.column_id);
  const card = source?.tasks.find((t) => t.id === taskId);
  if (!source || !target || !card) return previous;
  const moved: TaskCard = {
    ...card,
    column_id: target.id,
    column_name: target.name,
    status_key: target.status_key,
    is_done: target.is_done_column,
  };
  const columns = previous.columns.map((col) => {
    let tasks = col.tasks.filter((t) => t.id !== taskId);
    if (col.id === target.id) {
      const at = input.position === undefined ? tasks.length : Math.max(0, Math.min(input.position, tasks.length));
      tasks = [...tasks.slice(0, at), moved, ...tasks.slice(at)];
    }
    tasks = tasks.map((t, position) => ({ ...t, position }));
    const task_count = tasks.length;
    return { ...col, tasks, task_count, wip_exceeded: col.wip_limit !== null && task_count > col.wip_limit };
  });
  qc.setQueryData<BoardDetail>(key, { ...previous, columns });
  return previous;
}

/**
 * Move a task to a column (drag and drop). Pass `boardId` to update the cached board optimistically;
 * a gate refusal (409) rolls the board back — read it with `workflowConflict(error)`.
 */
export function useMoveTask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ taskId, ...input }: { taskId: string; boardId?: string } & TaskMoveInput) =>
      api.post<TaskCard>(`${TASKS}/${enc(taskId)}/move`, {
        column_id: input.column_id,
        position: input.position,
        override_wip: input.override_wip ?? false,
      }),
    onMutate: async ({ taskId, boardId, ...input }) => {
      if (!boardId) return { previous: undefined as BoardDetail | undefined };
      await qc.cancelQueries({ queryKey: workspaceKeys.board(boardId) });
      return { previous: moveCardInCache(qc, boardId, taskId, input) };
    },
    onError: (_err, { boardId }, ctx) => {
      if (boardId && ctx?.previous) qc.setQueryData(workspaceKeys.board(boardId), ctx.previous);
    },
    onSettled: (_card, _err, { taskId }) => invalidateTask(qc, taskId),
  });
}

/** Create (or return the existing open) remediation task for a finding. `created` is false when it existed. */
export function useCreateTaskFromFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { finding_id: string; board_id?: string }) => api.post<FromFindingResult>(`${TASKS}/from-finding`, body),
    onSuccess: (result) => {
      qc.setQueryData(workspaceKeys.task(result.task.id), result.task);
      invalidateTask(qc);
      void qc.invalidateQueries({ queryKey: ["workspace", "remediation"] });
    },
  });
}

// ---------------------------------------------------------------------------- labels & assignees

export function useLabels() {
  return useQuery({ queryKey: workspaceKeys.labels, queryFn: () => api.get<LabelWithUsage[]>(`${TASKS}/labels`) });
}

export function useCreateLabel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; color?: string }) => api.post<Label>(`${TASKS}/labels`, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: workspaceKeys.labels }),
  });
}

export function useSetAssignees() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ taskId, assignees }: { taskId: string; assignees: AssigneeInput[] }) =>
      api.put<Assignee[]>(`${TASKS}/${enc(taskId)}/assignees`, { assignees }),
    onSuccess: (_a, { taskId }) => invalidateTask(qc, taskId),
  });
}

// ---------------------------------------------------------------------------- task sub-resources

/** Mutation on a task sub-resource; refreshes the task, task lists and boards on success. */
function useTaskMutation<TVars extends { taskId: string }, TResult>(fn: (vars: TVars) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: (_r: TResult, vars: TVars) => invalidateTask(qc, vars.taskId) });
}

export const useAddComment = () =>
  useTaskMutation(({ taskId, body }: { taskId: string; body: string }) =>
    api.post<TaskComment>(`${TASKS}/${enc(taskId)}/comments`, { body }));

/** Only the author can edit a comment (403 otherwise). */
export const useEditComment = () =>
  useTaskMutation(({ commentId, body }: { taskId: string; commentId: string; body: string }) =>
    api.patch<TaskComment>(`${TASKS}/comments/${enc(commentId)}`, { body }));

/** The author or an organisation admin can delete a comment. */
export const useDeleteComment = () =>
  useTaskMutation(({ commentId }: { taskId: string; commentId: string }) =>
    api.delete<void>(`${TASKS}/comments/${enc(commentId)}`));

/** `taskId` depends on `dependsOnTaskId`. "blocks" dependencies that would form a cycle are refused (409). */
export const useAddDependency = () =>
  useTaskMutation(({ taskId, dependsOnTaskId, kind = "blocks" }: { taskId: string; dependsOnTaskId: string; kind?: DependencyKind }) =>
    api.post<TaskDependency>(`${TASKS}/${enc(taskId)}/dependencies`, { depends_on_task_id: dependsOnTaskId, kind }));

export const useRemoveDependency = () =>
  useTaskMutation(({ dependencyId }: { taskId: string; dependencyId: string }) =>
    api.delete<void>(`${TASKS}/dependencies/${enc(dependencyId)}`));

/** Reference a recorded security record (must exist in the organisation; 404 otherwise). */
export const useAddRef = () =>
  useTaskMutation(({ taskId, ...ref }: { taskId: string } & RefInput) => api.post<TaskRef>(`${TASKS}/${enc(taskId)}/refs`, ref));

export const useRemoveRef = () =>
  useTaskMutation(({ refId }: { taskId: string; refId: string }) => api.delete<void>(`${TASKS}/refs/${enc(refId)}`));

/** Attach a log, stack trace, note or link. Content is redacted server-side and capped at 100 KB (413). */
export const useAddAttachment = () =>
  useTaskMutation(({ taskId, ...attachment }: { taskId: string } & AttachmentInput) =>
    api.post<TaskAttachment>(`${TASKS}/${enc(taskId)}/attachments`, attachment));

export const useDeleteAttachment = () =>
  useTaskMutation(({ attachmentId }: { taskId: string; attachmentId: string }) =>
    api.delete<void>(`${TASKS}/attachments/${enc(attachmentId)}`));

/** Link a branch, commit, pull request or deployment. Linking a PR fires the column's `pr_linked` automation. */
export const useAddLink = () =>
  useTaskMutation(({ taskId, ...link }: { taskId: string } & LinkInput) => api.post<TaskLinks>(`${TASKS}/${enc(taskId)}/links`, link));

export const useRemoveLink = () =>
  useTaskMutation(({ taskId, kind, index }: { taskId: string; kind: LinkKind; index: number }) =>
    api.delete<TaskLinks>(`${TASKS}/${enc(taskId)}/links/${enc(kind)}/${index}`));

/** Record a fix attempt. `claimed_complete` is a claim only; it never verifies the task. */
export const useCreateFixAttempt = () =>
  useTaskMutation(({ taskId, ...attempt }: { taskId: string } & FixAttemptInput) =>
    api.post<FixAttempt>(`${TASKS}/${enc(taskId)}/fix-attempts`, attempt));

export const useUpdateFixAttempt = () =>
  useTaskMutation(({ attemptId, patch }: { taskId: string; attemptId: string; patch: FixAttemptPatch }) =>
    api.patch<FixAttempt>(`${TASKS}/fix-attempts/${enc(attemptId)}`, patch));

/** Record verification evidence. The task's verification status changes only through these runs. */
export const useRecordVerification = () =>
  useTaskMutation(({ taskId, ...run }: { taskId: string } & VerificationInput) =>
    api.post<VerificationRun>(`${TASKS}/${enc(taskId)}/verifications`, run));

/** Run a Simulation Lab scenario through the real pipeline and record it as verification (503 if unavailable). */
export const useVerifyWithSimulation = () =>
  useTaskMutation(({ taskId, scenarioId, fixAttemptId }: { taskId: string; scenarioId: string; fixAttemptId?: string }) =>
    api.post<VerificationRun>(`${TASKS}/${enc(taskId)}/verify-with-simulation`, {
      scenario_id: scenarioId,
      ...(fixAttemptId ? { fix_attempt_id: fixAttemptId } : {}),
    }));
