/**
 * Engineering Workspace AI data hooks — context packs, fix-context prompts, templates and breakdown.
 * Backend contract: backend/app/api/routes/workspace_ai.py (all under /api/v1/workspace/ai).
 *
 *   GET    /modes[?task_id=]                        -> AiCatalogue (modes, presets, profiles, options, sections;
 *                                                     with task_id also the suggested pack profile per mode)
 *   POST   /context-packs                           -> ContextPack (201)
 *   GET    /context-packs[?task_id]                 -> Page<ContextPackSummary>
 *   GET    /context-packs/{id}                      -> ContextPack
 *   PATCH  /context-packs/{id}  {items:[{key,included}]} -> ContextPack (token estimate recomputed)
 *   DELETE /context-packs/{id}                      -> 204
 *   GET    /context-packs/{id}/export               -> JSON attachment (re-redacted; audited) — hooks.useExportContextPack
 *   POST   /fix-context                             -> FixContextResult (200 preview / 201 when save=true)
 *   GET    /prompts[?task_id]                       -> Page<PromptSummary>
 *   GET    /prompts/{id}                            -> SavedPrompt
 *   PATCH  /prompts/{id}                            -> SavedPrompt (version + 1; 422 with details.errors if invalid)
 *   POST   /prompts/{id}/regenerate-section         -> SavedPrompt (section rebuilt from current records)
 *   GET    /prompts/{id}/export?format=markdown|json -> attachment
 *   GET    /templates, POST /templates, GET|PATCH|DELETE /templates/{id} (built-ins are read-only: 409)
 *   POST   /breakdown                               -> BreakdownResult (drafts only; nothing is created)
 *   POST   /breakdown/apply                         -> BreakdownApplyResult (201; 422 on a dependency cycle)
 *
 * Nothing is sent to an external AI provider; every response carries `external_transfer: false`.
 * Query keys start with ["workspace", "ai"] so the `task.updated` live event refreshes them.
 * Use `validationErrors` / `workflowConflict` from "../api" to read 422 / 409 refusals.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { api, ApiError, downloadFile, type Page } from "@/lib/api";
import { workspaceKeys } from "../api";
import type {
  AiCatalogue,
  BreakdownApplyInput,
  BreakdownApplyResult,
  BreakdownResult,
  ContextPack,
  ContextPackCreateInput,
  ContextPackSummary,
  ExportFormat,
  FixContextInput,
  FixContextResult,
  PackItemToggle,
  PromptPatch,
  PromptSummary,
  PromptTemplate,
  SavedPrompt,
  TemplateInput,
  TemplatePatch,
} from "./types";

const enc = encodeURIComponent;
const AI = "/workspace/ai";

export interface AiListFilters {
  taskId?: string;
  limit?: number;
  offset?: number;
}

export const workspaceAiKeys = {
  all: ["workspace", "ai"] as const,
  catalogue: ["workspace", "ai", "modes"] as const,
  templates: ["workspace", "ai", "templates"] as const,
  template: (id: string) => ["workspace", "ai", "templates", id] as const,
  packs: ["workspace", "ai", "packs"] as const,
  packList: (filters: AiListFilters) => ["workspace", "ai", "packs", "list", filters] as const,
  pack: (id: string) => ["workspace", "ai", "packs", "detail", id] as const,
  prompts: ["workspace", "ai", "prompts"] as const,
  promptList: (filters: AiListFilters) => ["workspace", "ai", "prompts", "list", filters] as const,
  prompt: (id: string) => ["workspace", "ai", "prompts", "detail", id] as const,
};

const notFound = (err: unknown) => err instanceof ApiError && err.status === 404;
const retryUnlessNotFound = (count: number, err: unknown) => !notFound(err) && count < 2;

const listQuery = ({ taskId, limit = 50, offset = 0 }: AiListFilters) => ({ task_id: taskId, limit, offset });

/** Saving prompts/packs or applying a breakdown writes task activity: refresh the task too. */
function invalidateTaskActivity(qc: QueryClient, taskId: string | null | undefined) {
  if (taskId) void qc.invalidateQueries({ queryKey: workspaceKeys.task(taskId) });
}

// ---------------------------------------------------------------------------- catalogue

/**
 * The generation catalogue. With a task id it also carries the context-pack profile the server picks
 * for that task in each mode (`suggested_profiles`), so the UI never re-implements that rule.
 */
export function useAiCatalogue(taskId?: string | null) {
  return useQuery({
    queryKey: taskId ? [...workspaceAiKeys.catalogue, "task", taskId] : workspaceAiKeys.catalogue,
    queryFn: () => api.get<AiCatalogue>(`${AI}/modes`, { task_id: taskId ?? undefined }),
    staleTime: 5 * 60_000,
    retry: retryUnlessNotFound,
  });
}

// ---------------------------------------------------------------------------- context packs

export function useContextPacks(filters: AiListFilters = {}) {
  return useQuery({
    queryKey: workspaceAiKeys.packList(filters),
    queryFn: () => api.get<Page<ContextPackSummary>>(`${AI}/context-packs`, listQuery(filters)),
    placeholderData: keepPreviousData,
    retry: retryUnlessNotFound,
  });
}

export function useContextPack(id: string | null | undefined) {
  return useQuery({
    queryKey: workspaceAiKeys.pack(id ?? ""),
    queryFn: () => api.get<ContextPack>(`${AI}/context-packs/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessNotFound,
  });
}

export function useCreateContextPack() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ContextPackCreateInput) => api.post<ContextPack>(`${AI}/context-packs`, body),
    onSuccess: (pack) => {
      qc.setQueryData(workspaceAiKeys.pack(pack.id), pack);
      void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.packs, "list"] });
      invalidateTaskActivity(qc, pack.task_id);
    },
  });
}

/** Include or exclude pack items. Sensitive, unverified or missing items are refused with HTTP 422. */
export function useToggleContextPackItems() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ packId, items }: { packId: string; items: PackItemToggle[] }) =>
      api.patch<ContextPack>(`${AI}/context-packs/${enc(packId)}`, { items }),
    onSuccess: (pack) => {
      qc.setQueryData(workspaceAiKeys.pack(pack.id), pack);
      void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.packs, "list"] });
    },
  });
}

export function useDeleteContextPack() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ packId }: { packId: string; taskId?: string | null }) =>
      api.delete<void>(`${AI}/context-packs/${enc(packId)}`),
    onSuccess: (_void, { packId, taskId }) => {
      qc.removeQueries({ queryKey: workspaceAiKeys.pack(packId) });
      void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.packs, "list"] });
      invalidateTaskActivity(qc, taskId);
    },
  });
}

// ---------------------------------------------------------------------------- fix context & prompts

/** Generate a fix-context prompt. With `save: true` the prompt and its context pack are stored. */
export function useGenerateFixContext() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: FixContextInput) => api.post<FixContextResult>(`${AI}/fix-context`, body),
    onSuccess: (result) => {
      if (!result.saved) return;
      void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.prompts, "list"] });
      void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.packs, "list"] });
      invalidateTaskActivity(qc, result.task_id);
    },
  });
}

export function usePrompts(filters: AiListFilters = {}) {
  return useQuery({
    queryKey: workspaceAiKeys.promptList(filters),
    queryFn: () => api.get<Page<PromptSummary>>(`${AI}/prompts`, listQuery(filters)),
    placeholderData: keepPreviousData,
    retry: retryUnlessNotFound,
  });
}

export function usePrompt(id: string | null | undefined) {
  return useQuery({
    queryKey: workspaceAiKeys.prompt(id ?? ""),
    queryFn: () => api.get<SavedPrompt>(`${AI}/prompts/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessNotFound,
  });
}

function storePrompt(qc: QueryClient, prompt: SavedPrompt) {
  qc.setQueryData(workspaceAiKeys.prompt(prompt.id), prompt);
  void qc.invalidateQueries({ queryKey: [...workspaceAiKeys.prompts, "list"] });
  invalidateTaskActivity(qc, prompt.task_id);
}

/** Edit sections (content or removal), extra instructions or options. Each successful edit is a new version. */
export function useUpdatePrompt() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ promptId, patch }: { promptId: string; patch: PromptPatch }) =>
      api.patch<SavedPrompt>(`${AI}/prompts/${enc(promptId)}`, patch),
    onSuccess: (prompt) => storePrompt(qc, prompt),
  });
}

/** Rebuild one section from current records (also restores a removed section). */
export function useRegenerateSection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ promptId, sectionKey }: { promptId: string; sectionKey: string }) =>
      api.post<SavedPrompt>(`${AI}/prompts/${enc(promptId)}/regenerate-section`, { section_key: sectionKey }),
    onSuccess: (prompt) => storePrompt(qc, prompt),
  });
}

/** Filename the server uses in Content-Disposition for an export. */
export function exportFilename(prompt: Pick<PromptSummary, "task_key" | "mode" | "version">, format: ExportFormat) {
  const stem = `${prompt.task_key ?? "prompt"}-${prompt.mode}-v${prompt.version}`.replace(/[^A-Za-z0-9._-]+/g, "_");
  return `${stem}.${format === "markdown" ? "md" : "json"}`;
}

/** Download a saved prompt as Markdown or as the structured JSON export (sections + context pack). */
export function useExportPrompt() {
  return useMutation({
    mutationFn: async ({ prompt, format }: { prompt: PromptSummary; format: ExportFormat }) => {
      const body = await api.get<unknown>(`${AI}/prompts/${enc(prompt.id)}/export`, { format });
      const text = typeof body === "string" ? body : JSON.stringify(body, null, 2);
      downloadFile(exportFilename(prompt, format), text, format === "markdown" ? "text/markdown" : "application/json");
      return { filename: exportFilename(prompt, format), bytes: text.length };
    },
  });
}

// ---------------------------------------------------------------------------- templates

export function useTemplates() {
  return useQuery({
    queryKey: workspaceAiKeys.templates,
    queryFn: () => api.get<PromptTemplate[]>(`${AI}/templates`),
  });
}

export function useTemplate(id: string | null | undefined) {
  return useQuery({
    queryKey: workspaceAiKeys.template(id ?? ""),
    queryFn: () => api.get<PromptTemplate>(`${AI}/templates/${enc(id ?? "")}`),
    enabled: !!id,
    retry: retryUnlessNotFound,
  });
}

export function useCreateTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TemplateInput) => api.post<PromptTemplate>(`${AI}/templates`, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: workspaceAiKeys.templates }),
  });
}

/** Organisation templates only; built-in templates answer 409 (read-only). */
export function useUpdateTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ templateId, patch }: { templateId: string; patch: TemplatePatch }) =>
      api.patch<PromptTemplate>(`${AI}/templates/${enc(templateId)}`, patch),
    onSuccess: () => void qc.invalidateQueries({ queryKey: workspaceAiKeys.templates }),
  });
}

export function useDeleteTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (templateId: string) => api.delete<void>(`${AI}/templates/${enc(templateId)}`),
    onSuccess: (_void, templateId) => {
      qc.removeQueries({ queryKey: workspaceAiKeys.template(templateId) });
      void qc.invalidateQueries({ queryKey: workspaceAiKeys.templates });
    },
  });
}

// ---------------------------------------------------------------------------- breakdown

/** Deterministic subtask drafts for a task (nothing is created). `plan` overrides the automatic choice. */
export function useBreakdownDrafts() {
  return useMutation({
    mutationFn: (body: { task_id: string; plan?: string }) => api.post<BreakdownResult>(`${AI}/breakdown`, body),
  });
}

/** Create subtasks and their dependencies from (edited) drafts, in one transaction. */
export function useApplyBreakdown() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BreakdownApplyInput) => api.post<BreakdownApplyResult>(`${AI}/breakdown/apply`, body),
    onSuccess: (result) => {
      invalidateTaskActivity(qc, result.parent_task_id);
      void qc.invalidateQueries({ queryKey: ["workspace", "tasks", "list"] });
      void qc.invalidateQueries({ queryKey: workspaceKeys.boards });
    },
  });
}
