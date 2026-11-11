/**
 * Task-detail hooks that the workspace client does not provide: Simulation Lab scenarios (for
 * "Verify with simulation"), a debounced task search for pickers, and a field-save helper that
 * reports refusals in plain language.
 */
import { useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/components/ui";
import { useDebounce } from "@/hooks/useDebounce";
import { api } from "@/lib/api";
import { useTasks, useUpdateTask, validationErrors, workflowConflict } from "../api";
import type { TaskPatch } from "../types";
import { errorMessage } from "./useWorkflowConflicts";

// ---------------------------------------------------------------------------- simulation scenarios

export interface ScenarioOption {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
}

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v : null);

/** Accepts the scenario catalogue as a bare list or a `Page`, tolerating `id`/`key` and `name`/`title`. */
export function normalizeScenarios(body: unknown): ScenarioOption[] {
  const list = Array.isArray(body) ? body : body && typeof body === "object" && Array.isArray((body as { items?: unknown }).items) ? (body as { items: unknown[] }).items : [];
  return list.flatMap((raw) => {
    if (!raw || typeof raw !== "object") return [];
    const r = raw as Record<string, unknown>;
    const id = str(r.id) ?? str(r.key) ?? str(r.scenario_id);
    if (!id) return [];
    return [{ id, name: str(r.name) ?? str(r.title) ?? id, description: str(r.description) ?? str(r.summary), category: str(r.category) ?? str(r.attack_type) }];
  });
}

export function useSimulationScenarios(enabled: boolean) {
  return useQuery({
    queryKey: ["simulations", "scenarios"],
    queryFn: async () => normalizeScenarios(await api.get<unknown>("/simulations/scenarios")),
    enabled,
    staleTime: 5 * 60_000,
  });
}

// ---------------------------------------------------------------------------- task search

/** Tasks matching `query` (title, description or key such as CTX-12), for pickers. */
export function useTaskSearch(query: string, enabled: boolean) {
  const q = useDebounce(query.trim(), 200);
  return useTasks({ q: q || undefined, include_done: true, sort: "updated", limit: 20 }, { enabled });
}

// ---------------------------------------------------------------------------- saving fields

/** Turn a refusal into one plain sentence (validation list, gate explanation or error message). */
export function describeError(error: unknown): string {
  const errors = validationErrors(error);
  if (errors.length > 0) return errors.join(" ");
  return workflowConflict(error)?.message ?? errorMessage(error);
}

/** Save a partial task update; failures become a toast and the returned promise rejects. */
export function useSaveTask(taskId: string) {
  const { mutateAsync, isPending } = useUpdateTask();
  const toast = useToast();
  const save = useCallback(
    (patch: TaskPatch, what = "Change") =>
      mutateAsync({ taskId, patch }).catch((error: unknown) => {
        toast.error(`${what} not saved`, describeError(error));
        throw error;
      }),
    [taskId, mutateAsync, toast],
  );
  return { save, pending: isPending };
}
