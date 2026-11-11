/**
 * Extra client code for the AI screens that is not part of the backend contract module (api.ts):
 * client-side downloads of server-generated content and small derived-data hooks.
 */
import { useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, ApiError, downloadFile } from "@/lib/api";
import { useAuth } from "@/features/auth/AuthProvider";
import { validationErrors, workflowConflict } from "../api";
import { useAiCatalogue, useTemplates } from "./api";
import { safeFilename } from "./meta";
import type { ContextPack, ModeInfo, PresetInfo, ProfileInfo, PromptMode, PromptTemplate } from "./types";

/** Body of GET /workspace/ai/context-packs/{id}/export (services.workspace_ai_packs.export_pack). */
interface ContextPackExport {
  context_pack: Pick<ContextPack, "id" | "profile">;
  task: { id: string; key: string; title: string } | null;
}

/** Filename the server puts in Content-Disposition for a pack export. */
export function packExportFilename(doc: ContextPackExport): string {
  return safeFilename(`context-pack-${doc.task?.key ?? doc.context_pack.id}-${doc.context_pack.profile}`, "json");
}

/**
 * Download a stored context pack through the server's export endpoint, which re-redacts the pack
 * (items, verification status, reasons and excerpts — sensitive files never have content) and writes
 * a `context_pack.exported` audit entry. The current version is exported.
 */
export function useExportContextPack() {
  return useMutation({
    mutationFn: async (packId: string) => {
      const doc = await api.get<ContextPackExport>(`/workspace/ai/context-packs/${encodeURIComponent(packId)}/export`);
      const filename = packExportFilename(doc);
      downloadFile(filename, JSON.stringify(doc, null, 2), "application/json");
      return { filename };
    },
  });
}

/** Download an unsaved (draft) prompt exactly as the server rendered it. */
export function downloadDraftMarkdown(taskKey: string | null | undefined, mode: string, content: string): string {
  const filename = safeFilename(`${taskKey ?? "prompt"}-${mode}-draft`, "md");
  downloadFile(filename, content, "text/markdown");
  return filename;
}

/** Lookup maps over the catalogue so components can resolve labels by key. */
export function useCatalogueMaps() {
  const catalogue = useAiCatalogue();
  const maps = useMemo(() => {
    const data = catalogue.data;
    return {
      modes: new Map<string, ModeInfo>((data?.modes ?? []).map((m) => [m.key, m])),
      presets: new Map<string, PresetInfo>((data?.presets ?? []).map((p) => [p.key, p])),
      profiles: new Map<string, ProfileInfo>((data?.profiles ?? []).map((p) => [p.key, p])),
      sectionTitles: new Map<string, string>((data?.sections ?? []).map((s) => [s.key, s.title])),
    };
  }, [catalogue.data]);
  return { catalogue, ...maps };
}

/** Templates split into built-in and organisation groups, plus an id lookup. */
export function useTemplateGroups() {
  const templates = useTemplates();
  const groups = useMemo(() => {
    const all = templates.data ?? [];
    return {
      builtin: all.filter((t) => t.is_builtin),
      org: all.filter((t) => !t.is_builtin),
      byId: new Map<string, PromptTemplate>(all.map((t) => [t.id, t])),
    };
  }, [templates.data]);
  return { templates, ...groups };
}

export function useCanWrite(): boolean {
  const { can } = useAuth();
  return can("write");
}

/** Best plain-language message for a failed mutation (422 validation lists, 409 explanations). */
export function mutationMessage(error: unknown): string {
  const errors = validationErrors(error);
  if (errors.length) return errors.join(" ");
  const conflict = workflowConflict(error);
  if (conflict) return conflict.message;
  if (error instanceof ApiError && error.status === 403) return "You do not have permission to do this.";
  return error instanceof Error ? error.message : "The request failed.";
}

export const modeLabel = (modes: Map<string, ModeInfo>, key: PromptMode | string) => modes.get(key)?.label ?? key;
