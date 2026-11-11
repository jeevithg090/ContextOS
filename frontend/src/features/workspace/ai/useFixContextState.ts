/**
 * Configuration and preview state of the Fix Context workspace.
 *
 * - `config` is what the next generation will request (mode, preset, options, template, profile).
 * - `pack` is the stored context pack in use (it always matches `config.profile`); without one the
 *   server builds a fresh, unsaved pack for the chosen profile.
 * - `preview` is the prompt on screen: an unsaved draft (`draft`) or a stored prompt (`promptId`).
 *   It remembers the request and pack revision it was generated from, so the UI can say when the
 *   preview no longer matches the settings ("stale").
 */
import { useCallback, useMemo, useState } from "react";
import { completeOptions, defaultOptions, effectiveOptions, optionsEqual, suggestedProfile } from "./meta";
import type {
  AgentPreset,
  AiCatalogue,
  ContextPackSummary,
  FixContextInput,
  FixContextResult,
  GenerationOptions,
  ModeInfo,
  PackProfile,
  PromptMode,
  PromptTemplate,
  SavedPrompt,
} from "./types";
import type { TaskDetail } from "../types";

export interface FixConfig {
  mode: PromptMode;
  preset: AgentPreset;
  options: GenerationOptions;
  templateId: string | null;
  profile: PackProfile;
  /** Until the user picks a profile, it follows the profile suggested for the task and mode. */
  profileChosen: boolean;
}

export interface PackRef {
  id: string;
  profile: PackProfile;
}

export interface PreviewState {
  draft: FixContextResult | null;
  promptId: string | null;
  /** Pack revision (builds, selections, item toggles) the preview was generated from. */
  packRev: number;
  /** The request that produced the preview (saving a draft repeats it with `save: true`). */
  request: FixContextInput;
}

export interface InitialFixState {
  config: FixConfig;
  pack: PackRef | null;
  preview: PreviewState | null;
}

type TaskLike = Pick<TaskDetail, "id" | "task_type" | "related_finding_id">;

export const DEFAULT_MODE: PromptMode = "implement_fix";
export const DEFAULT_PRESET: AgentPreset = "generic";

export function buildRequest(taskId: string, config: FixConfig, pack: PackRef | null, mode: ModeInfo | undefined): FixContextInput {
  return {
    task_id: taskId,
    mode: config.mode,
    preset: config.preset,
    options: effectiveOptions(config.options, mode),
    ...(config.templateId ? { template_id: config.templateId } : {}),
    ...(pack ? { context_pack_id: pack.id } : { profile: config.profile }),
  };
}

/** Starting state from what the URL asked for: a saved prompt, a template and/or a stored pack. */
export function initialFixState({
  catalogue,
  task,
  prompt,
  template,
  pack,
  templates,
}: {
  catalogue: AiCatalogue;
  task: TaskLike;
  prompt?: SavedPrompt | null;
  template?: PromptTemplate | null;
  pack?: ContextPackSummary | null;
  templates: PromptTemplate[];
}): InitialFixState {
  const defaults = defaultOptions(catalogue);
  const usablePack = pack && pack.task_id === task.id ? { id: pack.id, profile: pack.profile } : null;
  let config: FixConfig = {
    mode: DEFAULT_MODE,
    preset: DEFAULT_PRESET,
    options: defaults,
    templateId: null,
    profile: suggestedProfile(task, DEFAULT_MODE),
    profileChosen: false,
  };
  if (prompt) {
    const knownTemplate = prompt.template_id && templates.some((t) => t.id === prompt.template_id) ? prompt.template_id : null;
    config = { ...config, mode: prompt.mode, preset: prompt.preset, options: completeOptions(prompt.options, defaults), templateId: knownTemplate, profile: suggestedProfile(task, prompt.mode) };
  } else if (template) {
    config = { ...config, mode: template.mode, preset: template.preset, options: completeOptions(template.options, defaults), templateId: template.id, profile: suggestedProfile(task, template.mode) };
  }
  if (usablePack) config = { ...config, profile: usablePack.profile, profileChosen: true };
  const modeInfo = catalogue.modes.find((m) => m.key === config.mode);
  const preview: PreviewState | null = prompt
    ? { draft: null, promptId: prompt.id, packRev: 0, request: buildRequest(task.id, config, usablePack, modeInfo) }
    : null;
  return { config, pack: usablePack, preview };
}

export function useFixContextState(initial: InitialFixState, task: TaskLike, modes: Map<string, ModeInfo>) {
  const [config, setConfig] = useState<FixConfig>(initial.config);
  const [pack, setPack] = useState<PackRef | null>(initial.pack);
  const [packRev, setPackRev] = useState(0);
  const [preview, setPreviewState] = useState<PreviewState | null>(initial.preview);

  const bumpPack = useCallback(() => setPackRev((r) => r + 1), []);

  /** Changing the profile away from the stored pack's profile detaches the pack (it stays saved). */
  const withProfile = useCallback(
    (profile: PackProfile) => {
      if (pack && pack.profile !== profile) {
        setPack(null);
        bumpPack();
      }
    },
    [pack, bumpPack],
  );

  const setMode = useCallback(
    (mode: PromptMode) => {
      const profile = config.profileChosen ? config.profile : suggestedProfile(task, mode);
      withProfile(profile);
      setConfig((c) => ({ ...c, mode, profile }));
    },
    [config.profileChosen, config.profile, task, withProfile],
  );

  const setPreset = useCallback((preset: AgentPreset) => setConfig((c) => ({ ...c, preset })), []);

  const setOptions = useCallback((patch: Partial<GenerationOptions>) => setConfig((c) => ({ ...c, options: { ...c.options, ...patch } })), []);

  const setProfile = useCallback(
    (profile: PackProfile) => {
      withProfile(profile);
      setConfig((c) => ({ ...c, profile, profileChosen: true }));
    },
    [withProfile],
  );

  const applyTemplate = useCallback(
    (template: PromptTemplate, defaults: GenerationOptions) => {
      const profile = config.profileChosen ? config.profile : suggestedProfile(task, template.mode);
      withProfile(profile);
      setConfig((c) => ({ ...c, mode: template.mode, preset: template.preset, options: completeOptions(template.options, defaults), templateId: template.id, profile }));
    },
    [config.profileChosen, config.profile, task, withProfile],
  );

  const clearTemplate = useCallback(() => {
    setConfig((c) => ({ ...c, templateId: null }));
  }, []);

  /** Use a stored pack (built here, chosen from the task's packs, or created by saving). */
  const selectPack = useCallback(
    (next: Pick<ContextPackSummary, "id" | "profile">, options: { silent?: boolean } = {}) => {
      setPack({ id: next.id, profile: next.profile });
      setConfig((c) => ({ ...c, profile: next.profile, profileChosen: true }));
      if (!options.silent) bumpPack();
    },
    [bumpPack],
  );

  const detachPack = useCallback(() => {
    setPack(null);
    bumpPack();
  }, [bumpPack]);

  const modeInfo = modes.get(config.mode);
  const request = useMemo(() => buildRequest(task.id, config, pack, modeInfo), [task.id, config, pack, modeInfo]);

  const showDraft = useCallback(
    (draft: FixContextResult, used: FixContextInput) => setPreviewState({ draft, promptId: null, packRev, request: used }),
    [packRev],
  );

  /**
   * The draft on screen was stored. When saving created the pack it used, `adoptPack` records it on
   * the preview's request (the workspace selects the same pack, so the preview stays current).
   */
  const showSaved = useCallback(
    (promptId: string, adoptPack?: PackRef | null) =>
      setPreviewState((prev) => {
        if (!prev) return { draft: null, promptId, packRev, request };
        if (!adoptPack) return { ...prev, draft: null, promptId };
        const adopted: FixContextInput = { ...prev.request, context_pack_id: adoptPack.id };
        delete adopted.profile;
        return { ...prev, draft: null, promptId, request: adopted };
      }),
    [packRev, request],
  );

  /** The settings now match the preview again (e.g. options were applied to the saved prompt). */
  const markCurrent = useCallback(() => setPreviewState((prev) => (prev ? { ...prev, packRev, request } : prev)), [packRev, request]);

  const clearPreview = useCallback(() => setPreviewState(null), []);

  const sameTarget =
    !!preview &&
    preview.packRev === packRev &&
    preview.request.mode === request.mode &&
    preview.request.preset === request.preset &&
    (preview.request.template_id ?? null) === (request.template_id ?? null) &&
    (preview.request.context_pack_id ?? null) === (request.context_pack_id ?? null) &&
    (preview.request.profile ?? null) === (request.profile ?? null);
  const sameOptions = !!preview && optionsEqual(preview.request.options as GenerationOptions, request.options as GenerationOptions);
  /** The settings or the pack changed since the preview was generated. */
  const stale = !!preview && !(sameTarget && sameOptions);
  /** Only generation options changed since a saved preview: they can be applied to it in place. */
  const optionsOnlyChange = stale && !!preview?.promptId && sameTarget && !sameOptions;

  return {
    config,
    pack,
    modeInfo,
    request,
    preview,
    stale,
    optionsOnlyChange,
    setMode,
    setPreset,
    setOptions,
    setProfile,
    applyTemplate,
    clearTemplate,
    selectPack,
    detachPack,
    packChanged: bumpPack,
    showDraft,
    showSaved,
    markCurrent,
    clearPreview,
  };
}

export type FixContextState = ReturnType<typeof useFixContextState>;
