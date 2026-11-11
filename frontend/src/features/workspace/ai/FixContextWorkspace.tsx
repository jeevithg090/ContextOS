import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FileText, Package, Sparkles } from "lucide-react";
import { Button, EmptyState, ErrorState, Kbd, LoadingRows, Skeleton, Tabs, TabPanel, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useContextPack, useGenerateFixContext, usePrompt, useUpdatePrompt } from "./api";
import { ConfigPanel } from "./ConfigPanel";
import { FixAttemptDialog } from "./FixAttemptDialog";
import { mutationMessage, useCanWrite } from "./hooks";
import { formatTokens, mayModify, PRESET_AGENT_TOOL } from "./meta";
import { PackCard } from "./PackCard";
import { PackDetail } from "./PackDetail";
import { PromptPreview, viewFromDraft, viewFromSaved } from "./PromptPreview";
import type { AiCatalogue, ModeInfo } from "./types";
import { useFixContextState, type InitialFixState } from "./useFixContextState";
import type { FixAttempt, TaskDetail } from "../types";

type RightTab = "prompt" | "pack";

const MOD_KEY = typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent) ? "⌘" : "Ctrl";

function GenerationError({ error }: { error: unknown }) {
  return (
    <div role="alert" className="rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-xs">
      <p className="font-medium text-danger">The prompt could not be generated</p>
      <p className="mt-0.5 text-fg-muted">{mutationMessage(error)}</p>
    </div>
  );
}

/**
 * The Fix Context workspace for one task: configuration on the left, the context pack and the
 * generated prompt on the right. Generation runs on the ContextOS server; nothing leaves it.
 */
export function FixContextWorkspace({
  task,
  catalogue,
  initial,
  onPromptChange,
}: {
  task: TaskDetail;
  catalogue: AiCatalogue;
  initial: InitialFixState;
  /** The stored prompt shown changed (saved, or replaced by a new draft → null). */
  onPromptChange: (promptId: string | null) => void;
}) {
  const toast = useToast();
  const canWrite = useCanWrite();
  const modes = useMemo(() => new Map<string, ModeInfo>(catalogue.modes.map((m) => [m.key, m])), [catalogue.modes]);
  const state = useFixContextState(initial, task, modes);
  const generate = useGenerateFixContext();
  const saveGen = useGenerateFixContext();
  const update = useUpdatePrompt();
  const saved = usePrompt(state.preview?.promptId);
  const pack = useContextPack(state.pack?.id);
  const [tab, setTab] = useState<RightTab>("prompt");
  const [fixOpen, setFixOpen] = useState(false);
  const [fixAttempt, setFixAttempt] = useState<FixAttempt | null>(null);
  const previewRef = useRef<HTMLElement>(null);

  const { preview, request } = state;
  const view = preview?.draft ? viewFromDraft(preview.draft) : saved.data ? viewFromSaved(saved.data) : null;
  const savedMissing = saved.error instanceof ApiError && saved.error.status === 404;

  const runGenerate = useCallback(() => {
    if (generate.isPending) return;
    const used = request;
    generate.mutate(used, {
      onSuccess: (result) => {
        state.showDraft(result, used);
        setFixAttempt(null);
        setTab("prompt");
        onPromptChange(null);
        // Stacked layout (narrow screens): bring the new preview into view.
        const el = previewRef.current;
        if (el && el.getBoundingClientRect().top > window.innerHeight * 0.6) el.scrollIntoView?.({ behavior: "smooth", block: "start" });
      },
    });
  }, [generate, request, state, onPromptChange]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        runGenerate();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [runGenerate]);

  /** Resolve the stored prompt id, saving the draft on screen first when needed. */
  const ensureSaved = useCallback(
    () =>
      new Promise<string>((resolve, reject) => {
        const current = state.preview;
        if (!current) return reject(new Error("Generate a prompt first."));
        if (current.promptId) return resolve(current.promptId);
        const wasStale = state.stale;
        saveGen.mutate(
          { ...current.request, save: true },
          {
            onSuccess: (result) => {
              if (!result.prompt_id) return reject(new Error("The server did not store the prompt."));
              const created = !current.request.context_pack_id && result.context_pack && !wasStale ? { id: result.context_pack.id, profile: result.context_pack.profile } : null;
              if (created) state.selectPack(created, { silent: true });
              state.showSaved(result.prompt_id, created);
              onPromptChange(result.prompt_id);
              toast.success(`Prompt saved to ${task.key}`, `Version ${result.version ?? 1}${result.context_pack ? ` · ${result.context_pack.profile_label} context pack stored` : ""}.`);
              resolve(result.prompt_id);
            },
            onError: (err) => reject(err),
          },
        );
      }),
    [state, saveGen, onPromptChange, toast, task.key],
  );

  const save = () => void ensureSaved().catch((err) => toast.error("Could not save the prompt", mutationMessage(err)));

  const applyOptions = () => {
    if (!preview?.promptId) return;
    update.mutate(
      { promptId: preview.promptId, patch: { options: request.options } },
      {
        onSuccess: (p) => {
          state.markCurrent();
          toast.success("Options applied", p.notes.length ? p.notes.join(" ") : `Now version ${p.version}.`);
        },
        onError: (err) => toast.error("Could not apply the options", mutationMessage(err)),
      },
    );
  };

  const effectiveModify = mayModify(state.modeInfo, state.config.options);
  const packTabLabel = pack.data ? `Context pack (${pack.data.counts.included}/${pack.data.counts.total})` : "Context pack";

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(360px,420px)_minmax(0,1fr)]">
      <aside aria-label="Prompt configuration" className="panel flex flex-col xl:sticky xl:top-0 xl:max-h-[calc(100vh-7rem)]">
        <div className="min-h-0 flex-1 overflow-y-auto">
          <ConfigPanel state={state} catalogue={catalogue} canWrite={canWrite} />
          <div className="border-t border-border">
            <PackCard state={state} catalogue={catalogue} task={task} canWrite={canWrite} onInspect={() => setTab("pack")} />
          </div>
        </div>
        <div className="space-y-2 border-t border-border p-3">
          {generate.error && <GenerationError error={generate.error} />}
          <Button variant="primary" className="w-full" icon={<Sparkles className="h-3.5 w-3.5" aria-hidden />} loading={generate.isPending} onClick={runGenerate}>
            {preview ? "Generate again" : "Generate preview"}
          </Button>
          <p className="text-center text-2xs text-fg-faint">
            {state.modeInfo?.label ?? state.config.mode} · {effectiveModify ? "agent may modify files" : "read-only for the agent"} · <Kbd>{MOD_KEY}</Kbd>
            <Kbd>↵</Kbd>
          </p>
        </div>
      </aside>

      <section ref={previewRef} aria-label="Preview" className="panel min-w-0 scroll-mt-4">
        <Tabs
          value={tab}
          onValueChange={(v) => setTab(v as RightTab)}
          className="px-4 pt-1"
          tabs={[
            { value: "prompt", label: <span className="inline-flex items-center gap-1.5"><FileText className="h-3.5 w-3.5" aria-hidden />Prompt{view ? ` · ${formatTokens(view.tokenEstimate, false)}` : ""}</span> },
            { value: "pack", label: <span className="inline-flex items-center gap-1.5"><Package className="h-3.5 w-3.5" aria-hidden />{packTabLabel}</span> },
          ]}
        >
          <TabPanel value="prompt" className="py-4">
            {generate.isPending && !view ? (
              <div className="space-y-3" aria-busy="true" aria-label="Generating prompt">
                <Skeleton className="h-6 w-1/2" />
                <Skeleton className="h-10 w-full" />
                <LoadingRows rows={5} />
              </div>
            ) : preview?.promptId && !preview.draft && saved.isLoading ? (
              <LoadingRows rows={6} />
            ) : savedMissing ? (
              <EmptyState
                title="This saved prompt no longer exists"
                description="It may have been deleted with its task. Generate a new prompt from the current settings."
                action={<Button size="sm" variant="primary" onClick={() => { state.clearPreview(); onPromptChange(null); runGenerate(); }}>Generate preview</Button>}
              />
            ) : preview?.promptId && !preview.draft && saved.error ? (
              <ErrorState error={saved.error} onRetry={() => void saved.refetch()} />
            ) : view ? (
              <PromptPreview
                view={view}
                taskId={task.id}
                canWrite={canWrite}
                catalogueSections={catalogue.sections}
                stale={state.stale}
                optionsOnlyChange={state.optionsOnlyChange}
                onGenerateAgain={runGenerate}
                generating={generate.isPending}
                onApplyOptions={applyOptions}
                applying={update.isPending}
                onSave={save}
                saving={saveGen.isPending}
                onStartFix={() => setFixOpen(true)}
                fixAttempt={fixAttempt}
              />
            ) : (
              <EmptyState
                icon={<Sparkles className="h-4 w-4" />}
                title="No prompt yet"
                description="Choose a mode and options, then generate. You get typed sections — facts, evidence, hypotheses and instructions kept apart — and a final prompt to copy into your coding agent."
                action={
                  <Button size="sm" variant="primary" loading={generate.isPending} onClick={runGenerate}>
                    Generate preview
                  </Button>
                }
              />
            )}
          </TabPanel>
          <TabPanel value="pack" className="py-4">
            {!state.pack ? (
              <EmptyState
                icon={<Package className="h-4 w-4" />}
                title="No stored context pack"
                description={`Generation will build a fresh ${catalogue.profiles.find((p) => p.key === state.config.profile)?.label ?? state.config.profile} pack that is not saved. ${
                  canWrite
                    ? "Build a pack in the configuration panel to see every file and record, why it was chosen and whether it was verified — and to include or exclude items."
                    : "Someone with write access can build a stored pack so its files and records can be inspected here."
                }`}
              />
            ) : pack.isLoading ? (
              <LoadingRows rows={6} />
            ) : pack.error ? (
              <ErrorState error={pack.error} onRetry={() => void pack.refetch()} />
            ) : pack.data ? (
              <PackDetailWithStaleness key={state.pack.id} packId={state.pack.id} onChanged={state.packChanged} canWrite={canWrite} repositoryConfigured={catalogue.repository_configured} />
            ) : null}
          </TabPanel>
        </Tabs>
      </section>

      <FixAttemptDialog
        open={fixOpen}
        onOpenChange={setFixOpen}
        taskId={task.id}
        taskKey={task.key}
        defaultTool={PRESET_AGENT_TOOL[state.config.preset]}
        needsSave={!preview?.promptId}
        ensurePromptId={ensureSaved}
        onStarted={(attempt) => {
          setFixAttempt(attempt);
          toast.success(`Fix attempt recorded on ${task.key}`, "Linked to this prompt. Verify the fix on the task when it is done.");
        }}
      />
    </div>
  );
}

/** Pack detail that tells the workspace when included items change (the preview becomes stale). */
function PackDetailWithStaleness({ packId, onChanged, canWrite, repositoryConfigured }: { packId: string; onChanged: () => void; canWrite: boolean; repositoryConfigured: boolean }) {
  const pack = useContextPack(packId);
  const signature = pack.data ? pack.data.items.filter((i) => i.included).map((i) => i.key).join("|") : null;
  const [seen, setSeen] = useState<string | null>(signature);
  useEffect(() => {
    if (signature === null) return;
    if (seen !== null && signature !== seen) onChanged();
    setSeen(signature);
  }, [signature, seen, onChanged]);
  if (!pack.data) return null;
  return <PackDetail pack={pack.data} canEdit={canWrite} repositoryConfigured={repositoryConfigured} />;
}
