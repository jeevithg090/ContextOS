import { useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, ChevronDown, Download, FileJson, Info, Play, Plus, RefreshCw, Save } from "lucide-react";
import { CodeBlock, CopyButton, Markdown, SegmentedControl } from "@/components/data";
import { Badge, Button, useToast } from "@/components/ui";
import { cn, timeAgo } from "@/lib/format";
import { useExportPrompt, useRegenerateSection } from "./api";
import { KindLegend } from "./controls";
import { downloadDraftMarkdown, mutationMessage, useExportContextPack } from "./hooks";
import { formatTokens, TOKEN_ESTIMATE_NOTE } from "./meta";
import { ModeAccess } from "./ModeCards";
import { DRAFT_EDIT_HINT, SectionCard } from "./SectionCard";
import type { FixContextResult, PromptSection, SavedPrompt, SectionInfo } from "./types";
import type { FixAttempt } from "../types";

/** What the preview shows, from either an unsaved draft or a stored prompt. */
export interface PromptView {
  promptId: string | null;
  version: number | null;
  taskKey: string | null;
  mode: string;
  modeLabel: string;
  presetLabel: string;
  mayModifyFiles: boolean;
  sections: PromptSection[];
  content: string;
  tokenEstimate: number;
  sources: string[];
  problems: string[];
  notes: string[];
  contextPackId: string | null;
  updatedAt: string | null;
  saved: SavedPrompt | null;
}

export function viewFromDraft(r: FixContextResult): PromptView {
  return {
    promptId: r.prompt_id,
    version: r.version,
    taskKey: r.task_key,
    mode: r.mode,
    modeLabel: r.mode_label,
    presetLabel: r.preset_label,
    mayModifyFiles: r.may_modify_files,
    sections: r.sections,
    content: r.content,
    tokenEstimate: r.token_estimate,
    sources: r.sources,
    problems: r.problems,
    notes: r.notes,
    contextPackId: r.context_pack?.id ?? null,
    updatedAt: null,
    saved: null,
  };
}

export function viewFromSaved(p: SavedPrompt): PromptView {
  return {
    promptId: p.id,
    version: p.version,
    taskKey: p.task_key,
    mode: p.mode,
    modeLabel: p.mode_label,
    presetLabel: p.preset_label,
    mayModifyFiles: p.may_modify_files,
    sections: p.sections,
    content: p.content,
    tokenEstimate: p.token_estimate,
    sources: p.sources,
    problems: p.problems,
    notes: p.notes,
    contextPackId: p.context_pack_id,
    updatedAt: p.updated_at,
    saved: p,
  };
}

type Tab = "sections" | "final";
type FinalView = "rendered" | "raw";

export interface PromptPreviewProps {
  view: PromptView;
  taskId: string;
  canWrite: boolean;
  catalogueSections: SectionInfo[];
  stale: boolean;
  optionsOnlyChange: boolean;
  onGenerateAgain: () => void;
  generating: boolean;
  onApplyOptions: () => void;
  applying: boolean;
  onSave: () => void;
  saving: boolean;
  onStartFix: () => void;
  fixAttempt: FixAttempt | null;
}

/** The generated prompt: status, actions, typed section cards and the final rendered prompt. */
export function PromptPreview(props: PromptPreviewProps) {
  const { view, taskId, canWrite, stale } = props;
  const toast = useToast();
  const exportPrompt = useExportPrompt();
  const exportPack = useExportContextPack();
  const addBack = useRegenerateSection();
  const [tab, setTab] = useState<Tab>("sections");
  const [finalView, setFinalView] = useState<FinalView>("raw");
  const [legendOpen, setLegendOpen] = useState(false);
  const saved = !!view.promptId;
  const present = new Set(view.sections.map((s) => s.key));
  const missing = props.catalogueSections.filter((s) => !present.has(s.key));

  const exportMarkdown = () => {
    if (view.saved) {
      exportPrompt.mutate({ prompt: view.saved, format: "markdown" }, { onError: (err) => toast.error("Export failed", mutationMessage(err)) });
    } else {
      downloadDraftMarkdown(view.taskKey, view.mode, view.content);
    }
  };

  return (
    <div className="space-y-3">
      {/* status strip */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        {saved ? (
          <Badge tone="ok" dot title={view.updatedAt ? `Last changed ${timeAgo(view.updatedAt)}` : undefined}>
            Saved to task · v{view.version}
          </Badge>
        ) : (
          <Badge tone="neutral" dot title="Generated for review; nothing is stored until you save it.">
            Unsaved preview
          </Badge>
        )}
        <span className="text-[13px] font-medium text-fg">{view.modeLabel}</span>
        <ModeAccess mayModify={view.mayModifyFiles} />
        <span className="text-xs text-fg-muted">for {view.presetLabel}</span>
        <span className="num text-xs text-fg-muted" title={TOKEN_ESTIMATE_NOTE}>
          {formatTokens(view.tokenEstimate)}
        </span>
        <span className="text-xs text-fg-faint">
          {view.sections.length} sections · {view.sources.length} sources
        </span>
      </div>

      {stale && (
        <div role="status" className="flex flex-wrap items-center gap-2 rounded-md border border-warn/30 bg-warn/[0.07] px-3 py-2 text-xs">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
          <span className="min-w-0 flex-1 text-fg">
            The settings or the context pack changed since this prompt was generated.
            {saved ? " The saved prompt still reflects the old settings." : ""}
          </span>
          {props.optionsOnlyChange && canWrite && (
            <Button size="xs" variant="outline" loading={props.applying} onClick={props.onApplyOptions} title="Rebuilds sections you have not edited with the new options (new version)">
              Apply options to saved prompt
            </Button>
          )}
          <Button size="xs" variant="secondary" icon={<RefreshCw className="h-3 w-3" aria-hidden />} loading={props.generating} onClick={props.onGenerateAgain}>
            Generate again
          </Button>
        </div>
      )}

      {/* actions */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface-2/50 p-2">
        <CopyButton value={view.content} label="Copy prompt" className="bg-surface" onCopied={() => toast.success("Prompt copied", "Paste it into your coding agent.")}>
          Copy prompt
        </CopyButton>
        <Button size="sm" variant="outline" icon={<Download className="h-3.5 w-3.5" aria-hidden />} loading={exportPrompt.isPending} onClick={exportMarkdown}>
          Export Markdown
        </Button>
        <Button
          size="sm"
          variant="outline"
          icon={<FileJson className="h-3.5 w-3.5" aria-hidden />}
          disabled={!view.contextPackId}
          loading={exportPack.isPending}
          title={view.contextPackId ? "Download the stored context pack as JSON" : "This preview used a fresh, unsaved pack. Build a pack or save the prompt to export it."}
          onClick={() => view.contextPackId && exportPack.mutate(view.contextPackId, { onError: (err) => toast.error("Export failed", mutationMessage(err)) })}
        >
          Export context pack JSON
        </Button>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {!saved && canWrite && (
            <Button size="sm" variant="secondary" icon={<Save className="h-3.5 w-3.5" aria-hidden />} loading={props.saving} onClick={props.onSave} title="Store this prompt and its context pack on the task">
              Save to task
            </Button>
          )}
          {canWrite && (
            <Button size="sm" variant="primary" icon={<Play className="h-3.5 w-3.5" aria-hidden />} onClick={props.onStartFix} disabled={props.saving}>
              {saved ? "Start fix attempt" : "Save & start fix attempt"}
            </Button>
          )}
        </div>
      </div>
      {!canWrite && <p className="text-2xs text-fg-faint">You can generate, copy and export prompts. Saving prompts and starting fix attempts needs write access.</p>}

      {props.fixAttempt && (
        <div role="status" className="flex flex-wrap items-center gap-2 rounded-md border border-ok/30 bg-ok/[0.07] px-3 py-2 text-xs">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-ok" aria-hidden />
          <span className="min-w-0 flex-1 text-fg">
            Fix attempt recorded ({props.fixAttempt.status === "in_progress" ? "in progress" : "planned"}) and linked to this prompt. It is a record of work, not verification.
          </span>
          <Link to={`/work/tasks/${encodeURIComponent(taskId)}`} className="font-medium text-accent hover:underline">
            Open task
          </Link>
        </div>
      )}

      {view.problems.length > 0 && (
        <div role="alert" className="rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-xs">
          <p className="font-medium text-danger">This prompt is incomplete for its mode</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-fg-muted">
            {view.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      {view.notes.length > 0 && (
        <ul className="space-y-1 rounded-md border border-border bg-surface-2/40 px-3 py-2" aria-label="Generation notes">
          {view.notes.map((n, i) => (
            <li key={i} className="flex items-start gap-2 text-2xs text-fg-muted">
              <Info className="mt-0.5 h-3 w-3 shrink-0 text-fg-faint" aria-hidden />
              {n}
            </li>
          ))}
        </ul>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
        <SegmentedControl<Tab>
          aria-label="Preview view"
          size="md"
          value={tab}
          onChange={setTab}
          options={[
            { value: "sections", label: "Sections", count: view.sections.length },
            { value: "final", label: "Final prompt" },
          ]}
        />
        {tab === "sections" ? (
          <button type="button" onClick={() => setLegendOpen((v) => !v)} aria-expanded={legendOpen} className="inline-flex items-center gap-1 text-2xs text-fg-muted hover:text-fg">
            What the labels mean
            <ChevronDown className={cn("h-3 w-3 transition-transform", legendOpen && "rotate-180")} aria-hidden />
          </button>
        ) : (
          <SegmentedControl<FinalView>
            aria-label="Final prompt format"
            value={finalView}
            onChange={setFinalView}
            options={[
              { value: "raw", label: "Markdown source" },
              { value: "rendered", label: "Rendered" },
            ]}
          />
        )}
      </div>

      {tab === "sections" ? (
        <div className="space-y-2.5">
          {legendOpen && <KindLegend className="rounded-md border border-border bg-surface-2/40 p-3" />}
          {!saved && canWrite && <p className="text-2xs text-fg-faint">{DRAFT_EDIT_HINT}</p>}
          {view.sections.map((section) => (
            <SectionCard key={section.key} section={section} promptId={view.promptId} canWrite={canWrite} />
          ))}
          {missing.length > 0 && (
            <div className="rounded-md border border-dashed border-border-strong px-3 py-2.5">
              <p className="text-xs font-medium text-fg">Not in this prompt</p>
              <p className="mt-0.5 text-2xs text-fg-muted">
                {saved ? "Removed or optional sections. Adding one rebuilds it from current records." : "Save the prompt to add these sections back."}
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {missing.map((s) => (
                  <Button
                    key={s.key}
                    size="xs"
                    variant="outline"
                    icon={<Plus className="h-3 w-3" aria-hidden />}
                    disabled={!saved || !canWrite || addBack.isPending}
                    loading={addBack.isPending && addBack.variables?.sectionKey === s.key}
                    onClick={() =>
                      view.promptId &&
                      addBack.mutate(
                        { promptId: view.promptId, sectionKey: s.key },
                        {
                          onSuccess: (p) => toast.success(`“${s.title}” added`, `Now version ${p.version}.`),
                          onError: (err) => toast.error("Could not add the section", mutationMessage(err)),
                        },
                      )
                    }
                  >
                    {s.title}
                  </Button>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : finalView === "raw" ? (
        <CodeBlock code={view.content} language="markdown" title={view.taskKey ? `${view.taskKey} · ${view.modeLabel}` : view.modeLabel} maxHeight={720} wrap />
      ) : (
        <div className="rounded-md border border-border bg-surface p-4">
          <Markdown source={view.content} />
        </div>
      )}
    </div>
  );
}
