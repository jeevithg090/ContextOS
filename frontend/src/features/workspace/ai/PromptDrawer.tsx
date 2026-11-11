import { useState } from "react";
import { Link } from "react-router-dom";
import { Download, FileJson, Sparkles } from "lucide-react";
import { CodeBlock, CopyButton, Markdown, SegmentedControl } from "@/components/data";
import { Badge, Button, Drawer, ErrorState, KeyValue, LoadingRows, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useExportPrompt, usePrompt } from "./api";
import { KindBadge, PrivacyNote } from "./controls";
import { mutationMessage } from "./hooks";
import { formatTokens, optionsSummary, TOKEN_ESTIMATE_NOTE } from "./meta";
import { ModeAccess } from "./ModeCards";
import type { ExportFormat, SavedPrompt } from "./types";

type View = "rendered" | "raw" | "sections";

function PromptBody({ prompt }: { prompt: SavedPrompt }) {
  const [view, setView] = useState<View>("rendered");
  return (
    <div className="space-y-4 p-5">
      <PrivacyNote detail={prompt.privacy_note} />
      {prompt.problems.length > 0 && (
        <div role="alert" className="rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-xs">
          <p className="font-medium text-danger">Incomplete for its mode</p>
          <ul className="mt-1 list-disc pl-4 text-fg-muted">
            {prompt.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      <KeyValue
        items={[
          { label: "Mode", value: <span className="inline-flex flex-wrap items-center gap-2">{prompt.mode_label}<ModeAccess mayModify={prompt.may_modify_files} /></span> },
          { label: "Coding agent", value: prompt.preset_label },
          { label: "Options", value: optionsSummary(prompt.options) },
          {
            label: "Version",
            value: (
              <span className="inline-flex flex-wrap items-center gap-2">
                v{prompt.version}
                {prompt.edited_sections.length > 0 && <Badge tone="accent">{prompt.edited_sections.length} edited section{prompt.edited_sections.length === 1 ? "" : "s"}</Badge>}
              </span>
            ),
          },
          { label: "Size", value: <span title={TOKEN_ESTIMATE_NOTE}>{formatTokens(prompt.token_estimate)} · {prompt.sections.length} sections · {prompt.sources.length} sources</span> },
          {
            label: "Context pack",
            value: prompt.context_pack_id ? (
              <Link className="font-mono text-xs text-accent hover:underline" to={`/work/context-packs?pack=${encodeURIComponent(prompt.context_pack_id)}`}>
                {prompt.context_pack_id}
              </Link>
            ) : (
              <span className="text-fg-faint">Not stored</span>
            ),
          },
          { label: "Created", value: formatDateTime(prompt.created_at) },
          { label: "Last changed", value: `${formatDateTime(prompt.updated_at)} (${timeAgo(prompt.updated_at)})` },
        ]}
      />
      <SegmentedControl<View>
        aria-label="Prompt view"
        size="md"
        value={view}
        onChange={setView}
        options={[
          { value: "rendered", label: "Rendered" },
          { value: "raw", label: "Markdown source" },
          { value: "sections", label: "Sections", count: prompt.sections.length },
        ]}
      />
      {view === "rendered" ? (
        <div className="rounded-md border border-border p-4">
          <Markdown source={prompt.content} />
        </div>
      ) : view === "raw" ? (
        <CodeBlock code={prompt.content} language="markdown" maxHeight={560} wrap />
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {prompt.sections.map((s) => (
            <li key={s.key} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <span className="min-w-0 flex-1 truncate text-[13px] text-fg">{s.title}</span>
              <KindBadge kind={s.kind} />
              {s.required && <Badge tone="neutral">Required</Badge>}
              {s.edited && <Badge tone="accent">Edited</Badge>}
              <span className="num text-2xs text-fg-faint">{formatTokens(Math.ceil(s.content.length / 4), false)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Read-only view of a saved prompt with copy, export and a way back into Fix Context. */
export function PromptDrawer({ promptId, onOpenChange }: { promptId: string | null; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const prompt = usePrompt(promptId);
  const exportPrompt = useExportPrompt();
  const data = prompt.data;

  const runExport = (format: ExportFormat) => {
    if (!data) return;
    exportPrompt.mutate({ prompt: data, format }, { onError: (err) => toast.error("Export failed", mutationMessage(err)) });
  };

  return (
    <Drawer
      open={!!promptId}
      onOpenChange={onOpenChange}
      title={data ? `${data.task_key ?? "Deleted task"} · ${data.mode_label}` : "Saved prompt"}
      subtitle={data ? (data.task_title ?? "The task this prompt was generated for no longer exists.") : undefined}
      actions={
        data ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <CopyButton value={data.content} label="Copy prompt" onCopied={() => toast.success("Prompt copied", "Paste it into your coding agent.")}>
              Copy
            </CopyButton>
            <Button size="sm" variant="ghost" icon={<Download className="h-3.5 w-3.5" aria-hidden />} onClick={() => runExport("markdown")} disabled={exportPrompt.isPending} title="Download as Markdown">
              .md
            </Button>
            <Button size="sm" variant="ghost" icon={<FileJson className="h-3.5 w-3.5" aria-hidden />} onClick={() => runExport("json")} disabled={exportPrompt.isPending} title="Download sections, options and context pack as JSON">
              .json
            </Button>
            {data.task_id ? (
              <Link
                to={`/work/fix-context/${encodeURIComponent(data.task_id)}?prompt=${encodeURIComponent(data.id)}`}
                className="inline-flex h-7 items-center gap-1.5 rounded bg-accent px-2.5 text-xs font-medium text-accent-fg hover:bg-accent-strong"
              >
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                Open in Fix Context
              </Link>
            ) : null}
          </div>
        ) : undefined
      }
    >
      {prompt.isLoading ? (
        <LoadingRows rows={8} />
      ) : prompt.error ? (
        <ErrorState error={prompt.error instanceof ApiError && prompt.error.status === 404 ? new Error("This prompt no longer exists.") : prompt.error} onRetry={() => void prompt.refetch()} />
      ) : data ? (
        <PromptBody prompt={data} />
      ) : null}
    </Drawer>
  );
}
