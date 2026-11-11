import { useEffect, useId, useState } from "react";
import { Pencil, RotateCcw, Trash2 } from "lucide-react";
import { ConfirmDialog, Markdown, SegmentedControl } from "@/components/data";
import { Badge, Button, Textarea, useToast } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn } from "@/lib/format";
import { useRegenerateSection, useUpdatePrompt } from "./api";
import { KindBadge } from "./controls";
import { mutationMessage } from "./hooks";
import { kindMeta } from "./meta";
import type { PromptSection, SavedPrompt } from "./types";

type View = "rendered" | "raw";
const MAX_SOURCES = 6;

export const DRAFT_EDIT_HINT = "Save the prompt to the task to edit, remove or regenerate sections. Each change is stored as a new version.";

function notifyNotes(toast: ReturnType<typeof useToast>, prompt: SavedPrompt, title: string) {
  toast.success(title, prompt.notes.length ? prompt.notes.join(" ") : `Now version ${prompt.version}.`);
}

/**
 * One prompt section: kind (fact / evidence / hypothesis …), sources, content as rendered Markdown or
 * raw text, and — for saved prompts — edit, regenerate-from-records and remove.
 */
export function SectionCard({ section, promptId, canWrite }: { section: PromptSection; promptId: string | null; canWrite: boolean }) {
  const id = useId();
  const toast = useToast();
  const update = useUpdatePrompt();
  const regenerate = useRegenerateSection();
  const [view, setView] = useState<View>("rendered");
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(section.content);
  const [error, setError] = useState<string | null>(null);
  const [confirmRegen, setConfirmRegen] = useState(false);
  const meta = kindMeta(section.kind);
  const saved = !!promptId;
  const editable = saved && canWrite;
  const blockedTitle = !canWrite ? "You need write access to change prompts" : !saved ? DRAFT_EDIT_HINT : undefined;
  const busy = update.isPending || regenerate.isPending;
  const otherKinds = section.kinds.filter((k) => k !== section.kind);

  useEffect(() => {
    if (!editing) setText(section.content);
  }, [section.content, editing]);

  const save = () => {
    if (!promptId) return;
    setError(null);
    update.mutate(
      { promptId, patch: { sections: [{ key: section.key, content: text }] } },
      {
        onSuccess: (prompt) => {
          setEditing(false);
          notifyNotes(toast, prompt, `“${section.title}” saved`);
        },
        onError: (err) => setError(mutationMessage(err)),
      },
    );
  };

  const remove = () => {
    if (!promptId) return;
    update.mutate(
      { promptId, patch: { sections: [{ key: section.key, removed: true }] } },
      {
        onSuccess: (prompt) => notifyNotes(toast, prompt, `“${section.title}” removed`),
        onError: (err) => toast.error("Could not remove the section", mutationMessage(err)),
      },
    );
  };

  const rebuild = () =>
    new Promise<void>((resolve, reject) => {
      if (!promptId) return resolve();
      regenerate.mutate(
        { promptId, sectionKey: section.key },
        {
          onSuccess: (prompt) => {
            setEditing(false);
            notifyNotes(toast, prompt, `“${section.title}” rebuilt from current records`);
            resolve();
          },
          onError: (err) => reject(new Error(mutationMessage(err))),
        },
      );
    });

  return (
    <article aria-labelledby={`${id}-title`} className="relative overflow-hidden rounded-md border border-border bg-surface">
      <span className={cn("absolute inset-y-0 left-0 w-[3px]", TONE_CLASSES[meta.tone].dot)} aria-hidden />
      <header className="flex flex-wrap items-center gap-2 border-b border-border/70 py-2 pl-4 pr-2">
        <h3 id={`${id}-title`} className="min-w-0 truncate text-[13px] font-semibold text-fg">
          {section.title}
        </h3>
        <KindBadge kind={section.kind} />
        {otherKinds.map((k) => (
          <KindBadge key={k} kind={k} className="opacity-80" />
        ))}
        {section.required && (
          <Badge tone="neutral" title="This mode needs this section; it cannot be removed.">
            Required
          </Badge>
        )}
        {section.edited && (
          <Badge tone="accent" title="Edited by a person; regenerating replaces the edit.">
            Edited
          </Badge>
        )}
        <div className="ml-auto flex items-center gap-1">
          {!editing && (
            <SegmentedControl<View>
              aria-label={`${section.title} view`}
              value={view}
              onChange={setView}
              options={[
                { value: "rendered", label: "Preview" },
                { value: "raw", label: "Markdown" },
              ]}
            />
          )}
          {!editing && (
            <>
              <Button size="xs" variant="ghost" icon={<Pencil className="h-3 w-3" aria-hidden />} disabled={!editable || busy} title={blockedTitle ?? "Edit this section"} onClick={() => setEditing(true)}>
                Edit
              </Button>
              <Button
                size="xs"
                variant="ghost"
                icon={<RotateCcw className="h-3 w-3" aria-hidden />}
                disabled={!editable || busy}
                loading={regenerate.isPending}
                title={blockedTitle ?? "Rebuild this section from the current records"}
                onClick={() => (section.edited ? setConfirmRegen(true) : void rebuild().catch((e: Error) => toast.error("Could not regenerate the section", e.message)))}
              >
                Regenerate
              </Button>
              <Button
                size="xs"
                variant="ghost"
                icon={<Trash2 className="h-3 w-3" aria-hidden />}
                disabled={!editable || busy || section.required}
                title={section.required ? "Required by this mode" : (blockedTitle ?? "Remove this section from the prompt")}
                onClick={remove}
              >
                Remove
              </Button>
            </>
          )}
        </div>
      </header>

      <div className="py-3 pl-4 pr-3">
        {editing ? (
          <div className="space-y-2">
            <label htmlFor={`${id}-edit`} className="sr-only">
              Edit {section.title} (Markdown)
            </label>
            <Textarea id={`${id}-edit`} value={text} onChange={(e) => setText(e.target.value)} className="min-h-[180px] font-mono text-xs" autoFocus />
            {error && (
              <p role="alert" className="text-2xs text-danger">
                {error}
              </p>
            )}
            <div className="flex items-center justify-between gap-2">
              <p className="text-2xs text-fg-faint">Saving stores a new version. Secrets in your text are redacted by the server.</p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={update.isPending}
                  onClick={() => {
                    setEditing(false);
                    setError(null);
                    setText(section.content);
                  }}
                >
                  Cancel
                </Button>
                <Button size="sm" variant="primary" loading={update.isPending} disabled={text === section.content} onClick={save}>
                  Save section
                </Button>
              </div>
            </div>
          </div>
        ) : view === "rendered" ? (
          section.content.trim() ? (
            <Markdown source={section.content} headingOffset={3} />
          ) : (
            <p className="text-xs text-fg-faint">This section is empty.</p>
          )
        ) : (
          <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded bg-surface-2/60 p-2.5 font-mono text-xs text-fg">{section.content}</pre>
        )}
        {section.sources.length > 0 && !editing && (
          <div className="mt-3 flex flex-wrap items-center gap-1.5" aria-label="Sources">
            <span className="text-2xs text-fg-faint">Sources</span>
            {section.sources.slice(0, MAX_SOURCES).map((src) => (
              <span key={src} className="max-w-[260px] truncate rounded border border-border bg-surface-2 px-1.5 py-px font-mono text-2xs text-fg-muted" title={src}>
                {src}
              </span>
            ))}
            {section.sources.length > MAX_SOURCES && <span className="text-2xs text-fg-faint" title={section.sources.slice(MAX_SOURCES).join("\n")}>+{section.sources.length - MAX_SOURCES} more</span>}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmRegen}
        onOpenChange={setConfirmRegen}
        title={`Regenerate “${section.title}”?`}
        description="The section is rebuilt from the current records. Your edits to it are replaced; ContextOS keeps only the latest version of a prompt."
        confirmLabel="Regenerate section"
        destructive
        onConfirm={rebuild}
      />
    </article>
  );
}
