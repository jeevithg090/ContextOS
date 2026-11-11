/**
 * The written definition of the work: description, reproduction steps, expected vs actual
 * behaviour, the acceptance-criteria checklist and the related files list.
 */
import { useState, type FormEvent } from "react";
import { FileCode2, Plus, Trash2 } from "lucide-react";
import { Section } from "@/components/data";
import { Button, IconButton, Input } from "@/components/ui";
import { cn } from "@/lib/format";
import type { AcceptanceCriterion, TaskDetail } from "../../types";
import { MarkdownField } from "../fields/InlineEditors";
import { useSaveTask } from "../hooks";

function CriteriaChecklist({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const { save, pending } = useSaveTask(task.id);
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  const [editText, setEditText] = useState("");
  const items = task.acceptance_criteria;
  const done = items.filter((c) => c.done).length;

  const write = (next: AcceptanceCriterion[]) => save({ acceptance_criteria: next }, "Acceptance criteria");
  const add = (e: FormEvent) => {
    e.preventDefault();
    const text = draft.trim();
    if (!text) return;
    void write([...items, { text, done: false }]).then(() => setDraft(""), () => undefined);
  };
  const commitEdit = (index: number) => {
    const text = editText.trim();
    setEditing(null);
    if (text && text !== items[index].text) void write(items.map((c, i) => (i === index ? { ...c, text } : c))).catch(() => undefined);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs font-medium text-fg-muted">Acceptance criteria</div>
        {items.length > 0 && (
          <span className={cn("num text-2xs", done === items.length ? "text-ok" : "text-fg-faint")}>
            {done}/{items.length} met
          </span>
        )}
      </div>
      {items.length === 0 && <p className="text-xs text-fg-faint">{canWrite ? "Define what “fixed” means so the work can be verified." : "None defined."}</p>}
      <ul className="space-y-1">
        {items.map((c, i) => (
          <li key={`${i}-${c.text}`} className="group flex items-start gap-2 rounded px-1 py-0.5 hover:bg-surface-2">
            <input
              type="checkbox"
              className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[rgb(var(--accent))]"
              checked={c.done}
              disabled={!canWrite || pending}
              aria-label={`Mark “${c.text}” as ${c.done ? "not met" : "met"}`}
              onChange={() => void write(items.map((x, j) => (j === i ? { ...x, done: !x.done } : x))).catch(() => undefined)}
            />
            {editing === i ? (
              <Input
                autoFocus
                value={editText}
                maxLength={1000}
                aria-label="Criterion text"
                onChange={(e) => setEditText(e.target.value)}
                onBlur={() => commitEdit(i)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") commitEdit(i);
                  else if (e.key === "Escape") {
                    e.stopPropagation();
                    setEditing(null);
                  }
                }}
                className="!h-6 flex-1 !text-xs"
              />
            ) : (
              <button
                type="button"
                disabled={!canWrite}
                onClick={() => {
                  setEditing(i);
                  setEditText(c.text);
                }}
                className={cn("min-w-0 flex-1 break-words text-left text-[13px] disabled:cursor-default", c.done ? "text-fg-muted line-through decoration-fg-faint" : "text-fg")}
              >
                {c.text}
              </button>
            )}
            {canWrite && (
              <IconButton label={`Remove criterion “${c.text}”`} className="h-5 w-5 opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={() => void write(items.filter((_, j) => j !== i)).catch(() => undefined)}>
                <Trash2 className="h-3 w-3" aria-hidden />
              </IconButton>
            )}
          </li>
        ))}
      </ul>
      {canWrite && items.length < 50 && (
        <form onSubmit={add} className="flex gap-1.5">
          <Input value={draft} maxLength={1000} onChange={(e) => setDraft(e.target.value)} placeholder="Add a criterion, e.g. “Injected instructions are treated as data”" aria-label="New acceptance criterion" className="!h-7 !text-xs" />
          <Button size="sm" type="submit" disabled={!draft.trim()} loading={pending}>
            Add
          </Button>
        </form>
      )}
    </div>
  );
}

function RelatedFiles({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const { save, pending } = useSaveTask(task.id);
  const [draft, setDraft] = useState("");
  const files = task.related_files;
  const add = (e: FormEvent) => {
    e.preventDefault();
    const path = draft.trim();
    if (!path || files.includes(path)) return;
    void save({ related_files: [...files, path] }, "Related files").then(() => setDraft(""), () => undefined);
  };
  return (
    <Section
      title="Related files"
      description="Repository paths relevant to the fix. Fix-context generation checks that they exist and never includes sensitive files."
      bodyClassName="space-y-2"
    >
      {files.length === 0 && <p className="text-xs text-fg-faint">No files listed.</p>}
      <ul className="space-y-0.5">
        {files.map((f) => (
          <li key={f} className="group flex items-center gap-2 rounded px-1 py-0.5 hover:bg-surface-2">
            <FileCode2 className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={f}>
              {f}
            </span>
            {canWrite && (
              <IconButton label={`Remove ${f}`} className="h-5 w-5 opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={() => void save({ related_files: files.filter((x) => x !== f) }, "Related files").catch(() => undefined)}>
                <Trash2 className="h-3 w-3" aria-hidden />
              </IconButton>
            )}
          </li>
        ))}
      </ul>
      {canWrite && (
        <form onSubmit={add} className="flex gap-1.5">
          <Input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="backend/app/engines/detection/injection.py" aria-label="Add related file path" className="!h-7 font-mono !text-xs" />
          <Button size="sm" type="submit" icon={<Plus className="h-3 w-3" aria-hidden />} disabled={!draft.trim()} loading={pending}>
            Add
          </Button>
        </form>
      )}
    </Section>
  );
}

export function DetailsSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const { save } = useSaveTask(task.id);
  return (
    <div className="space-y-4">
      <Section title="Description">
        <MarkdownField label="Description" hideLabel value={task.description} canEdit={canWrite} placeholder="Describe the problem, its impact and any constraints." rows={8} onSave={(v) => save({ description: v }, "Description")} />
      </Section>
      <Section title="Problem definition" description="What happens, what should happen and how to see it. Used verbatim in generated fix context." bodyClassName="space-y-4">
        <MarkdownField label="Reproduction steps" value={task.reproduction_steps} canEdit={canWrite} placeholder="1. … 2. … 3. …" onSave={(v) => save({ reproduction_steps: v }, "Reproduction steps")} />
        <div className="grid gap-4 md:grid-cols-2">
          <MarkdownField label="Expected behaviour" value={task.expected_behaviour} canEdit={canWrite} placeholder="What should happen." rows={4} onSave={(v) => save({ expected_behaviour: v }, "Expected behaviour")} />
          <MarkdownField label="Actual behaviour" value={task.actual_behaviour} canEdit={canWrite} placeholder="What happens instead." rows={4} onSave={(v) => save({ actual_behaviour: v }, "Actual behaviour")} />
        </div>
        <CriteriaChecklist task={task} canWrite={canWrite} />
      </Section>
      <RelatedFiles task={task} canWrite={canWrite} />
    </div>
  );
}
