/** Inline editors: a click-to-edit title and a Markdown field with write / preview modes. */
import { useEffect, useState } from "react";
import { Pencil } from "lucide-react";
import { Markdown, SegmentedControl } from "@/components/data";
import { Button, Textarea } from "@/components/ui";
import { cn } from "@/lib/format";

export function InlineTitle({ value, onSave, canEdit, className }: { value: string; onSave: (next: string) => Promise<unknown>; canEdit: boolean; className?: string }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  const commit = async () => {
    const next = draft.trim();
    if (!next || next === value) {
      setEditing(false);
      setDraft(value);
      return;
    }
    setSaving(true);
    try {
      await onSave(next);
      setEditing(false);
    } catch {
      // The save hook already reported the error; keep the draft so nothing typed is lost.
    } finally {
      setSaving(false);
    }
  };

  if (editing) {
    return (
      <textarea
        autoFocus
        rows={2}
        value={draft}
        maxLength={300}
        disabled={saving}
        aria-label="Task title"
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => void commit()}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            void commit();
          } else if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            setDraft(value);
            setEditing(false);
          }
        }}
        className={cn("w-full resize-none rounded border border-accent/50 bg-surface-2 px-2 py-1 text-lg font-semibold leading-snug text-fg focus:outline-none", className)}
      />
    );
  }
  if (!canEdit) return <h1 className={cn("break-words text-lg font-semibold leading-snug text-fg", className)}>{value}</h1>;
  return (
    <h1 className={cn("group break-words text-lg font-semibold leading-snug text-fg", className)}>
      <button type="button" onClick={() => setEditing(true)} className="-mx-1 rounded px-1 text-left hover:bg-surface-2" title="Edit title">
        {value}
        <Pencil className="ml-1.5 inline h-3.5 w-3.5 align-baseline text-fg-faint opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
        <span className="sr-only"> (edit title)</span>
      </button>
    </h1>
  );
}

export interface MarkdownFieldProps {
  label: string;
  value: string;
  onSave: (next: string) => Promise<unknown>;
  canEdit: boolean;
  placeholder: string;
  /** Rows of the editor. */
  rows?: number;
  maxLength?: number;
  /** Hide the field label (when a section heading already names it). */
  hideLabel?: boolean;
}

export function MarkdownField({ label, value, onSave, canEdit, placeholder, rows = 6, maxLength = 50_000, hideLabel }: MarkdownFieldProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const [mode, setMode] = useState<"write" | "preview">("write");
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  const save = async () => {
    setSaving(true);
    try {
      await onSave(draft.trim());
      setEditing(false);
    } catch {
      // Reported by the save hook; the draft is kept.
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-1.5">
      {(!hideLabel || (canEdit && !editing)) && (
        <div className="flex items-center justify-between gap-2">
          {!hideLabel ? <div className="text-xs font-medium text-fg-muted">{label}</div> : <span />}
          {canEdit && !editing && (
            <Button size="xs" variant="ghost" icon={<Pencil className="h-3 w-3" aria-hidden />} onClick={() => {
                setMode("write");
                setEditing(true);
              }} aria-label={`Edit ${label.toLowerCase()}`}>
              Edit
            </Button>
          )}
        </div>
      )}
      {editing ? (
        <div className="space-y-2">
          <SegmentedControl<"write" | "preview">
            aria-label={`${label} editor mode`}
            value={mode}
            onChange={setMode}
            options={[
              { value: "write", label: "Write" },
              { value: "preview", label: "Preview" },
            ]}
          />
          {mode === "write" ? (
            <Textarea
              autoFocus
              rows={rows}
              value={draft}
              maxLength={maxLength}
              aria-label={label}
              placeholder={placeholder}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault();
                  void save();
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  e.stopPropagation();
                  setEditing(false);
                }
              }}
              className="font-mono text-xs"
            />
          ) : (
            <div className="min-h-[80px] rounded border border-border bg-surface-2 px-3 py-2">
              {draft.trim() ? <Markdown source={draft} headingOffset={2} /> : <p className="text-xs text-fg-faint">Nothing to preview.</p>}
            </div>
          )}
          <div className="flex items-center justify-between gap-2">
            <span className="text-2xs text-fg-faint">Markdown supported · ⌘/Ctrl + Enter to save · secrets are redacted on save</span>
            <span className="flex gap-1.5">
              <Button size="xs" variant="ghost" onClick={() => setEditing(false)} disabled={saving}>
                Cancel
              </Button>
              <Button size="xs" variant="primary" onClick={() => void save()} loading={saving} disabled={draft.trim() === value.trim()}>
                Save
              </Button>
            </span>
          </div>
        </div>
      ) : value.trim() ? (
        <Markdown source={value} headingOffset={2} />
      ) : (
        <p className="text-xs text-fg-faint">{canEdit ? placeholder : "Not provided."}</p>
      )}
    </div>
  );
}
