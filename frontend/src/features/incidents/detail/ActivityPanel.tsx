/** Investigator notes (composer) and the incident's activity feed, newest first. */
import { useId, useState } from "react";
import { Bot, MessageSquare } from "lucide-react";
import { Button, Kbd, Textarea, useToast } from "@/components/ui";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { errorMessage, useAddNote } from "../api";
import { ACTIVITY_LABELS } from "../meta";
import type { Activity, IncidentDetail } from "../types";

function NoteComposer({ incidentId }: { incidentId: string }) {
  const id = useId();
  const toast = useToast();
  const add = useAddNote(incidentId);
  const [body, setBody] = useState("");

  const submit = () => {
    const text = body.trim();
    if (!text || add.isPending) return;
    add.mutate(text, {
      onSuccess: () => setBody(""),
      onError: (err) => toast.error("Could not add the note", errorMessage(err)),
    });
  };

  return (
    <div className="space-y-2">
      <label htmlFor={id} className="sr-only">
        Add a note
      </label>
      <Textarea
        id={id}
        value={body}
        onChange={(e) => setBody(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
            e.preventDefault();
            submit();
          }
        }}
        rows={3}
        maxLength={8000}
        placeholder="What did you find? Decisions, hypotheses, next steps…"
      />
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs text-fg-faint">Secrets are redacted before the note is stored.</span>
        <Button size="sm" variant="primary" onClick={submit} loading={add.isPending} disabled={!body.trim()}>
          Add note <Kbd>⌘↵</Kbd>
        </Button>
      </div>
    </div>
  );
}

function Entry({ a }: { a: Activity }) {
  const system = a.actor.type === "system";
  const note = a.kind === "note";
  return (
    <li className="flex gap-2.5">
      <span
        className={cn(
          "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-2xs font-semibold",
          system ? "border-border text-fg-faint" : "border-accent/30 bg-accent/10 text-accent",
        )}
        aria-hidden
      >
        {system ? <Bot className="h-3.5 w-3.5" /> : note ? <MessageSquare className="h-3 w-3" /> : a.actor.name.slice(0, 1).toUpperCase()}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-1.5 text-xs">
          <span className="font-medium text-fg">{a.actor.name}</span>
          <span className="text-fg-muted">{ACTIVITY_LABELS[a.kind] ?? a.kind.replace(/_/g, " ")}</span>
          <time dateTime={a.created_at} title={formatDateTime(a.created_at)} className="text-2xs text-fg-faint">
            {timeAgo(a.created_at)}
          </time>
        </div>
        {a.body && (
          <p className={cn("mt-0.5 whitespace-pre-wrap break-words", note ? "rounded border border-border bg-surface-2/60 px-2.5 py-1.5 text-[13px] text-fg" : "text-xs text-fg-muted")}>{a.body}</p>
        )}
      </div>
    </li>
  );
}

export function ActivityPanel({ incident, canWrite }: { incident: IncidentDetail; canWrite: boolean }) {
  const [showAll, setShowAll] = useState(false);
  const entries = [...incident.activity].reverse();
  const visible = showAll ? entries : entries.slice(0, 12);
  return (
    <div className="space-y-4">
      {canWrite && <NoteComposer incidentId={incident.id} />}
      {entries.length === 0 ? (
        <p className="text-xs text-fg-muted">No activity yet.</p>
      ) : (
        <ol className="space-y-3" aria-label="Incident activity, newest first">
          {visible.map((a) => (
            <Entry key={a.id} a={a} />
          ))}
        </ol>
      )}
      {entries.length > visible.length && (
        <button type="button" className="text-xs text-accent hover:underline" onClick={() => setShowAll(true)}>
          Show {entries.length - visible.length} older entries
        </button>
      )}
    </div>
  );
}
