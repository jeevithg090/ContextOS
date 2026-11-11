/**
 * Attachments: logs, stack traces, notes and links. Text is redacted by the server before it is
 * stored, so a pasted token never reaches the database in raw form.
 */
import { useId, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { ExternalLink, FileText, Paperclip, Plus, Trash2, Upload } from "lucide-react";
import { CodeBlock, ConfirmDialog, REDACTION_PREFIX, Section, safeHref } from "@/components/data";
import { Badge, Button, EmptyState, Field, IconButton, Input, Select, Textarea, useToast } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useAddAttachment, useDeleteAttachment } from "../../api";
import { ATTACHMENT_MAX_BYTES, type AttachmentKind, type TaskAttachment, type TaskDetail } from "../../types";
import { describeError } from "../hooks";

const KIND_LABELS: Record<AttachmentKind, string> = { log: "Log", stack_trace: "Stack trace", note: "Note", link: "Link" };

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const byteLength = (text: string) => new TextEncoder().encode(text).length;

function AttachmentRow({ item, canWrite, onDelete }: { item: TaskAttachment; canWrite: boolean; onDelete: () => void }) {
  const href = item.url ? safeHref(item.url) : null;
  return (
    <li className="space-y-1.5 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <FileText className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        <span className="min-w-0 truncate text-[13px] font-medium text-fg">{item.name}</span>
        <Badge>{KIND_LABELS[item.kind]}</Badge>
        {item.size > 0 && <span className="num text-2xs text-fg-faint">{formatBytes(item.size)}</span>}
        <span className="ml-auto text-2xs text-fg-faint">
          {item.created_by?.name ?? "System"} · {timeAgo(item.created_at)}
        </span>
        {canWrite && (
          <IconButton label={`Delete attachment ${item.name}`} className="h-6 w-6" onClick={onDelete}>
            <Trash2 className="h-3 w-3" aria-hidden />
          </IconButton>
        )}
      </div>
      {href && (
        <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex max-w-full items-center gap-1 truncate text-xs text-accent hover:underline">
          <span className="truncate">{item.url}</span>
          <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
        </a>
      )}
      {item.content && <CodeBlock code={item.content} language={item.kind === "note" ? null : item.kind === "stack_trace" ? "trace" : "log"} maxHeight={180} />}
    </li>
  );
}

function AddAttachmentForm({ taskId, onDone }: { taskId: string; onDone: () => void }) {
  const ids = { name: useId(), kind: useId(), url: useId(), content: useId() };
  const toast = useToast();
  const add = useAddAttachment();
  const fileRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<AttachmentKind>("log");
  const [url, setUrl] = useState("");
  const [content, setContent] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);
  const size = byteLength(content);
  const tooBig = size > ATTACHMENT_MAX_BYTES;

  const loadFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setFileError(null);
    if (file.size > ATTACHMENT_MAX_BYTES) {
      setFileError(`${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(ATTACHMENT_MAX_BYTES)}. Attach the relevant excerpt instead.`);
      return;
    }
    file.text().then(
      (text) => {
        setContent(text);
        if (!name.trim()) setName(file.name);
      },
      () => setFileError(`${file.name} could not be read as text.`),
    );
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (tooBig) return;
    add.mutate(
      { taskId, name: name.trim(), kind, url: kind === "link" ? url.trim() || null : null, content: kind === "link" ? null : content },
      {
        onSuccess: (a) => {
          const redacted = !!a.content?.includes(REDACTION_PREFIX) && !content.includes(REDACTION_PREFIX);
          toast.success("Attachment added", redacted ? "Secrets in the text were redacted before storage." : undefined);
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
      <div className="grid gap-3 sm:grid-cols-[1fr_160px]">
        <Field label="Name" htmlFor={ids.name}>
          <Input id={ids.name} value={name} maxLength={300} required onChange={(e) => setName(e.target.value)} placeholder="gateway-error.log" />
        </Field>
        <Field label="Kind" htmlFor={ids.kind}>
          <Select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value as AttachmentKind)}>
            {(Object.keys(KIND_LABELS) as AttachmentKind[]).map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      {kind === "link" ? (
        <Field label="URL" htmlFor={ids.url}>
          <Input id={ids.url} type="url" required value={url} maxLength={2048} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" />
        </Field>
      ) : (
        <Field
          label="Content"
          htmlFor={ids.content}
          error={tooBig ? `Too large: ${formatBytes(size)} of ${formatBytes(ATTACHMENT_MAX_BYTES)}.` : fileError}
          hint={`${formatBytes(size)} of ${formatBytes(ATTACHMENT_MAX_BYTES)} · secrets are redacted by the server before storage.`}
        >
          <Textarea id={ids.content} rows={6} required value={content} onChange={(e) => setContent(e.target.value)} className="font-mono text-xs" placeholder="Paste the log excerpt or stack trace" />
        </Field>
      )}
      {add.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(add.error)}
        </p>
      )}
      <div className="flex items-center justify-between gap-2">
        {kind !== "link" ? (
          <>
            <input ref={fileRef} type="file" accept=".log,.txt,.json,.md,.trace,text/*" className="sr-only" onChange={loadFile} aria-label="Load attachment content from a text file" tabIndex={-1} />
            <Button size="sm" variant="ghost" icon={<Upload className="h-3.5 w-3.5" aria-hidden />} onClick={() => fileRef.current?.click()}>
              Load from file
            </Button>
          </>
        ) : (
          <span />
        )}
        <span className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={onDone} disabled={add.isPending}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" type="submit" loading={add.isPending} disabled={!name.trim() || tooBig || (kind === "link" ? !url.trim() : !content.trim())}>
            Attach
          </Button>
        </span>
      </div>
    </form>
  );
}

export function AttachmentsSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const toast = useToast();
  const remove = useDeleteAttachment();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<TaskAttachment | null>(null);
  return (
    <Section
      title="Attachments"
      description="Logs, stack traces, notes and links (text up to 100 KB). Secrets are redacted before storage."
      actions={
        canWrite && !adding ? (
          <Button size="xs" variant="outline" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setAdding(true)}>
            Attach
          </Button>
        ) : undefined
      }
    >
      {adding && <AddAttachmentForm taskId={task.id} onDone={() => setAdding(false)} />}
      {task.attachments.length === 0 && !adding ? (
        <EmptyState className="py-6" icon={<Paperclip className="h-4 w-4" aria-hidden />} title="No attachments" description="Attach the log or stack trace that shows the problem." />
      ) : (
        <ul className="divide-y divide-border/70">
          {task.attachments.map((a) => (
            <AttachmentRow key={a.id} item={a} canWrite={canWrite} onDelete={() => setDeleting(a)} />
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        destructive
        title={`Delete “${deleting?.name ?? "attachment"}”?`}
        description="The attachment is removed from the task. This cannot be undone."
        confirmLabel="Delete attachment"
        onConfirm={async () => {
          if (!deleting) return;
          await remove.mutateAsync({ taskId: task.id, attachmentId: deleting.id });
          toast.success("Attachment deleted");
        }}
      />
    </Section>
  );
}
