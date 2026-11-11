/**
 * Security context: references to recorded findings, sessions, context receipts, policy decisions
 * and other records. References point at the evidence; they never copy it.
 */
import { useId, useState, type FormEvent } from "react";
import { Plus, ShieldAlert, Trash2 } from "lucide-react";
import { ConfirmDialog, EntityLink, Section, entityTypeLabel } from "@/components/data";
import { Badge, Button, EmptyState, Field, IconButton, Input, Select, useToast } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useAddRef, useRemoveRef } from "../../api";
import { REF_TYPES, type RefType, type TaskDetail, type TaskRef } from "../../types";
import { describeError } from "../hooks";

const REF_LABELS: Partial<Record<RefType, string>> = { context_item: "Context receipt", tool_invocation: "Tool call", policy_decision: "Policy decision" };
const refLabel = (t: string) => REF_LABELS[t as RefType] ?? entityTypeLabel(t);
/** Id prefixes (app.core.ids) so the placeholder shows what a valid id looks like. */
const ID_HINTS: Record<RefType, string> = {
  finding: "fnd_…",
  incident: "inc_…",
  event: "evt_…",
  session: "asn_…",
  agent: "agt_…",
  tool_invocation: "inv_…",
  policy_decision: "dec_…",
  context_item: "ctx_…",
  source: "src_…",
  approval: "apr_…",
  destination: "dst_…",
};

function RefRow({ refItem, canWrite, onRemove }: { refItem: TaskRef; canWrite: boolean; onRemove: () => void }) {
  return (
    <li className="group flex items-start gap-3 px-4 py-2.5">
      <div className="w-28 shrink-0 pt-0.5 text-2xs uppercase tracking-[0.06em] text-fg-faint">{refLabel(refItem.ref_type)}</div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          {refItem.exists ? (
            <EntityLink type={refItem.ref_type} id={refItem.ref_id} label={refItem.label} />
          ) : (
            <span className="font-mono text-xs text-fg-muted line-through" title="The referenced record no longer exists">
              {refItem.label || refItem.ref_id}
            </span>
          )}
          {!refItem.exists && <Badge tone="warn">Record deleted</Badge>}
        </div>
        {refItem.detail && <div className="mt-0.5 text-xs text-fg-muted">{refItem.detail}</div>}
        {refItem.note && <div className="mt-0.5 text-xs text-fg">{refItem.note}</div>}
        <div className="mt-0.5 font-mono text-2xs text-fg-faint">
          {refItem.ref_id} · linked {timeAgo(refItem.created_at)}
        </div>
      </div>
      {canWrite && (
        <IconButton label={`Remove reference ${refItem.label || refItem.ref_id}`} className="opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={onRemove}>
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
      )}
    </li>
  );
}

function AddRefForm({ taskId, onDone }: { taskId: string; onDone: () => void }) {
  const ids = { type: useId(), id: useId(), note: useId() };
  const toast = useToast();
  const add = useAddRef();
  const [refType, setRefType] = useState<RefType>("finding");
  const [refId, setRefId] = useState("");
  const [note, setNote] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(
      { taskId, ref_type: refType, ref_id: refId.trim(), note: note.trim() || null },
      {
        onSuccess: (ref) => {
          toast.success("Security context linked", ref.label);
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 border-t border-border bg-surface-2/40 px-4 py-3">
      <div className="grid gap-3 sm:grid-cols-[160px_1fr]">
        <Field label="Record type" htmlFor={ids.type}>
          <Select id={ids.type} value={refType} onChange={(e) => setRefType(e.target.value as RefType)}>
            {REF_TYPES.map((t) => (
              <option key={t} value={t}>
                {refLabel(t)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Record id" htmlFor={ids.id} hint="Copy it from the record's page. It must exist in this organisation.">
          <Input id={ids.id} value={refId} maxLength={40} required placeholder={ID_HINTS[refType]} onChange={(e) => setRefId(e.target.value)} className="font-mono !text-xs" />
        </Field>
      </div>
      <Field label="Why it matters (optional)" htmlFor={ids.note}>
        <Input id={ids.note} value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Session where the injected instruction was followed" />
      </Field>
      {add.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(add.error)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onDone} disabled={add.isPending}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" type="submit" loading={add.isPending} disabled={!refId.trim()}>
          Link record
        </Button>
      </div>
    </form>
  );
}

export function SecurityContextSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const toast = useToast();
  const remove = useRemoveRef();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<TaskRef | null>(null);

  return (
    <Section
      title="Security context"
      description="Recorded evidence this task is about. Links point at the original records, which stay the source of truth."
      flush
      actions={
        canWrite && !adding ? (
          <Button size="xs" variant="outline" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setAdding(true)}>
            Add reference
          </Button>
        ) : undefined
      }
    >
      {task.refs.length === 0 && !adding ? (
        <EmptyState
          className="py-8"
          icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
          title="No security context linked"
          description="Link the finding, session, context receipt or policy decision this work responds to, so a fix can be checked against the real evidence."
        />
      ) : (
        <ul className="divide-y divide-border/70">
          {task.refs.map((r) => (
            <RefRow key={r.id} refItem={r} canWrite={canWrite} onRemove={() => setRemoving(r)} />
          ))}
        </ul>
      )}
      {adding && <AddRefForm taskId={task.id} onDone={() => setAdding(false)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title="Remove this reference?"
        description="The record itself is not changed; only its link to this task is removed."
        confirmLabel="Remove reference"
        onConfirm={async () => {
          if (!removing) return;
          await remove.mutateAsync({ taskId: task.id, refId: removing.id });
          toast.success("Reference removed");
        }}
      >
        {removing && <p className="text-xs">{refLabel(removing.ref_type)}: {removing.label || removing.ref_id}</p>}
      </ConfirmDialog>
    </Section>
  );
}
