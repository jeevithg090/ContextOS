/**
 * Break a task into subtasks. The server drafts them deterministically from the task (nothing is
 * sent to an external AI provider); the user edits titles, descriptions, criteria and dependencies,
 * removes what is not wanted, and applies — subtasks and dependencies are created in one transaction.
 */
import { useEffect, useId, useState } from "react";
import { AlertTriangle, ListTree, Trash2 } from "lucide-react";
import { Button, Dialog, EmptyState, IconButton, Input, LoadingRows, Select, Textarea, useToast } from "@/components/ui";
import { humanize } from "@/lib/domain";
import { pluralize } from "@/lib/format";
import { PRIORITY_META, TASK_TYPE_LABELS } from "../analytics/taskMeta";
import { useApplyBreakdown, useBreakdownDrafts } from "../ai/api";
import type { SubtaskDraft } from "../ai/types";
import { validationErrors, workflowConflict } from "../api";
import { TASK_PRIORITIES, TASK_TYPES, type TaskDetail, type TaskPriority, type TaskType } from "../types";
import { cycleMembers, removeDraft, toggleDependency, toLines } from "./breakdownDrafts";
import { describeError } from "./hooks";

interface EditableDraft {
  title: string;
  description: string;
  task_type: TaskType;
  criteria: string;
  tests: string;
  depends_on: number[];
}

const toEditable = (d: SubtaskDraft): EditableDraft => ({
  title: d.title,
  description: d.description,
  task_type: d.task_type,
  criteria: d.acceptance_criteria.join("\n"),
  tests: d.testing_requirements.join("\n"),
  depends_on: [...d.depends_on],
});

const toDraft = (d: EditableDraft): SubtaskDraft => ({
  title: d.title.trim(),
  description: d.description.trim(),
  task_type: d.task_type,
  acceptance_criteria: toLines(d.criteria),
  testing_requirements: toLines(d.tests),
  depends_on: d.depends_on,
});

function DraftEditor({ draft, index, all, onChange, onRemove, inCycle }: { draft: EditableDraft; index: number; all: EditableDraft[]; onChange: (patch: Partial<EditableDraft>) => void; onRemove: () => void; inCycle: boolean }) {
  const base = useId();
  return (
    <li className={`rounded-md border p-3 ${inCycle ? "border-danger/50" : "border-border"} bg-surface-2/40`}>
      <div className="flex items-start gap-2">
        <span className="num mt-1.5 w-5 shrink-0 text-right text-xs text-fg-faint">{index + 1}.</span>
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex gap-2">
            <Input aria-label={`Subtask ${index + 1} title`} value={draft.title} maxLength={300} onChange={(e) => onChange({ title: e.target.value })} className="font-medium" />
            <Select aria-label={`Subtask ${index + 1} type`} value={draft.task_type} onChange={(e) => onChange({ task_type: e.target.value as TaskType })} className="!w-44 shrink-0 !text-xs">
              {TASK_TYPES.map((t) => (
                <option key={t} value={t}>
                  {TASK_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
            <IconButton label={`Remove subtask ${index + 1}`} onClick={onRemove}>
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </IconButton>
          </div>
          <Textarea aria-label={`Subtask ${index + 1} description`} rows={2} value={draft.description} onChange={(e) => onChange({ description: e.target.value })} className="min-h-[52px] text-xs" />
          <div className="grid gap-2 md:grid-cols-2">
            <label className="block space-y-1" htmlFor={`${base}-criteria`}>
              <span className="text-2xs text-fg-faint">Acceptance criteria (one per line)</span>
              <Textarea id={`${base}-criteria`} rows={3} value={draft.criteria} onChange={(e) => onChange({ criteria: e.target.value })} className="min-h-[64px] text-xs" />
            </label>
            <label className="block space-y-1" htmlFor={`${base}-tests`}>
              <span className="text-2xs text-fg-faint">Testing requirements (one per line)</span>
              <Textarea id={`${base}-tests`} rows={3} value={draft.tests} onChange={(e) => onChange({ tests: e.target.value })} className="min-h-[64px] text-xs" />
            </label>
          </div>
          {all.length > 1 && (
            <fieldset className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <legend className="sr-only">Subtask {index + 1} depends on</legend>
              <span className="text-2xs text-fg-faint">Depends on:</span>
              {all.map((other, j) =>
                j === index ? null : (
                  <label key={j} className="inline-flex cursor-pointer items-center gap-1 text-2xs text-fg-muted" title={other.title}>
                    <input type="checkbox" className="h-3 w-3 accent-[rgb(var(--accent))]" checked={draft.depends_on.includes(j)} onChange={() => onChange({ depends_on: toggleDependency(all, index, j)[index].depends_on })} />
                    {j + 1}
                  </label>
                ),
              )}
            </fieldset>
          )}
        </div>
      </div>
    </li>
  );
}

export function BreakdownDialog({ task, open, onOpenChange }: { task: TaskDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  return open ? <BreakdownBody task={task} onOpenChange={onOpenChange} /> : null;
}

function BreakdownBody({ task, onOpenChange }: { task: TaskDetail; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const generate = useBreakdownDrafts();
  const apply = useApplyBreakdown();
  const [plan, setPlan] = useState<string>("");
  const [drafts, setDrafts] = useState<EditableDraft[]>([]);
  const [priority, setPriority] = useState<TaskPriority>(task.priority);
  const [edited, setEdited] = useState(false);
  const result = generate.data;
  const { mutate: requestDrafts } = generate;

  useEffect(() => {
    requestDrafts(
      { task_id: task.id },
      {
        onSuccess: (r) => {
          setPlan(r.plan);
          setDrafts(r.drafts.map(toEditable));
        },
      },
    );
  }, [requestDrafts, task.id]);

  const regenerate = (nextPlan: string) => {
    setPlan(nextPlan);
    setEdited(false);
    requestDrafts(
      { task_id: task.id, ...(nextPlan ? { plan: nextPlan } : {}) },
      {
        onSuccess: (r) => {
          setPlan(r.plan);
          setDrafts(r.drafts.map(toEditable));
        },
      },
    );
  };

  const update = (index: number, patch: Partial<EditableDraft>) => {
    setEdited(true);
    setDrafts((all) => all.map((d, i) => (i === index ? { ...d, ...patch } : d)));
  };

  const cycles = cycleMembers(drafts);
  const untitled = drafts.some((d) => !d.title.trim());
  const conflict = workflowConflict(apply.error);
  const errors = validationErrors(apply.error);

  const submit = (overrideWip = false) =>
    apply.mutate(
      { task_id: task.id, drafts: drafts.map(toDraft), priority, override_wip: overrideWip },
      {
        onSuccess: (r) => {
          toast.success(`${pluralize(r.created.length, "subtask")} created`, r.dependencies.length ? `${pluralize(r.dependencies.length, "dependency", "dependencies")} added.` : undefined);
          onOpenChange(false);
        },
      },
    );

  return (
    <Dialog
      open
      onOpenChange={(next) => !apply.isPending && onOpenChange(next)}
      title={`Break down ${task.key}`}
      description="Drafts are generated on the ContextOS server from this task's own fields; nothing is sent to an external AI provider. Review and edit before creating anything."
      className="w-[min(880px,calc(100vw-32px))]"
      footer={
        <>
          <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={apply.isPending}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" loading={apply.isPending} disabled={drafts.length === 0 || untitled || cycles.length > 0 || generate.isPending} onClick={() => submit(false)}>
            Create {pluralize(drafts.length, "subtask")}
          </Button>
        </>
      }
    >
      {generate.isPending && drafts.length === 0 ? (
        <LoadingRows rows={4} />
      ) : generate.error ? (
        <EmptyState title="Could not draft subtasks" description={describeError(generate.error)} action={<Button size="sm" onClick={() => regenerate(plan)}>Try again</Button>} />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            {result && result.plans.length > 1 && (
              <label className="inline-flex items-center gap-2 text-xs text-fg-muted">
                Plan
                <Select
                  value={plan}
                  disabled={generate.isPending}
                  onChange={(e) => regenerate(e.target.value)}
                  className="!h-7 !w-auto !text-xs"
                >
                  {result.plans.map((p) => (
                    <option key={p} value={p}>
                      {humanize(p)}
                    </option>
                  ))}
                </Select>
              </label>
            )}
            {edited && result && result.plans.length > 1 && <span className="text-2xs text-fg-faint">Changing the plan replaces your edits.</span>}
            <label className="inline-flex items-center gap-2 text-xs text-fg-muted">
              Priority for new subtasks
              <Select value={priority} onChange={(e) => setPriority(e.target.value as TaskPriority)} className="!h-7 !w-auto !text-xs">
                {TASK_PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {PRIORITY_META[p].label}
                  </option>
                ))}
              </Select>
            </label>
          </div>
          {result?.note && <p className="text-xs text-fg-muted">{result.note}</p>}
          {result && result.existing_subtasks > 0 && (
            <p className="text-xs text-warn">This task already has {pluralize(result.existing_subtasks, "subtask")}. New ones are added alongside them.</p>
          )}
          {drafts.length === 0 ? (
            <EmptyState icon={<ListTree className="h-4 w-4" aria-hidden />} title="No drafts left" description="Every draft was removed. Choose a plan to regenerate, or cancel." />
          ) : (
            <ol className="space-y-2" aria-label="Subtask drafts">
              {drafts.map((d, i) => (
                <DraftEditor
                  key={i}
                  draft={d}
                  index={i}
                  all={drafts}
                  inCycle={cycles.includes(i + 1)}
                  onChange={(patch) => update(i, patch)}
                  onRemove={() => {
                    setEdited(true);
                    setDrafts((all) => removeDraft(all, i));
                  }}
                />
              ))}
            </ol>
          )}
          {cycles.length > 0 && (
            <p role="alert" className="flex items-center gap-1.5 text-xs text-danger">
              <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
              Subtasks {cycles.join(", ")} depend on each other in a cycle. Remove one of those dependencies.
            </p>
          )}
          {apply.error && (
            <div role="alert" className="space-y-2 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
              <p>{errors.length > 0 ? errors.join(" ") : (conflict?.message ?? describeError(apply.error))}</p>
              {conflict?.reason === "wip_limit_exceeded" && (
                <Button size="xs" variant="outline" onClick={() => submit(true)} loading={apply.isPending}>
                  Create anyway (override WIP limit)
                </Button>
              )}
            </div>
          )}
        </div>
      )}
    </Dialog>
  );
}
