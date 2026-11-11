/**
 * Fix attempts: who (or which coding agent) tried a fix, with which generated prompt, and where the
 * change lives. "Claimed complete" is recorded as a claim; only verification runs verify a task.
 */
import { useId, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Info, Pencil, Plus, Wrench } from "lucide-react";
import { Section, safeHref } from "@/components/data";
import { Badge, Button, EmptyState, Field, Input, Select, Textarea, useToast } from "@/components/ui";
import type { Tone } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { usePrompts } from "../../ai/api";
import { useCreateFixAttempt, useUpdateFixAttempt } from "../../api";
import { FIX_STATUSES, type AgentTool, type FixAttempt, type FixAttemptPatch, type FixStatus, type SettableFixStatus, type TaskDetail } from "../../types";
import { describeError } from "../hooks";

export const AGENT_TOOL_LABELS: Record<AgentTool, string> = {
  claude_code: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  copilot: "Copilot",
  human: "Person (no agent)",
  other: "Other tool",
};

export const FIX_STATUS_META: Record<FixStatus, { label: string; tone: Tone }> = {
  planned: { label: "Planned", tone: "neutral" },
  in_progress: { label: "In progress", tone: "accent" },
  claimed_complete: { label: "Claimed complete", tone: "warn" },
  verified: { label: "Verified", tone: "ok" },
  failed: { label: "Failed", tone: "danger" },
  abandoned: { label: "Abandoned", tone: "neutral" },
};

const SETTABLE: SettableFixStatus[] = FIX_STATUSES.filter((s): s is SettableFixStatus => s !== "verified");

const CLAIM_NOTE = "“Claimed complete” records that an agent or person says the fix is done. It is a claim, not verification: the task is verified only when a verification run passes.";

function AttemptCard({ attempt, taskId, canWrite, index }: { attempt: FixAttempt; taskId: string; canWrite: boolean; index: number }) {
  const toast = useToast();
  const update = useUpdateFixAttempt();
  const [editing, setEditing] = useState(false);
  const [branch, setBranch] = useState(attempt.branch ?? "");
  const [commit, setCommit] = useState(attempt.commit_sha ?? "");
  const [prUrl, setPrUrl] = useState(attempt.pr_url ?? "");
  const [notes, setNotes] = useState(attempt.notes ?? "");
  const meta = FIX_STATUS_META[attempt.status];
  const pr = attempt.pr_url ? safeHref(attempt.pr_url) : null;

  const patch = (body: FixAttemptPatch, success: string) =>
    update.mutate(
      { taskId, attemptId: attempt.id, patch: body },
      {
        onSuccess: () => {
          toast.success(success, body.status === "claimed_complete" ? "Recorded as a claim. Record a verification run to verify the task." : undefined);
          setEditing(false);
        },
        onError: (e) => toast.error("Fix attempt not updated", describeError(e)),
      },
    );

  return (
    <li className="rounded-md border border-border bg-surface-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[13px] font-medium text-fg">Attempt {index}</span>
        <Badge tone={meta.tone} dot>
          {meta.label}
        </Badge>
        <span className="text-xs text-fg-muted">{AGENT_TOOL_LABELS[attempt.agent_tool]}</span>
        {attempt.generated_prompt_id && (
          <Link to={`/work/fix-context/${encodeURIComponent(taskId)}?prompt=${encodeURIComponent(attempt.generated_prompt_id)}`} className="text-xs text-accent hover:underline">
            Generated prompt
          </Link>
        )}
        <span className="ml-auto text-2xs text-fg-faint" title={formatDateTime(attempt.created_at)}>
          {attempt.created_by?.name ?? "System"} · {timeAgo(attempt.created_at)}
        </span>
      </div>
      {attempt.is_claim_only && (
        <p className="mt-2 flex items-start gap-1.5 text-2xs text-warn">
          <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
          Claim only — not verification.
        </p>
      )}
      {!editing && (attempt.branch || attempt.commit_sha || attempt.pr_url || attempt.notes) && (
        <dl className="mt-2 grid grid-cols-[72px_1fr] gap-x-3 gap-y-1 text-xs">
          {attempt.branch && (
            <>
              <dt className="text-fg-faint">Branch</dt>
              <dd className="truncate font-mono text-fg">{attempt.branch}</dd>
            </>
          )}
          {attempt.commit_sha && (
            <>
              <dt className="text-fg-faint">Commit</dt>
              <dd className="font-mono text-fg">{attempt.commit_sha.slice(0, 12)}</dd>
            </>
          )}
          {attempt.pr_url && (
            <>
              <dt className="text-fg-faint">PR</dt>
              <dd className="truncate">
                {pr ? (
                  <a href={pr} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                    {attempt.pr_url}
                  </a>
                ) : (
                  attempt.pr_url
                )}
              </dd>
            </>
          )}
          {attempt.notes && (
            <>
              <dt className="text-fg-faint">Notes</dt>
              <dd className="whitespace-pre-wrap break-words text-fg">{attempt.notes}</dd>
            </>
          )}
        </dl>
      )}
      {editing && (
        <form
          className="mt-3 space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            patch({ branch: branch.trim() || null, commit_sha: commit.trim() || null, pr_url: prUrl.trim() || null, notes: notes.trim() || null }, "Fix attempt updated");
          }}
        >
          <div className="grid gap-2 sm:grid-cols-2">
            <Input aria-label="Branch" placeholder="Branch" value={branch} onChange={(e) => setBranch(e.target.value)} className="font-mono !text-xs" />
            <Input aria-label="Commit SHA" placeholder="Commit SHA" value={commit} onChange={(e) => setCommit(e.target.value)} className="font-mono !text-xs" />
          </div>
          <Input aria-label="Pull request URL" type="url" placeholder="Pull request URL" value={prUrl} onChange={(e) => setPrUrl(e.target.value)} />
          <Textarea aria-label="Notes" placeholder="Notes" rows={3} value={notes} maxLength={20_000} onChange={(e) => setNotes(e.target.value)} />
          <div className="flex justify-end gap-2">
            <Button size="xs" variant="ghost" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button size="xs" variant="primary" type="submit" loading={update.isPending}>
              Save
            </Button>
          </div>
        </form>
      )}
      {canWrite && !editing && (
        <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-border/70 pt-2">
          {attempt.status === "verified" ? (
            <span className="text-2xs text-fg-faint">Verified by a passed verification run; the status can no longer be set by hand.</span>
          ) : (
            <Select
              aria-label={`Status of attempt ${index}`}
              value={attempt.status}
              disabled={update.isPending}
              onChange={(e) => patch({ status: e.target.value as SettableFixStatus }, `Attempt ${index} marked ${FIX_STATUS_META[e.target.value as FixStatus].label.toLowerCase()}`)}
              className="!h-7 !w-auto !text-xs"
            >
              {SETTABLE.map((s) => (
                <option key={s} value={s}>
                  {FIX_STATUS_META[s].label}
                </option>
              ))}
            </Select>
          )}
          <Button size="xs" variant="ghost" icon={<Pencil className="h-3 w-3" aria-hidden />} onClick={() => setEditing(true)}>
            Edit details
          </Button>
        </div>
      )}
    </li>
  );
}

function StartAttemptForm({ taskId, onDone }: { taskId: string; onDone: () => void }) {
  const ids = { tool: useId(), prompt: useId(), status: useId(), branch: useId(), notes: useId() };
  const toast = useToast();
  const create = useCreateFixAttempt();
  const prompts = usePrompts({ taskId, limit: 50 });
  const [tool, setTool] = useState<AgentTool>("claude_code");
  const [promptId, setPromptId] = useState("");
  const [status, setStatus] = useState<SettableFixStatus>("in_progress");
  const [branch, setBranch] = useState("");
  const [notes, setNotes] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      { taskId, agent_tool: tool, generated_prompt_id: promptId || null, status, branch: branch.trim() || null, notes: notes.trim() || null },
      {
        onSuccess: () => {
          toast.success("Fix attempt recorded", "If this column has a “fix attempt starts” rule, the task moves automatically.");
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Who is fixing it" htmlFor={ids.tool}>
          <Select id={ids.tool} value={tool} onChange={(e) => setTool(e.target.value as AgentTool)}>
            {(Object.keys(AGENT_TOOL_LABELS) as AgentTool[]).map((t) => (
              <option key={t} value={t}>
                {AGENT_TOOL_LABELS[t]}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Status" htmlFor={ids.status}>
          <Select id={ids.status} value={status} onChange={(e) => setStatus(e.target.value as SettableFixStatus)}>
            {SETTABLE.filter((s) => s !== "abandoned").map((s) => (
              <option key={s} value={s}>
                {FIX_STATUS_META[s].label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Branch (optional)" htmlFor={ids.branch}>
          <Input id={ids.branch} value={branch} onChange={(e) => setBranch(e.target.value)} className="font-mono !text-xs" />
        </Field>
      </div>
      <Field
        label="Generated prompt (optional)"
        htmlFor={ids.prompt}
        hint={prompts.data && prompts.data.items.length === 0 ? "No saved prompts for this task yet. Use “Generate Fix Context” to create one." : "Link the fix-context prompt the agent was given."}
      >
        <Select id={ids.prompt} value={promptId} onChange={(e) => setPromptId(e.target.value)} disabled={prompts.isLoading}>
          <option value="">None</option>
          {(prompts.data?.items ?? []).map((p) => (
            <option key={p.id} value={p.id}>
              {p.mode_label} · {p.preset_label} · v{p.version} ({timeAgo(p.created_at)})
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Notes (optional)" htmlFor={ids.notes}>
        <Textarea id={ids.notes} rows={2} value={notes} maxLength={20_000} onChange={(e) => setNotes(e.target.value)} />
      </Field>
      {status === "claimed_complete" && <p className="text-2xs text-warn">{CLAIM_NOTE}</p>}
      {create.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(create.error)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onDone} disabled={create.isPending}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" type="submit" loading={create.isPending}>
          Record attempt
        </Button>
      </div>
    </form>
  );
}

export function FixAttemptsSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const [starting, setStarting] = useState(false);
  const attempts = [...task.fix_attempts].sort((a, b) => a.created_at.localeCompare(b.created_at));
  return (
    <Section
      title="Fix attempts"
      description={CLAIM_NOTE}
      actions={
        canWrite && !starting ? (
          <Button size="xs" variant="outline" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setStarting(true)}>
            Start attempt
          </Button>
        ) : undefined
      }
      bodyClassName="space-y-2"
    >
      {starting && <StartAttemptForm taskId={task.id} onDone={() => setStarting(false)} />}
      {attempts.length === 0 && !starting ? (
        <EmptyState className="py-6" icon={<Wrench className="h-4 w-4" aria-hidden />} title="No fix attempts yet" description="Record who is fixing this and with which prompt, so the outcome can be traced." />
      ) : (
        <ol className="space-y-2">
          {attempts
            .map((a, i) => ({ a, n: i + 1 }))
            .reverse()
            .map(({ a, n }) => (
              <AttemptCard key={a.id} attempt={a} taskId={task.id} canWrite={canWrite} index={n} />
            ))}
        </ol>
      )}
    </Section>
  );
}
