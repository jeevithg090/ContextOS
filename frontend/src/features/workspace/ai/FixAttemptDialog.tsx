import { useEffect, useId, useState, type FormEvent } from "react";
import { Button, Dialog, Field, Input, Select, Textarea } from "@/components/ui";
import { useCreateFixAttempt } from "../api";
import type { AgentTool, FixAttempt } from "../types";
import { mutationMessage } from "./hooks";
import { AGENT_TOOL_LABELS } from "./meta";

type StartStatus = "in_progress" | "planned";

/**
 * Record a fix attempt on the task, linked to the generated prompt. A fix attempt records who is
 * working on the fix and with which tool; it is not verification — the task stays unverified until
 * a verification run passes.
 */
export function FixAttemptDialog({
  open,
  onOpenChange,
  taskId,
  taskKey,
  defaultTool,
  ensurePromptId,
  needsSave,
  onStarted,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  taskId: string;
  taskKey: string;
  defaultTool: AgentTool;
  /** Resolves the saved prompt id, saving the draft first when needed. */
  ensurePromptId: () => Promise<string>;
  needsSave: boolean;
  onStarted: (attempt: FixAttempt) => void;
}) {
  const id = useId();
  const create = useCreateFixAttempt();
  const [tool, setTool] = useState<AgentTool>(defaultTool);
  const [status, setStatus] = useState<StartStatus>("in_progress");
  const [branch, setBranch] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setTool(defaultTool);
      setStatus("in_progress");
      setBranch("");
      setNotes("");
      setError(null);
    }
  }, [open, defaultTool]);

  const pending = saving || create.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    let promptId: string;
    try {
      setSaving(true);
      promptId = await ensurePromptId();
    } catch (err) {
      setError(`The prompt could not be saved: ${mutationMessage(err)}`);
      return;
    } finally {
      setSaving(false);
    }
    create.mutate(
      { taskId, agent_tool: tool, generated_prompt_id: promptId, status, branch: branch.trim() || null, notes: notes.trim() || null },
      {
        onSuccess: (attempt) => {
          onStarted(attempt);
          onOpenChange(false);
        },
        onError: (err) => setError(mutationMessage(err)),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !pending && onOpenChange(next)}
      title={`Start a fix attempt on ${taskKey}`}
      description="Records that a fix is underway with this prompt. It does not verify anything: the task stays unverified until a verification run passes."
      footer={
        <>
          <Button variant="ghost" disabled={pending} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form={`${id}-form`} loading={pending}>
            {needsSave ? "Save prompt and start" : "Start fix attempt"}
          </Button>
        </>
      }
    >
      <form id={`${id}-form`} onSubmit={submit} className="space-y-4">
        {needsSave && <p className="rounded border border-border bg-surface-2/60 px-3 py-2 text-xs text-fg-muted">This prompt is not saved yet. It will be saved to the task first so the fix attempt can link to it.</p>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Who runs the prompt" htmlFor={`${id}-tool`}>
            <Select id={`${id}-tool`} value={tool} onChange={(e) => setTool(e.target.value as AgentTool)}>
              {(Object.keys(AGENT_TOOL_LABELS) as AgentTool[]).map((t) => (
                <option key={t} value={t}>
                  {AGENT_TOOL_LABELS[t]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Status" htmlFor={`${id}-status`} hint={status === "in_progress" ? "Board automations for “fix attempt started” run when the attempt is in progress." : undefined}>
            <Select id={`${id}-status`} value={status} onChange={(e) => setStatus(e.target.value as StartStatus)}>
              <option value="in_progress">In progress — starting now</option>
              <option value="planned">Planned — not started</option>
            </Select>
          </Field>
        </div>
        <Field label="Branch" htmlFor={`${id}-branch`} hint="Optional. You can add the commit and pull request later on the task.">
          <Input id={`${id}-branch`} value={branch} maxLength={300} placeholder="fix/ctx-12-redact-tokens" className="font-mono text-xs" onChange={(e) => setBranch(e.target.value)} />
        </Field>
        <Field label="Notes" htmlFor={`${id}-notes`} hint="Optional. Secrets are redacted by the server.">
          <Textarea id={`${id}-notes`} value={notes} maxLength={20000} className="min-h-[60px] text-xs" onChange={(e) => setNotes(e.target.value)} />
        </Field>
        {error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}
