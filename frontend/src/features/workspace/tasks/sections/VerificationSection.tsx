/**
 * Verification: the evidence that a fix works. Runs are recorded by people (test run, review,
 * manual check, deployment, replay) or produced by running a Simulation Lab scenario through the
 * real pipeline. Only these runs change the task's verification status.
 */
import { useId, useState, type FormEvent } from "react";
import { ExternalLink, FlaskConical, Plus, ShieldCheck } from "lucide-react";
import { CodeBlock, EntityLink, Section, safeHref } from "@/components/data";
import { Badge, Button, EmptyState, Field, Input, Select, Textarea, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { humanize, type Tone } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useRecordVerification, useVerifyWithSimulation } from "../../api";
import { VERIFICATION_KINDS, type TaskDetail, type VerificationKind, type VerificationRun, type VerificationRunStatus } from "../../types";
import { describeError, useSimulationScenarios } from "../hooks";
import { VerificationStatusBadge } from "../taskBits";

const KIND_LABELS: Record<VerificationKind, string> = {
  test_run: "Test run",
  code_review: "Code review",
  manual: "Manual check",
  deployment: "Deployment check",
  simulation: "Simulation",
  replay: "Replay",
};

const RUN_TONES: Record<VerificationRunStatus, Tone> = { passed: "ok", failed: "danger", error: "danger", pending: "warn" };
const MANUAL_KINDS = VERIFICATION_KINDS.filter((k) => k !== "simulation");

function RunRow({ run, attemptNumber }: { run: VerificationRun; attemptNumber: number | null }) {
  const href = run.evidence_url ? safeHref(run.evidence_url) : null;
  return (
    <li className="rounded-md border border-border bg-surface-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={RUN_TONES[run.status]} dot>
          {humanize(run.status)}
        </Badge>
        <span className="text-[13px] font-medium text-fg">{KIND_LABELS[run.kind] ?? humanize(run.kind)}</span>
        {attemptNumber !== null && <span className="text-xs text-fg-muted">for attempt {attemptNumber}</span>}
        {run.simulation_run_id && <EntityLink type="simulation_run" id={run.simulation_run_id} label="Simulation run" />}
        <span className="ml-auto text-2xs text-fg-faint" title={formatDateTime(run.created_at)}>
          {run.created_by?.name ?? "ContextOS"} · {timeAgo(run.created_at)}
        </span>
      </div>
      {run.summary && <p className="mt-1.5 whitespace-pre-wrap break-words text-xs text-fg">{run.summary}</p>}
      {run.command && <CodeBlock code={run.command} language="shell" className="mt-2" />}
      {href && (
        <a href={href} target="_blank" rel="noreferrer noopener" className="mt-1.5 inline-flex items-center gap-1 text-xs text-accent hover:underline">
          Evidence <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      )}
      <div className="mt-1.5 text-2xs text-fg-faint">Task status after this run: {humanize(run.task_verification_status)}</div>
    </li>
  );
}

function RecordRunForm({ task, onDone }: { task: TaskDetail; onDone: () => void }) {
  const ids = { kind: useId(), status: useId(), summary: useId(), command: useId(), url: useId(), attempt: useId() };
  const toast = useToast();
  const record = useRecordVerification();
  const [kind, setKind] = useState<VerificationKind>("test_run");
  const [status, setStatus] = useState<VerificationRunStatus>("passed");
  const [summary, setSummary] = useState("");
  const [command, setCommand] = useState("");
  const [url, setUrl] = useState("");
  const [attempt, setAttempt] = useState(task.fix_attempts.length > 0 ? task.fix_attempts[task.fix_attempts.length - 1].id : "");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    record.mutate(
      { taskId: task.id, kind, status, summary: summary.trim(), command: command.trim() || null, evidence_url: url.trim() || null, fix_attempt_id: attempt || null },
      {
        onSuccess: (run) => {
          toast.success(`Verification ${run.status === "pending" ? "recorded as pending" : run.status}`, `Task verification status: ${humanize(run.task_verification_status)}.`);
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Kind" htmlFor={ids.kind}>
          <Select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value as VerificationKind)}>
            {MANUAL_KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Result" htmlFor={ids.status}>
          <Select id={ids.status} value={status} onChange={(e) => setStatus(e.target.value as VerificationRunStatus)}>
            <option value="passed">Passed</option>
            <option value="failed">Failed</option>
            <option value="error">Errored</option>
            <option value="pending">Pending</option>
          </Select>
        </Field>
        <Field label="For fix attempt" htmlFor={ids.attempt}>
          <Select id={ids.attempt} value={attempt} onChange={(e) => setAttempt(e.target.value)}>
            <option value="">Not tied to an attempt</option>
            {task.fix_attempts.map((a, i) => (
              <option key={a.id} value={a.id}>
                Attempt {i + 1} ({humanize(a.status)})
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <Field label="What was checked" htmlFor={ids.summary} hint="Be specific: what you ran or reviewed and what you observed.">
        <Textarea id={ids.summary} rows={3} required value={summary} maxLength={20_000} onChange={(e) => setSummary(e.target.value)} />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Command (optional)" htmlFor={ids.command}>
          <Input id={ids.command} value={command} maxLength={4000} onChange={(e) => setCommand(e.target.value)} placeholder="pytest -q tests/security" className="font-mono !text-xs" />
        </Field>
        <Field label="Evidence URL (optional)" htmlFor={ids.url}>
          <Input id={ids.url} type="url" value={url} maxLength={2048} onChange={(e) => setUrl(e.target.value)} placeholder="https://ci.example.com/run/123" />
        </Field>
      </div>
      {record.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(record.error)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onDone} disabled={record.isPending}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" type="submit" loading={record.isPending} disabled={!summary.trim()}>
          Record verification
        </Button>
      </div>
    </form>
  );
}

function SimulationForm({ task, onDone }: { task: TaskDetail; onDone: () => void }) {
  const ids = { scenario: useId(), attempt: useId() };
  const toast = useToast();
  const scenarios = useSimulationScenarios(true);
  const verify = useVerifyWithSimulation();
  const [scenarioId, setScenarioId] = useState("");
  const [attempt, setAttempt] = useState("");
  const chosen = scenarios.data?.find((s) => s.id === scenarioId);
  const unavailable = scenarios.error instanceof ApiError && (scenarios.error.status === 404 || scenarios.error.status === 503);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    verify.mutate(
      { taskId: task.id, scenarioId, fixAttemptId: attempt || undefined },
      {
        onSuccess: (run) => {
          toast.success(`Simulation ${run.status}`, `Recorded as verification. Task status: ${humanize(run.task_verification_status)}.`);
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
      <p className="text-xs text-fg-muted">
        Runs the scenario through the real detection and policy pipeline with synthetic data (flagged as simulation). The result — not your choice — sets the verification outcome.
      </p>
      {unavailable ? (
        <p className="text-xs text-warn">The Simulation Lab is not available in this deployment, so scenarios cannot be listed.</p>
      ) : scenarios.error ? (
        <p role="alert" className="text-xs text-danger">
          Could not load scenarios: {describeError(scenarios.error)}
        </p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-[1fr_200px]">
          <Field label="Scenario" htmlFor={ids.scenario} hint={chosen?.description ?? undefined}>
            <Select id={ids.scenario} value={scenarioId} required disabled={scenarios.isLoading} onChange={(e) => setScenarioId(e.target.value)}>
              <option value="">{scenarios.isLoading ? "Loading scenarios…" : "Choose a scenario…"}</option>
              {(scenarios.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                  {s.category ? ` · ${humanize(s.category)}` : ""}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="For fix attempt" htmlFor={ids.attempt}>
            <Select id={ids.attempt} value={attempt} onChange={(e) => setAttempt(e.target.value)}>
              <option value="">Not tied to an attempt</option>
              {task.fix_attempts.map((a, i) => (
                <option key={a.id} value={a.id}>
                  Attempt {i + 1}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      )}
      {verify.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(verify.error)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onDone} disabled={verify.isPending}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" type="submit" loading={verify.isPending} disabled={!scenarioId || unavailable} icon={<FlaskConical className="h-3.5 w-3.5" aria-hidden />}>
          Run simulation
        </Button>
      </div>
    </form>
  );
}

export function VerificationSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const [mode, setMode] = useState<"record" | "simulate" | null>(null);
  const runs = [...task.verification_runs].sort((a, b) => b.created_at.localeCompare(a.created_at));
  const attemptNumbers = new Map(task.fix_attempts.map((a, i) => [a.id, i + 1]));

  return (
    <Section
      title={
        <span className="inline-flex items-center gap-2">
          Verification <VerificationStatusBadge status={task.verification_status} />
        </span>
      }
      description="Evidence that the fix works. The verification status changes only through these runs; a failed run after a pass marks the task as failed again."
      actions={
        canWrite && mode === null ? (
          <>
            <Button size="xs" variant="outline" icon={<FlaskConical className="h-3 w-3" aria-hidden />} onClick={() => setMode("simulate")}>
              Verify with simulation
            </Button>
            <Button size="xs" variant="outline" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setMode("record")}>
              Record run
            </Button>
          </>
        ) : undefined
      }
      bodyClassName="space-y-2"
    >
      {mode === "record" && <RecordRunForm task={task} onDone={() => setMode(null)} />}
      {mode === "simulate" && <SimulationForm task={task} onDone={() => setMode(null)} />}
      {runs.length === 0 && mode === null ? (
        <EmptyState
          className="py-6"
          icon={<ShieldCheck className="h-4 w-4" aria-hidden />}
          title="Not verified"
          description="No verification run yet. Columns with a verification gate will refuse this task until a run passes."
        />
      ) : (
        <ol className="space-y-2">
          {runs.map((r) => (
            <RunRow key={r.id} run={r} attemptNumber={r.fix_attempt_id ? (attemptNumbers.get(r.fix_attempt_id) ?? null) : null} />
          ))}
        </ol>
      )}
    </Section>
  );
}
