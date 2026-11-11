import { useEffect, useId, useState } from "react";
import { Button, Dialog, Field, Select } from "@/components/ui";
import type { TaskCard } from "../types";
import { useAiCatalogue, useCreateContextPack } from "./api";
import { ChipsInput } from "./controls";
import { mutationMessage } from "./hooks";
import { formatCount, suggestedProfile } from "./meta";
import { TaskPicker } from "./TaskPicker";
import type { ContextPack, PackProfile } from "./types";

/** Build and store a context pack for a task: pick the task, a profile and optional extra paths. */
export function BuildPackDialog({ open, onOpenChange, onBuilt }: { open: boolean; onOpenChange: (open: boolean) => void; onBuilt: (pack: ContextPack) => void }) {
  const id = useId();
  const catalogue = useAiCatalogue();
  const build = useCreateContextPack();
  const [task, setTask] = useState<TaskCard | null>(null);
  const [profile, setProfile] = useState<PackProfile>("standard");
  const [chosen, setChosen] = useState(false);
  const [paths, setPaths] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTask(null);
      setProfile("standard");
      setChosen(false);
      setPaths([]);
      setError(null);
      build.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const pick = (t: TaskCard) => {
    setTask(t);
    if (!chosen) setProfile(suggestedProfile(t, "implement_fix"));
  };
  const selected = catalogue.data?.profiles.find((p) => p.key === profile);
  const suggested = task ? suggestedProfile(task, "implement_fix") : null;

  const submit = () => {
    if (!task) return setError("Choose a task first.");
    setError(null);
    build.mutate(
      { task_id: task.id, profile, extra_paths: paths },
      {
        onSuccess: (pack) => {
          onBuilt(pack);
          onOpenChange(false);
        },
        onError: (err) => setError(mutationMessage(err)),
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !build.isPending && onOpenChange(o)}
      title="Build a context pack"
      description="Collects the task's records and the repository files that matter for it, checks every path, and stores the result so you can inspect it."
      className="w-[min(720px,calc(100vw-32px))]"
      footer={
        <>
          <Button variant="ghost" disabled={build.isPending} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={build.isPending} disabled={!task} onClick={submit}>
            Build pack{task ? ` for ${task.key}` : ""}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <p className="mb-2 text-xs font-medium text-fg-muted">Task{task && <span className="ml-2 font-mono text-fg">{task.key}</span>}</p>
          <TaskPicker onSelect={pick} selectedId={task?.id ?? null} listClassName="max-h-[240px]" />
        </div>
        <Field
          label="Profile"
          htmlFor={`${id}-profile`}
          hint={selected ? `${selected.description}${selected.includes_tests ? " Includes related tests." : ""}${selected.includes_git_history ? " Includes recent git history." : ""}` : undefined}
        >
          <Select
            id={`${id}-profile`}
            value={profile}
            onChange={(e) => {
              setProfile(e.target.value as PackProfile);
              setChosen(true);
            }}
          >
            {(catalogue.data?.profiles ?? []).map((p) => (
              <option key={p.key} value={p.key}>
                {p.label} — {formatCount(p.token_budget)} token budget{p.key === suggested ? " (suggested)" : ""}
              </option>
            ))}
          </Select>
        </Field>
        <ChipsInput
          label="Extra files to verify"
          values={paths}
          onChange={setPaths}
          placeholder="frontend/src/lib/api.ts"
          mono
          maxItems={50}
          hint="Optional repository-relative paths. Sensitive files (keys, credentials, .env) are never read."
        />
        {error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {error}
          </p>
        )}
      </div>
    </Dialog>
  );
}
