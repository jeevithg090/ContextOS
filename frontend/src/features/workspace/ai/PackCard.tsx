import { useEffect, useId, useState } from "react";
import { Hammer, PackageOpen, RefreshCw } from "lucide-react";
import { Badge, Button, Select, Skeleton, useToast } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { cn, timeAgo } from "@/lib/format";
import { useContextPack, useContextPacks, useCreateContextPack } from "./api";
import { ChipsInput, TokenBudgetMeter } from "./controls";
import { mutationMessage } from "./hooks";
import { formatCount, suggestedProfile } from "./meta";
import { PackCounts } from "./PackDetail";
import type { AiCatalogue, PackProfile } from "./types";
import type { FixContextState } from "./useFixContextState";
import type { TaskDetail } from "../types";

/**
 * Context-pack controls in the configuration column: choose a profile, build (or rebuild) a stored
 * pack to inspect, or reuse one of the task's saved packs. Without a stored pack, generation builds
 * a fresh, unsaved pack for the chosen profile.
 */
export function PackCard({
  state,
  catalogue,
  task,
  canWrite,
  onInspect,
}: {
  state: FixContextState;
  catalogue: AiCatalogue;
  task: TaskDetail;
  canWrite: boolean;
  onInspect: () => void;
}) {
  const id = useId();
  const toast = useToast();
  const { config, pack: packRef } = state;
  const [extraPaths, setExtraPaths] = useState<string[]>([]);
  const pack = useContextPack(packRef?.id);
  const taskPacks = useContextPacks({ taskId: task.id, limit: 5 });
  const build = useCreateContextPack();
  const profile = catalogue.profiles.find((p) => p.key === config.profile);
  const suggested = suggestedProfile(task, config.mode);
  const latest = (taskPacks.data?.items ?? []).find((p) => p.id !== packRef?.id);
  const deleted = pack.error instanceof ApiError && pack.error.status === 404;

  const { detachPack } = state;
  useEffect(() => {
    if (deleted) {
      detachPack();
      toast.error("Context pack no longer exists", "It was deleted. Build a new pack or generate with a fresh one.");
    }
  }, [deleted, detachPack, toast]);

  const runBuild = () =>
    build.mutate(
      { task_id: task.id, profile: config.profile, extra_paths: extraPaths },
      {
        onSuccess: (created) => {
          state.selectPack(created);
          toast.success(`${created.profile_label} pack built`, `${created.counts.included} of ${created.counts.total} items included · ~${formatCount(created.token_estimate)} tokens`);
          onInspect();
        },
        onError: (err) => toast.error("Could not build the context pack", mutationMessage(err)),
      },
    );

  return (
    <section aria-labelledby={`${id}-title`} className="space-y-3 px-4 py-4">
      <div>
        <h2 id={`${id}-title`} className="flex items-center gap-2 text-[13px] font-semibold text-fg">
          <span className="num inline-flex h-4 w-4 items-center justify-center rounded-full bg-surface-3 text-2xs text-fg-muted" aria-hidden>
            5
          </span>
          Context pack
        </h2>
        <p className="mt-0.5 pl-6 text-2xs text-fg-faint">Which project files and records the prompt carries. Build a pack to inspect and adjust it.</p>
      </div>

      <div className="space-y-1.5">
        <label htmlFor={`${id}-profile`} className="flex items-center justify-between text-xs font-medium text-fg-muted">
          Profile
          {config.profile === suggested && <Badge tone="accent">Suggested for this task</Badge>}
        </label>
        <Select id={`${id}-profile`} value={config.profile} onChange={(e) => state.setProfile(e.target.value as PackProfile)}>
          {catalogue.profiles.map((p) => (
            <option key={p.key} value={p.key}>
              {p.label} — {formatCount(p.token_budget)} token budget{p.key === suggested ? " (suggested)" : ""}
            </option>
          ))}
        </Select>
        {profile && (
          <p className="text-2xs text-fg-muted">
            {profile.description}
            {profile.includes_tests ? " Includes related tests." : ""}
            {profile.includes_git_history ? " Includes recent git history." : ""}
          </p>
        )}
      </div>

      {packRef ? (
        pack.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : pack.data ? (
          <div className="space-y-2.5 rounded-md border border-border bg-surface-2/40 p-3">
            <div className="flex items-center justify-between gap-2 text-2xs">
              <span className="text-fg-muted">
                Stored pack · built {timeAgo(pack.data.created_at)}
              </span>
              <button type="button" onClick={onInspect} className="font-medium text-accent hover:underline">
                Inspect items
              </button>
            </div>
            <TokenBudgetMeter estimate={pack.data.token_estimate} budget={pack.data.token_budget} compact />
            <PackCounts pack={pack.data} className="gap-x-3 [&_span]:text-2xs" />
          </div>
        ) : pack.error && !deleted ? (
          <p className="text-2xs text-danger">Could not load the pack: {pack.error instanceof Error ? pack.error.message : "unknown error"}</p>
        ) : null
      ) : (
        <div className="flex items-start gap-2 rounded-md border border-dashed border-border-strong px-3 py-2.5 text-2xs text-fg-muted">
          <PackageOpen className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
          <span>
            No stored pack. Generating builds a fresh <span className="text-fg">{profile?.label ?? config.profile}</span> pack that is not saved
            {canWrite ? " — build one to see and change exactly what is included." : "."}
          </span>
        </div>
      )}

      {canWrite ? (
        <>
          <ChipsInput
            label="Extra files to verify"
            values={extraPaths}
            onChange={setExtraPaths}
            placeholder="backend/app/services/foo.py"
            mono
            maxItems={50}
            hint="Optional repository-relative paths. Each is checked against the repository; sensitive files are never read."
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant={packRef ? "outline" : "secondary"}
              icon={packRef ? <RefreshCw className="h-3.5 w-3.5" aria-hidden /> : <Hammer className="h-3.5 w-3.5" aria-hidden />}
              loading={build.isPending}
              onClick={runBuild}
            >
              {packRef ? "Rebuild pack" : `Build ${profile?.label ?? ""} pack`}
            </Button>
            {packRef && (
              <Button size="sm" variant="ghost" onClick={state.detachPack}>
                Don’t use a stored pack
              </Button>
            )}
          </div>
          {packRef && <p className="text-2xs text-fg-faint">Rebuilding stores a new pack from current records; the previous one stays in Context Packs.</p>}
        </>
      ) : (
        <p className="text-2xs text-fg-faint">You need write access to build and adjust context packs.</p>
      )}

      {latest && (
        <div className={cn("flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2 text-2xs")}>
          <span className="min-w-0 truncate text-fg-muted">
            Saved pack: <span className="text-fg">{latest.profile_label}</span> · {latest.counts.included}/{latest.counts.total} items · built {timeAgo(latest.created_at)}
          </span>
          <Button size="xs" variant="ghost" onClick={() => state.selectPack(latest)}>
            Use it
          </Button>
        </div>
      )}
    </section>
  );
}
