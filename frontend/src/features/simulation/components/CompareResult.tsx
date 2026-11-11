import { ArrowRight, Info } from "lucide-react";
import { EntityLink, RedactedText, Section } from "@/components/data";
import { Badge, Button, DecisionBadge, Stat, StatusBadge } from "@/components/ui";
import { FINDING_CATEGORY_LABELS, labelFrom } from "@/lib/domain";
import { cn, formatDateTime, shortId } from "@/lib/format";
import { compareCounts, diffStatusMeta, sortDiffs } from "../logic";
import type { CheckChange, DecisionChange, ScenarioDiff, SuiteCompare, SuiteSummary } from "../types";

const NOT_PROOF = "Differences between two suites are not proof of causation: they show what changed between the runs, not why.";

/** Regression diff between two suites: counts, scenarios (regressions first), policy changes. */
export function CompareResult({ data, onOpenRun }: { data: SuiteCompare; onOpenRun: (runId: string) => void }) {
  const counts = compareCounts(data.counts);
  const diffs = sortDiffs(data.scenarios);
  return (
    <div className="space-y-4">
      <div className="panel grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
        <Stat label="Regressed" value={counts.regressed} tone={counts.regressed > 0 ? "danger" : undefined} hint="Passed before, fail now" />
        <Stat label="Fixed" value={counts.fixed} tone={counts.fixed > 0 ? "ok" : undefined} hint="Failed before, pass now" />
        <Stat label="Unchanged" value={counts.unchanged} hint="Same verdict in both" />
        <Stat label="In one suite only" value={counts.other} hint="Added or removed scenarios" />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <SuiteCard title="Base (before)" suite={data.base} />
        <SuiteCard title="Head (after)" suite={data.head} />
      </div>

      <div role="note" className="flex items-start gap-2 rounded-md border border-border bg-surface-2/50 px-3 py-2.5 text-xs leading-5 text-fg-muted">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        <p>
          {data.note} {NOT_PROOF}
        </p>
      </div>

      <Section title="Scenarios" description="Regressions first. Each change shows the base result, then the head result." flush>
        {diffs.length === 0 ? (
          <p className="px-4 py-6 text-center text-xs text-fg-muted">Neither suite contains any scenario runs.</p>
        ) : (
          <ul className="divide-y divide-border" aria-label="Scenario changes">
            {diffs.map((d) => (
              <ScenarioDiffRow key={d.scenario_id} diff={d} onOpenRun={onOpenRun} />
            ))}
          </ul>
        )}
      </Section>

      <Section title="Policy changes between the snapshots" description="Compares the policies recorded when each suite started (enabled, mode, version, outcome).">
        {data.policy_changes.length === 0 ? (
          <p className="text-xs text-fg-muted">No policy changes between the two snapshots.</p>
        ) : (
          <ul className="space-y-1.5">
            {data.policy_changes.map((p) => (
              <li key={p.policy_id} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
                {p.change === "removed" ? <span className="text-fg">{p.name ?? shortId(p.policy_id)}</span> : <EntityLink type="policy" id={p.policy_id} label={p.name} showIcon={false} />}
                <span className="text-fg-muted">{p.change}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function SuiteCard({ title, suite }: { title: string; suite: SuiteSummary }) {
  return (
    <div className="rounded-md border border-border px-3 py-2.5 text-xs">
      <div className="label-caps">{title}</div>
      <div className="mt-1 flex flex-wrap items-baseline gap-x-2">
        <span className="font-mono text-fg">{shortId(suite.suite_run_id)}</span>
        <span className="text-fg-muted">{formatDateTime(suite.started_at)}</span>
      </div>
      <div className="mt-0.5 text-fg-muted">
        {suite.passed_count}/{suite.run_count} scenarios passed · {suite.agent_id ? <EntityLink type="agent" id={suite.agent_id} /> : "simulated agent"}
        {suite.agent_version ? ` · v${suite.agent_version}` : ""}
      </div>
    </div>
  );
}

function verdictText(passed: boolean | null, runId: string | null): string {
  if (!runId) return "not run";
  return passed ? "passed" : "failed";
}

function ScenarioDiffRow({ diff, onOpenRun }: { diff: ScenarioDiff; onOpenRun: (runId: string) => void }) {
  const meta = diffStatusMeta(diff.status);
  const hasChanges = diff.check_changes.length + diff.decision_changes.length + diff.new_finding_categories.length + diff.resolved_finding_categories.length > 0;
  return (
    <li className={cn("px-4 py-3", diff.status === "regressed" && "bg-danger/[0.04]")}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={meta.tone} dot title={meta.description}>
          {meta.label}
        </Badge>
        <span className="text-[13px] font-medium text-fg">{diff.scenario_name}</span>
        <span className="inline-flex items-center gap-1 text-xs text-fg-muted">
          {verdictText(diff.base_passed, diff.base_run_id)}
          <ArrowRight className="h-3 w-3" aria-label="then" />
          {verdictText(diff.head_passed, diff.head_run_id)}
        </span>
        <span className="ml-auto flex gap-1">
          {diff.base_run_id && (
            <Button size="xs" variant="ghost" onClick={() => onOpenRun(diff.base_run_id as string)} aria-label={`Open base run of ${diff.scenario_name}`}>
              Base run
            </Button>
          )}
          {diff.head_run_id && (
            <Button size="xs" variant="ghost" onClick={() => onOpenRun(diff.head_run_id as string)} aria-label={`Open head run of ${diff.scenario_name}`}>
              Head run
            </Button>
          )}
        </span>
      </div>
      {hasChanges && (
        <div className="mt-2 space-y-3 pl-0 sm:pl-2">
          {diff.check_changes.length > 0 && <CheckChanges changes={diff.check_changes} />}
          {diff.decision_changes.length > 0 && <DecisionChanges changes={diff.decision_changes} />}
          <CategoryChanges label="New finding categories" values={diff.new_finding_categories} />
          <CategoryChanges label="No longer raised" values={diff.resolved_finding_categories} />
        </div>
      )}
    </li>
  );
}

function CheckChanges({ changes }: { changes: CheckChange[] }) {
  return (
    <div>
      <div className="label-caps">Check changes</div>
      <ul className="mt-1 space-y-2">
        {changes.map((c) => (
          <li key={c.check} className="rounded-md border border-border p-2.5 text-xs">
            <p className="text-fg">{c.expectation}</p>
            <div className="mt-1.5 grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:items-start">
              <ChangeSide label="Before" passed={c.base_passed} actual={c.base_actual} />
              <ArrowRight className="hidden h-3.5 w-3.5 text-fg-faint sm:mt-5 sm:block" aria-hidden />
              <ChangeSide label="After" passed={c.head_passed} actual={c.head_actual} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ChangeSide({ label, passed, actual }: { label: string; passed: boolean | null; actual: string }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5">
        <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">{label}</span>
        <StatusBadge status={passed ? "passed" : "failed"} />
      </div>
      <p className="mt-1 break-words text-fg-muted">
        <RedactedText text={actual ?? ""} />
      </p>
    </div>
  );
}

function DecisionChanges({ changes }: { changes: DecisionChange[] }) {
  return (
    <div>
      <div className="label-caps">Decision changes</div>
      <ul className="mt-1 space-y-1">
        {changes.map((c) => (
          <li key={c.step} className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-fg">{c.step}</span>
            {c.base ? <DecisionBadge decision={c.base} /> : <span className="text-fg-faint">no decision</span>}
            <ArrowRight className="h-3 w-3 text-fg-faint" aria-label="then" />
            {c.head ? <DecisionBadge decision={c.head} /> : <span className="text-fg-faint">no decision</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function CategoryChanges({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      <span className="label-caps">{label}</span>
      {values.map((v) => (
        <Badge key={v} tone="neutral">
          {labelFrom(FINDING_CATEGORY_LABELS, v)}
        </Badge>
      ))}
    </div>
  );
}
