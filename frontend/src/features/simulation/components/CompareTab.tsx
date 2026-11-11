/**
 * Compare two regression suites: pick a base (before) and head (after) suite run; the server diffs
 * every scenario, check, step decision, finding category and the policy snapshots.
 */
import { ArrowLeftRight, GitCompare } from "lucide-react";
import { Section } from "@/components/data";
import { Button, EmptyState, ErrorState, Field, LoadingRows, Select } from "@/components/ui";
import { formatDateTime, shortId } from "@/lib/format";
import { isNotFound, useSuiteCompare, useSuites } from "../api";
import { defaultComparePair } from "../logic";
import type { SuiteSummary } from "../types";
import { CompareResult } from "./CompareResult";

const PICKER_LIMIT = 100;

export function suiteOptionLabel(s: SuiteSummary): string {
  const target = s.agent_id ? `agent ${shortId(s.agent_id)}` : "simulated agent";
  const version = s.agent_version ? ` v${s.agent_version}` : "";
  return `${formatDateTime(s.started_at)} · ${s.passed_count}/${s.run_count} passed · ${target}${version} · ${shortId(s.suite_run_id)}`;
}

export interface CompareTabProps {
  base: string | null;
  head: string | null;
  onChange: (pair: { base: string | null; head: string | null }) => void;
  onOpenRun: (runId: string) => void;
}

export function CompareTab({ base, head, onChange, onOpenRun }: CompareTabProps) {
  const suites = useSuites(PICKER_LIMIT, 0);
  const list = suites.data?.items ?? [];
  const fallback = defaultComparePair(list);
  const effectiveBase = base ?? fallback.base;
  const effectiveHead = head ?? fallback.head;
  const same = !!effectiveBase && effectiveBase === effectiveHead;
  const compare = useSuiteCompare(effectiveBase, effectiveHead);

  if (suites.isLoading) return <LoadingRows rows={4} />;
  if (suites.error && !suites.data) return <ErrorState error={suites.error} onRetry={() => void suites.refetch()} />;
  if (list.length < 2) {
    return (
      <EmptyState
        icon={<GitCompare className="h-5 w-5" />}
        title={list.length === 0 ? "No suites to compare yet" : "One suite so far"}
        description="Run the whole catalogue as a suite (Scenarios → “Run all as suite”) before and after a change to policies, trust rules or the agent, then compare the two runs here."
      />
    );
  }

  // A deep link may name a suite older than the picker's window: keep it selectable.
  const options = withSelected(list, [effectiveBase, effectiveHead]);

  return (
    <div className="space-y-4">
      <Section title="Suites to compare" description="Base is the suite before the change, head the suite after it.">
        <div className="grid items-end gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
          <Field label="Base (before)" htmlFor="compare-base">
            <Select id="compare-base" value={effectiveBase ?? ""} onChange={(e) => onChange({ base: e.target.value || null, head: effectiveHead })}>
              {options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
          <Button
            variant="ghost"
            size="sm"
            icon={<ArrowLeftRight className="h-3.5 w-3.5" aria-hidden />}
            onClick={() => onChange({ base: effectiveHead, head: effectiveBase })}
            aria-label="Swap base and head"
            className="justify-self-start md:justify-self-center"
          >
            Swap
          </Button>
          <Field label="Head (after)" htmlFor="compare-head">
            <Select id="compare-head" value={effectiveHead ?? ""} onChange={(e) => onChange({ base: effectiveBase, head: e.target.value || null })}>
              {options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      </Section>

      {same ? (
        <EmptyState title="Pick two different suites" description="Base and head are the same suite run, so there is nothing to compare." />
      ) : compare.isLoading ? (
        <LoadingRows rows={6} />
      ) : compare.error && !compare.data ? (
        isNotFound(compare.error) ? (
          <EmptyState title="Suite not found" description="One of the selected suite runs does not exist in your organisation. Pick another suite above." />
        ) : (
          <ErrorState error={compare.error} onRetry={() => void compare.refetch()} />
        )
      ) : compare.data ? (
        <CompareResult data={compare.data} onOpenRun={onOpenRun} />
      ) : null}
    </div>
  );
}

function withSelected(list: SuiteSummary[], selected: Array<string | null>): Array<{ value: string; label: string }> {
  const options = list.map((s) => ({ value: s.suite_run_id, label: suiteOptionLabel(s) }));
  for (const id of selected) {
    if (id && !options.some((o) => o.value === id)) options.push({ value: id, label: `Suite ${shortId(id)} (older)` });
  }
  return options;
}
