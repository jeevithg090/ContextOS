/**
 * Overview — answers "what is the security posture of my agents right now?".
 *
 * KPI strip (each number links to the list behind it), what needs a person, the riskiest agents,
 * activity in the window, recently denied or paused tool calls, source trust, integration health and
 * recent audit activity. Every value comes from GET /overview, computed from persisted rows; live
 * events refresh it (hooks/useLiveEvents invalidates ["overview"]). Window and the simulated-data
 * toggle live in the URL (?window=, ?sim=0) so a view can be shared.
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, FlaskConical } from "lucide-react";
import { SegmentedControl } from "@/components/data";
import { Button, Checkbox, ErrorState, PageHeader, Spinner } from "@/components/ui";
import { formatNumber, pluralize, timeAgo } from "@/lib/format";
import { ActivityCharts } from "./ActivityCharts";
import { useOverview } from "./api";
import { BlockedActions } from "./BlockedActions";
import { KpiStrip } from "./KpiStrip";
import { includeSimulatedFrom, onboardingStage, windowFrom, windowLong, WINDOWS } from "./meta";
import { NeedsAttention } from "./NeedsAttention";
import { OnboardingChecklist } from "./OnboardingChecklist";
import { IntegrationHealth, TrustDistribution } from "./PlatformPanels";
import { RecentActivity } from "./RecentActivity";
import { RiskyAgents } from "./RiskyAgents";
import type { Overview, OverviewWindow } from "./types";

function SimulationNotice({ data, onInclude }: { data: Overview; onInclude: () => void }) {
  const { events } = data.simulated;
  if (!events) return null;
  const window = windowLong(data.window);
  return (
    <div role="status" className="flex flex-wrap items-center gap-2 rounded-md border border-accent/25 bg-accent/[0.06] px-3 py-2 text-xs text-fg">
      <FlaskConical className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
      {data.include_simulated ? (
        <span>
          Includes {pluralize(events, "simulated event")} from the Simulation Lab in {window}. Simulated rows are labelled <span className="font-medium text-accent">Simulation</span>.
        </span>
      ) : (
        <>
          <span>
            {pluralize(events, "simulated event")} in {window} {events === 1 ? "is" : "are"} hidden.
          </span>
          <Button size="xs" variant="ghost" onClick={onInclude}>
            Include them
          </Button>
        </>
      )}
    </div>
  );
}

export function OverviewPage() {
  const [params, setParams] = useSearchParams();
  const window = windowFrom(params);
  const includeSimulated = includeSimulatedFrom(params);
  const query = useOverview(window, includeSimulated);
  const data = query.data;

  const setParam = useCallback(
    (key: string, value: string | null) =>
      setParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (value === null) next.delete(key);
          else next.set(key, value);
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const stage = data ? onboardingStage(data.onboarding) : null;
  const loading = query.isLoading;

  return (
    <>
      <PageHeader
        title="Overview"
        description="The security posture of your agents, computed from what their integrations reported: what needs a person, which agents carry risk and whether decisions are actually enforced."
        actions={
          <div className="flex flex-wrap items-center gap-3">
            {data && (
              <span className="inline-flex items-center gap-1.5 text-xs text-fg-faint" aria-live="polite">
                {query.isFetching && <Spinner className="h-3 w-3" />}
                Updated {timeAgo(data.generated_at)}
              </span>
            )}
            <Checkbox label="Include simulated" checked={includeSimulated} onChange={(v) => setParam("sim", v ? null : "0")} />
            <SegmentedControl<OverviewWindow>
              aria-label="Time window"
              value={window}
              onChange={(value) => setParam("window", value === "24h" ? null : value)}
              options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
            />
          </div>
        }
      />

      {query.error && !data ? (
        <div className="panel">
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        </div>
      ) : stage === "empty" && data ? (
        <OnboardingChecklist onboarding={data.onboarding} />
      ) : (
        <div className="space-y-4">
          {query.error && data && (
            <div role="status" className="flex items-center gap-2 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-fg">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
              The overview could not be refreshed; the figures below may be out of date.
              <Button size="xs" variant="ghost" className="ml-auto" onClick={() => void query.refetch()}>
                Retry
              </Button>
            </div>
          )}
          {data && <SimulationNotice data={data} onInclude={() => setParam("sim", null)} />}
          {data && stage === "simulated_only" && <OnboardingChecklist onboarding={data.onboarding} compact />}

          <KpiStrip data={data} />

          <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <NeedsAttention data={data} loading={loading} />
            <RiskyAgents data={data} loading={loading} />
          </div>

          <ActivityCharts data={data} loading={loading} />

          <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <BlockedActions data={data} loading={loading} />
            <TrustDistribution data={data} loading={loading} />
          </div>

          <div className="grid min-w-0 gap-4 lg:grid-cols-2">
            <IntegrationHealth data={data} loading={loading} />
            <RecentActivity data={data} loading={loading} />
          </div>

          {data && (
            <p className="text-2xs text-fg-faint">
              {formatNumber(data.posture.agents_total)} {data.posture.agents_total === 1 ? "agent" : "agents"} known · {formatNumber(data.posture.agents_active)} active and {pluralize(data.posture.sessions_active, "open session")} in {windowLong(data.window)}. Provenance and risk reflect what integrations observed and reported; they do not prove what a model decided.
            </p>
          )}
        </div>
      )}
    </>
  );
}
