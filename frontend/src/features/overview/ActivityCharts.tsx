/** What changed in the window: events received, findings first detected and policy decisions,
 * bucketed by the server (hourly for 24h, daily otherwise). Daily buckets are UTC days, so their
 * axis labels are formatted in UTC; hourly labels use local time. */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Section, TimeSeriesChart, type TimeSeries, type TimeSeriesDatum } from "@/components/data";
import { DECISION_META, SEVERITIES, SEVERITY_META, type Decision } from "@/lib/domain";
import { formatNumber, pluralize } from "@/lib/format";
import { windowLong, withSim } from "./meta";
import type { Overview } from "./types";

const SEVERITY_SERIES: TimeSeries[] = SEVERITIES.map((s) => ({ key: s, label: SEVERITY_META[s].label, tone: SEVERITY_META[s].tone }));
const DECISION_ORDER: Decision[] = ["DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT", "ALLOW"];
const DECISION_SERIES: TimeSeries[] = DECISION_ORDER.map((d) => ({ key: d, label: DECISION_META[d].label, tone: DECISION_META[d].tone }));

const UTC_DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });

export function utcDayLabel(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : UTC_DAY.format(new Date(t));
}

function sum(points: TimeSeriesDatum[], keys: string[]): number {
  return points.reduce((total, p) => total + keys.reduce((s, k) => s + (typeof p[k] === "number" ? (p[k] as number) : 0), 0), 0);
}

function ChartPanel({ title, description, total, action, children }: { title: string; description: string; total: string; action?: ReactNode; children: ReactNode }) {
  return (
    <Section
      title={title}
      description={description}
      className="min-w-0"
      actions={
        <div className="flex items-center gap-3">
          <span className="num font-mono text-xs text-fg-muted">{total}</span>
          {action}
        </div>
      }
    >
      {children}
    </Section>
  );
}

export function ActivityCharts({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const window = data ? windowLong(data.window) : "";
  const events = (data?.series.events ?? []) as unknown as TimeSeriesDatum[];
  const findings = (data?.series.findings_by_severity ?? []) as unknown as TimeSeriesDatum[];
  const decisions = (data?.series.decisions_by_outcome ?? []) as unknown as TimeSeriesDatum[];
  const eventSeries: TimeSeries[] = [{ key: "live", label: "Live" }];
  if (data?.include_simulated) eventSeries.push({ key: "simulated", label: "Simulated" });
  const sim = data?.include_simulated ?? false;
  const xFormat = data?.bucket === "day" ? utcDayLabel : undefined;

  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-3">
      <ChartPanel
        title="Events received"
        description={`Everything integrations reported, by server receive time${data?.include_simulated ? "; Simulation Lab traffic shown separately" : ""}.`}
        total={data ? pluralize(sum(events, ["live", "simulated"]), "event") : ""}
      >
        <TimeSeriesChart data={events} series={eventSeries} variant="bar" xFormat={xFormat} loading={loading && !data} height={168} emptyLabel={`No events in ${window}.`} aria-label={`Events received per ${data?.bucket ?? "bucket"}`} />
      </ChartPanel>
      <ChartPanel
        title="New findings"
        description="Findings by severity at first detection (false positives excluded)."
        total={data ? formatNumber(sum(findings, SEVERITIES as unknown as string[])) : ""}
        action={
          <Link to={withSim("/intelligence", sim)} className="text-xs text-accent hover:underline">
            View
          </Link>
        }
      >
        <TimeSeriesChart data={findings} series={SEVERITY_SERIES} variant="bar" xFormat={xFormat} loading={loading && !data} height={168} emptyLabel={`Nothing detected in ${window}.`} aria-label={`New findings per ${data?.bucket ?? "bucket"} by severity`} />
      </ChartPanel>
      <ChartPanel
        title="Policy decisions"
        description="Outcome of every tool call ContextOS evaluated."
        total={data ? formatNumber(data.posture.decisions_total) : ""}
        action={
          <Link to="/policies" className="text-xs text-accent hover:underline">
            Policies
          </Link>
        }
      >
        <TimeSeriesChart data={decisions} series={DECISION_SERIES} variant="bar" xFormat={xFormat} loading={loading && !data} height={168} emptyLabel={`No tool calls evaluated in ${window}.`} aria-label={`Policy decisions per ${data?.bucket ?? "bucket"} by outcome`} />
      </ChartPanel>
    </div>
  );
}
