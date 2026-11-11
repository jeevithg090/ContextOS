/** Charts for Engineering Analytics. Each one plots persisted counts; nothing is interpolated. */
import { format } from "date-fns";
import { BarList, Section, TimeSeriesChart, type BarListItem } from "@/components/data";
import { buildQuery } from "@/lib/api";
import { PRIORITY_META, statusKeyLabel, taskTypeLabel } from "./taskMeta";
import type { EngineeringAnalytics } from "./types";
import type { TaskPriority } from "../types";

const SERIES = [
  { key: "created", label: "Created" },
  { key: "completed", label: "Completed", tone: "ok" as const },
];

/** Short axis labels for the cycle-time buckets (the API's labels are spelled out). */
const CYCLE_SHORT: Record<string, string> = {
  lt_4h: "< 4 h",
  "4h_1d": "4–24 h",
  "1d_3d": "1–3 d",
  "3d_7d": "3–7 d",
  "1w_2w": "1–2 wk",
  "2w_4w": "2–4 wk",
  gt_4w: "> 4 wk",
};

const dayLabel = (iso: string) => format(new Date(iso), "d MMM");

function tasksHref(filters: Record<string, string | undefined>, boardId: string | null) {
  return `/work/tasks${buildQuery({ ...filters, board_id: boardId ?? undefined })}`;
}

export function FlowCharts({ data, loading }: { data: EngineeringAnalytics | undefined; loading: boolean }) {
  const unit = data?.series_granularity === "week" ? "week" : "day";
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section
        title="Created vs completed"
        description={`Tasks created and tasks completed per ${unit} (UTC). A widening gap means work arrives faster than it is finished.`}
      >
        <TimeSeriesChart
          data={(data?.created_vs_completed ?? []).map((p) => ({ t: p.start, created: p.created, completed: p.completed }))}
          series={SERIES}
          stacked={false}
          xFormat={dayLabel}
          loading={loading}
          emptyLabel="No tasks were created or completed in this window."
          aria-label={`Tasks created and completed per ${unit}`}
        />
      </Section>
      <Section title="Weekly throughput" description="Tasks completed per week (weeks start on Monday; the first week may be partial).">
        <TimeSeriesChart
          data={(data?.throughput ?? []).map((p) => ({ t: p.start, completed: p.completed }))}
          series={[{ key: "completed", label: "Completed", tone: "ok" }]}
          variant="bar"
          xFormat={(v) => `w/c ${dayLabel(v)}`}
          loading={loading}
          emptyLabel="No tasks were completed in this window."
          aria-label="Tasks completed per week"
        />
      </Section>
    </div>
  );
}

export function CycleTimeChart({ data, loading }: { data: EngineeringAnalytics | undefined; loading: boolean }) {
  return (
    <Section
      title="Time to complete"
      description={`Distribution of created → done time for the ${data?.completed_in_window ?? 0} tasks completed in this window.`}
    >
      <TimeSeriesChart
        data={(data?.cycle_time ?? []).map((b) => ({ t: CYCLE_SHORT[b.key] ?? b.label, tasks: b.count }))}
        series={[{ key: "tasks", label: "Tasks" }]}
        variant="bar"
        xFormat={(v) => v}
        loading={loading}
        emptyLabel="No tasks were completed in this window."
        aria-label="Number of tasks per completion-time bucket"
      />
    </Section>
  );
}

export function Breakdowns({ data }: { data: EngineeringAnalytics }) {
  const board = data.board_id;
  const priorities: BarListItem[] = data.by_priority.map((b) => ({
    key: b.key,
    label: PRIORITY_META[b.key as TaskPriority]?.label ?? b.key,
    value: b.count,
    tone: PRIORITY_META[b.key as TaskPriority]?.tone,
    href: b.count ? tasksHref({ priority: b.key }, board) : undefined,
  }));
  const types: BarListItem[] = data.by_type.map((b) => ({
    key: b.key,
    label: taskTypeLabel(b.key),
    value: b.count,
    href: tasksHref({ type: b.key }, board),
  }));
  const statuses: BarListItem[] = data.by_status_key
    .filter((b) => b.count > 0)
    .map((b) => ({ key: b.key, label: statusKeyLabel(b.key), value: b.count, href: tasksHref({ status: b.key }, board) }));
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Section title="Open tasks by priority" description="Every priority, including empty ones.">
        <BarList items={priorities} aria-label="Open tasks by priority" emptyLabel="No open tasks." />
      </Section>
      <Section title="Open tasks by type" description="Task types with at least one open task.">
        <BarList items={types} aria-label="Open tasks by type" emptyLabel="No open tasks." />
      </Section>
      <Section title="Open tasks by stage" description="Column status key, across boards.">
        <BarList items={statuses} aria-label="Open tasks by stage" emptyLabel="No open tasks." />
      </Section>
    </div>
  );
}
