/**
 * Engineering analytics and remediation pipeline types.
 * Mirrors backend/app/schemas/workspace_analytics.py — field names are the contract.
 *
 * Every number comes from persisted task, verification and finding rows. Ratios carry their
 * numerator and denominator; `rate` is null when nothing was counted.
 */
import type { Severity } from "@/lib/domain";
import type { TaskCard } from "../types";

export const REMEDIATION_STATES = ["no_task", "task_open", "task_done_unverified", "verified"] as const;
export type RemediationState = (typeof REMEDIATION_STATES)[number];

export const ANALYTICS_WINDOWS = ["7d", "30d", "90d", "180d", "365d"] as const;
export type AnalyticsWindow = (typeof ANALYTICS_WINDOWS)[number];

export interface CountItem {
  key: string;
  count: number;
}

export interface Ratio {
  numerator: number;
  denominator: number;
  /** numerator / denominator (0..1); null when the denominator is 0. */
  rate: number | null;
}

export interface FindingBacklog {
  /** no_task + task_open. */
  total: number;
  no_task: number;
  task_open: number;
  /** All open or acknowledged findings, whatever their remediation state. */
  open_findings: number;
}

export interface SeriesPoint {
  /** Bucket start (UTC midnight; weeks start on Monday). */
  start: string;
  created: number;
  completed: number;
}

export interface CycleBucket {
  key: string;
  label: string;
  min_hours: number;
  max_hours: number | null;
  count: number;
}

export interface CriticalItem {
  kind: "finding" | "task";
  id: string;
  title: string;
  severity: Severity | string;
  /** first_seen_at for findings, created_at for tasks. */
  since: string;
  state: RemediationState;
  is_simulation: boolean;
  agent_id: string | null;
  agent_name: string | null;
  task: TaskCard | null;
}

export interface EngineeringAnalytics {
  generated_at: string;
  window_days: number;
  window_start: string;
  /** Task metrics are limited to this board; finding metrics never are. */
  board_id: string | null;
  include_simulations: boolean;
  open_tasks: number;
  overdue: number;
  by_priority: CountItem[];
  by_type: CountItem[];
  by_status_key: CountItem[];
  completed_in_window: number;
  avg_resolution_hours: number | null;
  median_resolution_hours: number | null;
  p90_resolution_hours: number | null;
  findings_awaiting_remediation: FindingBacklog;
  remediation_completion_rate: Ratio;
  reopened_issues: { reopen_events: number; tasks_reopened: number };
  failed_verification_runs: Ratio;
  outstanding_critical: { total: number; findings: number; tasks: number; items: CriticalItem[] };
  series_granularity: "day" | "week";
  created_vs_completed: SeriesPoint[];
  throughput: SeriesPoint[];
  cycle_time: CycleBucket[];
}

export interface AnalyticsParams {
  window: AnalyticsWindow;
  board_id?: string;
  include_simulations: boolean;
}

export interface RemediationFinding {
  finding_id: string;
  title: string;
  category: string;
  severity: Severity | string;
  status: string;
  confidence: number;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  is_simulation: boolean;
  agent_id: string | null;
  agent_name: string | null;
  session_id: string | null;
  incident_id: string | null;
  state: RemediationState;
  /** Plain-language explanation of the state. */
  state_reason: string;
  linked_task_count: number;
  /** Open task, else the most recently completed (verified first). */
  task: TaskCard | null;
}

export type RemediationCounts = Record<RemediationState, number>;

export interface RemediationPage {
  items: RemediationFinding[];
  total: number;
  limit: number;
  offset: number;
  /** Findings per state for the same filters, ignoring the state filter. */
  counts: RemediationCounts;
}

export interface RemediationFilters {
  state?: RemediationState;
  severity?: Severity;
  q?: string;
  include_simulations: boolean;
  limit: number;
  offset: number;
}
