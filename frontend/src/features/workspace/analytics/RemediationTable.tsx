import { useState } from "react";
import { Plus, ShieldCheck } from "lucide-react";
import { DataTable, EntityLink, type DataTableColumn } from "@/components/data";
import { Button, SeverityBadge, SimulationBadge, Tooltip, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { FINDING_CATEGORY_LABELS, humanize } from "@/lib/domain";
import { timeAgo } from "@/lib/format";
import { useCreateTaskFromFinding } from "../api";
import { AssigneeStack, RemediationStateBadge, TaskKeyLink, VerificationBadge } from "./taskMeta";
import type { RemediationFinding } from "./types";

function CreateTaskButton({ finding }: { finding: RemediationFinding }) {
  const create = useCreateTaskFromFinding();
  const toast = useToast();
  return (
    <Button
      size="xs"
      variant="primary"
      icon={<Plus className="h-3 w-3" aria-hidden />}
      loading={create.isPending}
      aria-label={`Create a remediation task for ${finding.title}`}
      onClick={() =>
        create.mutate(
          { finding_id: finding.finding_id },
          {
            onSuccess: (result) =>
              toast.success(
                result.created ? `${result.task.key} created` : `${result.task.key} already tracks this finding`,
                `${result.task.board_name} · ${result.task.column_name}`,
              ),
            onError: (err) => toast.error("Couldn’t create the task", err instanceof Error ? err.message : undefined),
          },
        )
      }
    >
      Create task
    </Button>
  );
}

function TaskCell({ finding, canWrite }: { finding: RemediationFinding; canWrite: boolean }) {
  const task = finding.task;
  if (!task) {
    return canWrite ? <CreateTaskButton finding={finding} /> : <span className="text-xs text-fg-faint">No task</span>;
  }
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="flex items-center gap-2">
        <TaskKeyLink task={task} />
        <span className="truncate text-xs text-fg-muted">{task.column_name}</span>
        {finding.linked_task_count > 1 && <span className="text-2xs text-fg-faint">+{finding.linked_task_count - 1} more</span>}
      </span>
      <span className="flex items-center gap-2">
        <AssigneeStack assignees={task.assignees} />
        {(task.is_done || task.verification_status !== "unverified") && <VerificationBadge status={task.verification_status} />}
      </span>
    </div>
  );
}

/** Open findings with their remediation state and the task (or the action) behind it. */
export function RemediationTable({
  rows,
  loading,
  error,
  onRetry,
  filtered,
}: {
  rows: RemediationFinding[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  filtered: boolean;
}) {
  const { can } = useAuth();
  const canWrite = can("write");
  const [expanded, setExpanded] = useState<string | null>(null);
  const columns: Array<DataTableColumn<RemediationFinding>> = [
    { key: "severity", header: "Severity", width: 92, render: (f) => <SeverityBadge severity={f.severity} /> },
    {
      key: "title",
      header: "Finding",
      render: (f) => (
        <div className="min-w-0 max-w-[460px]">
          <div className="flex min-w-0 items-center gap-2">
            <EntityLink type="finding" id={f.finding_id} label={f.title} showIcon={false} className="text-[13px]" />
            {f.is_simulation && <SimulationBadge />}
          </div>
          <div className="mt-0.5 flex flex-wrap gap-x-2 text-2xs text-fg-muted">
            <span>{FINDING_CATEGORY_LABELS[f.category] ?? humanize(f.category)}</span>
            <span aria-hidden>·</span>
            <span>{humanize(f.status)}</span>
            {f.occurrence_count > 1 && (
              <>
                <span aria-hidden>·</span>
                <span>seen {f.occurrence_count}×</span>
              </>
            )}
            {f.incident_id && (
              <>
                <span aria-hidden>·</span>
                <EntityLink type="incident" id={f.incident_id} label="Incident" className="text-2xs" />
              </>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "agent",
      header: "Agent",
      hideBelow: "md",
      render: (f) => (f.agent_id ? <EntityLink type="agent" id={f.agent_id} label={f.agent_name} /> : <span className="text-fg-faint">—</span>),
    },
    {
      key: "state",
      header: "Remediation",
      render: (f) => (
        <div className="flex max-w-[280px] flex-col items-start gap-1">
          <RemediationStateBadge state={f.state} />
          <button
            type="button"
            onClick={() => setExpanded(expanded === f.finding_id ? null : f.finding_id)}
            aria-expanded={expanded === f.finding_id}
            className={`text-left text-2xs text-fg-muted hover:text-fg ${expanded === f.finding_id ? "" : "line-clamp-2"}`}
          >
            {f.state_reason}
          </button>
        </div>
      ),
    },
    { key: "task", header: "Task", render: (f) => <TaskCell finding={f} canWrite={canWrite} /> },
    {
      key: "last_seen_at",
      header: "Last seen",
      hideBelow: "lg",
      render: (f) => (
        <Tooltip content={`First seen ${timeAgo(f.first_seen_at)}`}>
          <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(f.last_seen_at)}</span>
        </Tooltip>
      ),
    },
  ];
  return (
    <DataTable
      aria-label="Open findings and their remediation state"
      columns={columns}
      rows={rows}
      rowKey={(f) => f.finding_id}
      loading={loading}
      error={error}
      onRetry={onRetry}
      manualSort
      empty={
        filtered
          ? { title: "No findings match these filters", description: "Clear the stage, severity or search filters to see every open finding." }
          : {
              icon: <ShieldCheck className="h-4 w-4" />,
              title: "No open findings",
              description: "Every finding is resolved or marked a false positive. New findings from agent activity appear here automatically.",
            }
      }
    />
  );
}
