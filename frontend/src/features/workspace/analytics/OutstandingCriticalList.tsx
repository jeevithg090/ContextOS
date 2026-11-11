import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { EntityLink, Section } from "@/components/data";
import { EmptyState, SeverityBadge, SimulationBadge } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { AssigneeStack, RemediationStateBadge, TaskKeyLink } from "./taskMeta";
import type { EngineeringAnalytics } from "./types";

/** Critical findings without a done task, then other open critical tasks — oldest first. */
export function OutstandingCriticalList({ data }: { data: EngineeringAnalytics["outstanding_critical"] }) {
  const hidden = data.total - data.items.length;
  return (
    <Section
      title="Outstanding critical work"
      description={`${data.findings} critical finding${data.findings === 1 ? "" : "s"} without a done task and ${data.tasks} open critical task${data.tasks === 1 ? "" : "s"} (an item is listed once even when a task tracks a finding).`}
      actions={
        <Link to="/work/remediation?severity=critical" className="text-xs text-accent hover:text-accent-strong">
          Open in Remediation
        </Link>
      }
      flush
    >
      {data.items.length === 0 ? (
        <EmptyState icon={<ShieldCheck className="h-4 w-4" />} title="Nothing critical is outstanding" description="No open critical findings or critical tasks." />
      ) : (
        <ul className="divide-y divide-border/70">
          {data.items.map((item) => (
            <li key={`${item.kind}-${item.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
              <SeverityBadge severity={item.severity} />
              <div className="min-w-0 flex-1">
                <div className="flex min-w-0 items-center gap-2">
                  {item.kind === "finding" ? (
                    <EntityLink type="finding" id={item.id} label={item.title} showIcon={false} className="text-[13px]" />
                  ) : (
                    <Link to={`/work/tasks/${encodeURIComponent(item.id)}`} className="truncate text-[13px] text-accent hover:text-accent-strong hover:underline">
                      {item.title}
                    </Link>
                  )}
                  {item.is_simulation && <SimulationBadge />}
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-2xs text-fg-muted">
                  <span>{item.kind === "finding" ? "Finding" : "Task"}</span>
                  <span aria-hidden>·</span>
                  <span>{item.kind === "finding" ? "first seen" : "created"} {timeAgo(item.since)}</span>
                  {item.agent_id && (
                    <>
                      <span aria-hidden>·</span>
                      <EntityLink type="agent" id={item.agent_id} label={item.agent_name} className="text-2xs" />
                    </>
                  )}
                </div>
              </div>
              {item.kind === "finding" && <RemediationStateBadge state={item.state} />}
              {item.task ? (
                <span className="inline-flex items-center gap-2 text-xs text-fg-muted">
                  <TaskKeyLink task={item.task} />
                  <span className="hidden sm:inline">{item.task.column_name}</span>
                  <AssigneeStack assignees={item.task.assignees} />
                </span>
              ) : (
                <span className="text-xs text-fg-faint">No task</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {hidden > 0 && <p className="border-t border-border px-4 py-2 text-xs text-fg-muted">{hidden} more not shown — see the Remediation view.</p>}
    </Section>
  );
}
