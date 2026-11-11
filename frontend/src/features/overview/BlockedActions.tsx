/** Tool calls that policy denied or paused in the window. The outcome text comes from the server and
 * only says "blocked" when an enforcing integration acted on the decision. */
import { ShieldCheck } from "lucide-react";
import { EntityLink, Section } from "@/components/data";
import { DecisionBadge, EmptyState, EnforcementBadge, LoadingRows, SimulationBadge, Table, TD, TH, THead, TR } from "@/components/ui";
import { cn, timeAgo } from "@/lib/format";
import { windowLong } from "./meta";
import type { BlockedAction, Overview } from "./types";

function outcomeTone(row: BlockedAction): string {
  if (row.enforcement === "observed") return "text-fg-muted";
  if (row.enforcement === "advisory") return "text-warn";
  return row.decision === "DENY" || row.status === "rejected" || row.status === "expired" ? "text-dec-deny" : "text-fg";
}

/** Wrapped in a focusable anchor target: the "Blocked actions" KPI scrolls here. */
export function BlockedActions({ data, loading }: { data: Overview | undefined; loading: boolean }) {
  const rows = data?.recent_blocked_or_paused ?? [];
  return (
    <div id="blocked-actions" tabIndex={-1} className="min-w-0 scroll-mt-4 rounded-lg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent/50">
      <Section
        title="Recently denied or paused"
        description="Tool calls policy denied or held for approval. Enforcement shows whether the decision could actually stop the call."
        flush
      >
        {!data ? (
          loading ? <LoadingRows rows={4} /> : null
        ) : rows.length === 0 ? (
          <EmptyState icon={<ShieldCheck className="h-4 w-4" />} title={`No tool call was denied or paused in ${windowLong(data.window)}`} description="Every evaluated call was allowed, restricted or audited." />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Action</TH>
                <TH>Decision</TH>
                <TH>Enforcement</TH>
                <TH>What happened</TH>
                <TH className="text-right">When</TH>
              </tr>
            </THead>
            <tbody>
              {rows.map((row) => (
                <TR key={row.invocation_id}>
                  <TD className="max-w-[320px]">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <EntityLink type="tool_invocation" id={row.invocation_id} sessionId={row.session_id} label={row.action} className="min-w-0 text-[13px]" />
                      {row.is_simulation && <SimulationBadge />}
                    </div>
                    <div className="mt-0.5 flex min-w-0 items-center gap-1 text-2xs text-fg-muted">
                      <EntityLink type="agent" id={row.agent.id} label={row.agent.name} showIcon={false} className="text-2xs" />
                      <span aria-hidden>·</span>
                      <span className="truncate font-mono">{row.tool.server ? `${row.tool.server}/${row.tool.name}` : row.tool.name}</span>
                    </div>
                  </TD>
                  <TD>
                    <DecisionBadge decision={row.decision} />
                  </TD>
                  <TD>
                    <EnforcementBadge mode={row.enforcement} />
                  </TD>
                  <TD className="max-w-[280px]">
                    <span className={cn("block text-xs", outcomeTone(row))}>{row.outcome}</span>
                    {row.reason && (
                      <span className="mt-0.5 block truncate text-2xs text-fg-faint" title={row.reason}>
                        {row.reason}
                      </span>
                    )}
                  </TD>
                  <TD className="whitespace-nowrap text-right text-xs text-fg-faint">{timeAgo(row.at)}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
    </div>
  );
}
