/** Detail pane for one approval: what the agent wants, why it was paused, what it had read, and the
 * decision controls (pending) or the recorded outcome (history). */
import { AlertTriangle, UserCheck } from "lucide-react";
import { Badge, EmptyState, ErrorState, LoadingRows, SimulationBadge, StatusBadge } from "@/components/ui";
import { cn, formatDateTime, timeAgo } from "@/lib/format";
import { useAuth } from "@/features/auth/AuthProvider";
import { isNotFound, useApproval } from "./api";
import { Countdown } from "./ApprovalQueue";
import { DecisionBar } from "./DecisionBar";
import { ActivitySection, ContextSection, FindingsSection } from "./detail/ContextSection";
import { WhatSection } from "./detail/WhatSection";
import { WhySection } from "./detail/WhySection";
import { decidedByLabel, deadlineOf, ranWithoutApproval, riskChips, useNow } from "./meta";
import type { ApprovalDetail } from "./types";

export interface ApprovalDetailPaneProps {
  approvalId: string | null;
  onDecided: (detail: ApprovalDetail) => void;
}

export function ApprovalDetailPane({ approvalId, onDecided }: ApprovalDetailPaneProps) {
  const query = useApproval(approvalId);

  if (!approvalId) {
    return (
      <EmptyState
        icon={<UserCheck className="h-5 w-5" />}
        title="Select a request"
        description="Pick a request to see what the agent wants to do, why ContextOS paused it and what the agent had read."
      />
    );
  }
  if (query.isLoading) return <LoadingRows rows={8} />;
  if (query.error && !query.data) {
    if (isNotFound(query.error)) {
      return <EmptyState title="Request not found" description="It may belong to another organisation, or the link is wrong." />;
    }
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  if (!query.data) return null;
  return <DetailBody approval={query.data} receivedAt={query.dataUpdatedAt} onDecided={onDecided} />;
}

function DetailBody({ approval: a, receivedAt, onDecided }: { approval: ApprovalDetail; receivedAt: number; onDecided: (d: ApprovalDetail) => void }) {
  const { can } = useAuth();
  const pending = a.status === "pending";
  const deadline = deadlineOf(a, receivedAt);
  const now = useNow(1000, pending);
  const deadlinePassed = deadline !== null && deadline <= now;
  const chips = riskChips(a);

  return (
    <div className="space-y-4">
      <div className={cn("panel p-4", pending && "border-dec-approval/30")}>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={a.status} />
          {pending && <Countdown deadline={deadline} now={now} />}
          {a.is_simulation && <SimulationBadge />}
          <span className="ml-auto text-2xs text-fg-faint" title={formatDateTime(a.requested_at)}>
            Requested {timeAgo(a.requested_at)}
            {a.expires_at && pending ? ` · expires ${formatDateTime(a.expires_at)}` : ""}
          </span>
        </div>
        <h2 className="mt-2 text-[15px] font-semibold leading-snug text-fg">
          {a.agent.name ?? "The agent"} wants to {a.action}
        </h2>
        {chips.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {chips.map((c) => (
              <Badge key={c.key} tone={c.tone} title={c.title}>
                {c.label}
              </Badge>
            ))}
          </div>
        )}
        {ranWithoutApproval(a) && (
          <div role="status" className="mt-3 flex items-start gap-2 rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-xs text-fg">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger" aria-hidden />
            <span>{a.enforcement_note}</span>
          </div>
        )}

        <div className="mt-4 border-t border-border pt-3">
          {pending ? (
            <>
              {!ranWithoutApproval(a) && <p className="mb-3 text-xs leading-relaxed text-fg-muted">{a.enforcement_note}</p>}
              <DecisionBar approval={a} canApprove={can("approve")} deadlinePassed={deadlinePassed} onDecided={onDecided} />
            </>
          ) : (
            <Outcome approval={a} />
          )}
        </div>
      </div>

      <WhatSection approval={a} />
      <WhySection approval={a} />
      <ContextSection approval={a} />
      <FindingsSection approval={a} />
      <ActivitySection approval={a} />
    </div>
  );
}

function Outcome({ approval: a }: { approval: ApprovalDetail }) {
  const waited = a.decided_at ? Math.max(0, Math.round((Date.parse(a.decided_at) - Date.parse(a.requested_at)) / 1000)) : null;
  return (
    <div className="space-y-1.5 text-xs">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-fg">
        <span className="font-medium">{decidedByLabel(a)}</span>
        {a.decided_at && (
          <span className="text-fg-muted" title={formatDateTime(a.decided_at)}>
            {a.status === "expired" ? "expired" : a.status} {timeAgo(a.decided_at)}
          </span>
        )}
        {waited !== null && <span className="num text-fg-faint">after waiting {waited < 120 ? `${waited}s` : `${Math.round(waited / 60)} min`}</span>}
      </div>
      {a.decision_note && <p className="rounded border border-border bg-surface-2/60 px-2.5 py-1.5 text-fg">“{a.decision_note}”</p>}
      {!ranWithoutApproval(a) && <p className="text-fg-muted">{a.enforcement_note}</p>}
    </div>
  );
}
