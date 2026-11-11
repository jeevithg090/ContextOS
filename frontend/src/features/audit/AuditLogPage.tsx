/**
 * Audit Log — answers "who did what, and is the record intact?".
 * Filterable, newest-first list of the organisation's keyed hash-chained audit trail; "Verify chain"
 * recomputes every hash server-side and explains what a pass or failure means; admins can export the
 * full chain as JSON Lines (the export is itself audited). Filters are kept in the URL.
 */
import { useEffect, useState } from "react";
import { Download, ScrollText, ShieldCheck } from "lucide-react";
import { Pagination } from "@/components/data";
import { Button, EmptyState, ErrorState, LoadingRows, PageHeader, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { usePagination } from "@/hooks";
import { useAuditExport, useAuditLog, useVerifyChain } from "./api";
import { AuditFilterBar, useAuditFilterParams } from "./AuditFilters";
import { AuditTable } from "./AuditTable";
import { VerifyResult } from "./VerifyResult";

export function AuditLogPage() {
  const { can } = useAuth();
  const canExport = can("admin");
  const toast = useToast();
  const filterState = useAuditFilterParams();
  const { filters } = filterState;
  const pagination = usePagination(50);
  const filterKey = JSON.stringify(filters);
  const { reset } = pagination;
  useEffect(() => reset(), [filterKey, reset]);

  const log = useAuditLog(filters, pagination.params);
  const verify = useVerifyChain();
  const exporter = useAuditExport();
  const [showResult, setShowResult] = useState(false);

  const runVerify = () => {
    setShowResult(true);
    verify.mutate(undefined, {
      onError: (err) => toast.error("Verification could not run", err instanceof Error ? err.message : undefined),
    });
  };

  const runExport = () =>
    exporter.mutate(undefined, {
      onSuccess: (res) =>
        toast.success(
          `Exported ${res.filename}`,
          res.headHash ? `Head #${res.throughSeq} · ${res.headHash.slice(0, 16)}… — store it outside ContextOS to anchor the chain.` : undefined,
        ),
      onError: (err) => toast.error("Export failed", err instanceof Error ? err.message : undefined),
    });

  const rowActions = {
    onActor: (e: { actor_type: string; actor_id: string | null }) =>
      filterState.set({ actor_type: e.actor_type, actor_id: e.actor_id }),
    onTarget: (e: { target_type: string | null; target_id: string | null }) =>
      filterState.set({ target_type: e.target_type, target_id: e.target_id }),
  };

  return (
    <>
      <PageHeader
        eyebrow="Audit Log"
        title="Who did what, and is the record intact?"
        description="Every security-relevant change — sign-ins, policy and trust edits, approvals, denied tool calls, key management — is appended to a per-organisation chain in which each entry carries a keyed hash of itself and of the entry before it."
        actions={
          <>
            <Button variant="outline" size="sm" icon={<ShieldCheck className="h-3.5 w-3.5" aria-hidden />} onClick={runVerify} loading={verify.isPending}>
              Verify chain
            </Button>
            {canExport && (
              <Button variant="secondary" size="sm" icon={<Download className="h-3.5 w-3.5" aria-hidden />} onClick={runExport} loading={exporter.isPending} title="Download the full chain as JSON Lines (admin)">
                Export JSONL
              </Button>
            )}
          </>
        }
      />

      {showResult && verify.data && !verify.isPending && <VerifyResult result={verify.data} onDismiss={() => setShowResult(false)} />}

      <AuditFilterBar state={filterState} total={log.data?.total} />

      <div className="panel">
        {log.isLoading ? (
          <LoadingRows rows={8} />
        ) : log.isError || !log.data ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} />
        ) : log.data.items.length === 0 ? (
          <EmptyState
            icon={<ScrollText className="h-5 w-5" aria-hidden />}
            title={filterState.active ? "No entries match these filters" : "No audit entries yet"}
            description={
              filterState.active
                ? "Try a shorter action prefix or a wider time window."
                : "Entries appear when someone signs in, changes a policy or trust rule, decides an approval, manages keys, or when a tool call is denied."
            }
            action={
              filterState.active ? (
                <Button size="sm" variant="outline" onClick={filterState.clear}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <AuditTable items={log.data.items} actions={rowActions} />
            <div className="border-t border-border px-4 py-2">
              <Pagination
                total={log.data.total}
                limit={pagination.limit}
                offset={pagination.offset}
                onChange={pagination.setOffset}
                onLimitChange={pagination.setLimit}
                pageSizeOptions={[25, 50, 100, 200]}
                itemLabel="entries"
              />
            </div>
          </>
        )}
      </div>
    </>
  );
}
