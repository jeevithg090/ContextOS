/**
 * Approval Centre — answers "which sensitive actions are waiting for a human?".
 *
 * Queue tab: pending requests, oldest first (closest to timing out) with a live countdown; the
 * selected request opens beside the list with the decision controls (A / R, J / K to move).
 * History tab: approved, rejected and expired requests with who decided and when; a row opens the
 * same detail in a side panel. URL state: ?tab=history, ?approval=<id>, ?sim=1. Live updates arrive
 * through SSE invalidation of the "approvals" query keys (hooks/useLiveEvents).
 */
import { useCallback, useEffect, useMemo, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { Pagination } from "@/components/data";
import { Checkbox, Drawer, PageHeader, TabPanel, Tabs } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { usePagination } from "@/hooks";
import { useApprovalCount, useApprovals } from "./api";
import { ApprovalDetailPane } from "./ApprovalDetailPane";
import { ApprovalQueue, KeyboardHints } from "./ApprovalQueue";
import { HistoryList } from "./HistoryList";
import type { ApprovalDetail, ApprovalView } from "./types";

const QUEUE_PAGE = 100;
const HISTORY_PAGE = 25;

function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  return !!el?.closest?.("input, textarea, select, [contenteditable='true'], [role='dialog']");
}

export function ApprovalCentrePage() {
  const [params, setParams] = useSearchParams();
  const view: ApprovalView = params.get("tab") === "history" ? "history" : "queue";
  const selectedId = params.get("approval");
  const includeSimulated = params.get("sim") === "1";
  const { can } = useAuth();

  const queuePage = usePagination(QUEUE_PAGE);
  const historyPage = usePagination(HISTORY_PAGE);
  const queue = useApprovals({ view: "queue", includeSimulated, ...queuePage.params });
  const history = useApprovals({ view: "history", includeSimulated, ...historyPage.params }, { enabled: view === "history" });
  const historyCount = useApprovalCount("history", includeSimulated);
  const detailRef = useRef<HTMLDivElement>(null);

  const update = useCallback(
    (fn: (p: URLSearchParams) => void) =>
      setParams(
        (current) => {
          const next = new URLSearchParams(current);
          fn(next);
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const select = useCallback(
    (id: string | null, opts: { scroll?: boolean } = {}) => {
      update((p) => (id ? p.set("approval", id) : p.delete("approval")));
      if (id && opts.scroll && window.matchMedia("(max-width: 1023px)").matches) {
        window.requestAnimationFrame(() => detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
      }
    },
    [update],
  );

  const queueItems = queue.data?.items;
  const queueIds = useMemo(() => (queueItems ?? []).map((a) => a.id), [queueItems]);

  // Queue: keep a request selected so the decision controls are always one keystroke away.
  useEffect(() => {
    if (view === "queue" && !selectedId && queueIds.length > 0) select(queueIds[0]);
  }, [view, selectedId, queueIds, select]);

  // J / K move through the queue (arrow keys work inside the list itself).
  useEffect(() => {
    if (view !== "queue") return;
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      if (document.querySelector("[role='dialog']")) return;
      const key = e.key.toLowerCase();
      if (key !== "j" && key !== "k") return;
      if (queueIds.length === 0) return;
      e.preventDefault();
      const index = selectedId ? queueIds.indexOf(selectedId) : -1;
      const next = key === "j" ? Math.min(queueIds.length - 1, index + 1) : Math.max(0, index - 1);
      select(queueIds[next]);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, queueIds, selectedId, select]);

  /** After a decision, move on to the next request still waiting (the list refetches without it). */
  const onDecided = useCallback(
    (detail: ApprovalDetail) => {
      if (view !== "queue") return;
      const index = queueIds.indexOf(detail.id);
      const remaining = queueIds.filter((id) => id !== detail.id);
      const next = remaining[Math.min(Math.max(index, 0), remaining.length - 1)];
      if (next) select(next);
    },
    [view, queueIds, select],
  );

  const refetchQueue = useCallback(() => void queue.refetch(), [queue]);
  const showHistory = useCallback(
    () =>
      update((p) => {
        p.set("tab", "history");
        p.delete("approval");
      }),
    [update],
  );
  const queueTotal = queue.data?.total;

  return (
    <>
      <PageHeader
        title="Approval Centre"
        description="Sensitive tool calls that a REQUIRE_APPROVAL policy paused until a person decides. Approve lets the paused call run; Reject makes the integration deny it. Requests nobody decides expire and are treated as not approved."
        actions={
          <Checkbox
            label="Include simulated"
            checked={includeSimulated}
            onChange={(v) => {
              queuePage.reset();
              historyPage.reset();
              update((p) => (v ? p.set("sim", "1") : p.delete("sim")));
            }}
          />
        }
      />

      <Tabs
        value={view}
        onValueChange={(v) =>
          update((p) => {
            if (v === "history") p.set("tab", "history");
            else p.delete("tab");
            p.delete("approval");
          })
        }
        tabs={[
          { value: "queue", label: "Waiting for a decision", count: queueTotal },
          { value: "history", label: "History", count: historyCount.data },
        ]}
      >
        <TabPanel value="queue" className="pt-4">
          {queueTotal === 0 && !selectedId ? (
            <div className="panel">
              <ApprovalQueue
                items={queueItems}
                receivedAt={queue.dataUpdatedAt}
                selectedId={null}
                onSelect={select}
                onDeadline={refetchQueue}
                loading={false}
                error={null}
                onRetry={refetchQueue}
                onShowHistory={showHistory}
              />
            </div>
          ) : (
            <div className="grid items-start gap-4 lg:grid-cols-[minmax(300px,380px)_minmax(0,1fr)]">
              <div className="panel overflow-hidden lg:sticky lg:top-4">
                <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-2.5">
                  <span className="text-xs text-fg-muted">
                    {queueTotal === undefined ? "Loading…" : queueTotal === 0 ? "Queue is empty" : `${queueTotal} waiting · oldest first`}
                  </span>
                  {(queueTotal ?? 0) > 0 && <KeyboardHints canDecide={can("approve")} />}
                </div>
                <div className="lg:max-h-[calc(100vh-15rem)] lg:overflow-y-auto">
                  <ApprovalQueue
                    items={queueItems}
                    receivedAt={queue.dataUpdatedAt}
                    selectedId={selectedId}
                    onSelect={(id) => select(id, { scroll: true })}
                    onDeadline={refetchQueue}
                    loading={queue.isLoading}
                    error={queue.error}
                    onRetry={refetchQueue}
                    onShowHistory={showHistory}
                  />
                </div>
                {queue.data && queue.data.total > queue.data.limit && (
                  <Pagination total={queue.data.total} limit={queue.data.limit} offset={queue.data.offset} onChange={queuePage.setOffset} itemLabel="requests" className="border-t border-border px-4" />
                )}
              </div>
              <div ref={detailRef} className="min-w-0 scroll-mt-4">
                <ApprovalDetailPane approvalId={selectedId} onDecided={onDecided} />
              </div>
            </div>
          )}
        </TabPanel>

        <TabPanel value="history" className="pt-4">
          <div className="panel overflow-hidden">
            <HistoryList
              rows={history.data?.items}
              total={history.data?.total ?? 0}
              limit={historyPage.limit}
              offset={historyPage.offset}
              onPage={historyPage.setOffset}
              selectedId={selectedId}
              onSelect={(id) => select(id)}
              loading={history.isLoading}
              error={history.error}
              onRetry={() => void history.refetch()}
            />
          </div>
          <Drawer open={view === "history" && !!selectedId} onOpenChange={(open) => !open && select(null)} title="Approval request" width="w-[min(780px,100vw)]">
            <div className="p-4">
              <ApprovalDetailPane approvalId={selectedId} onDecided={() => undefined} />
            </div>
          </Drawer>
        </TabPanel>
      </Tabs>
    </>
  );
}
