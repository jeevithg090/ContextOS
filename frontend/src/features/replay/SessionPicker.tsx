/** Recent sessions to replay, with their live risk, so the riskiest ones are easy to find. */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { History } from "lucide-react";
import { Badge, Checkbox, EmptyState, ErrorState, LoadingRows, Mono, SimulationBadge, StatusBadge, Table, TD, TH, THead, TR } from "@/components/ui";
import { EntityLink, RiskMeter, SearchInput, SegmentedControl } from "@/components/data";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useReplaySessions } from "./api";
import type { SessionPickerFilters, SessionSort } from "./types";

export function SessionPicker() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<SessionPickerFilters>({ q: "", sort: "recent", include_simulated: false });
  const sessions = useReplaySessions(filters);
  const items = sessions.data?.items ?? [];
  const open = (id: string) => navigate(`/replay/${encodeURIComponent(id)}`);

  return (
    <section className="panel" aria-label="Choose a session to replay">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <h2 className="mr-auto text-[13px] font-semibold text-fg">Choose a session</h2>
        <SearchInput value={filters.q} onChange={(q) => setFilters((f) => ({ ...f, q }))} placeholder="Session id…" label="Search sessions" className="w-56" />
        <SegmentedControl<SessionSort>
          aria-label="Sort sessions"
          value={filters.sort}
          onChange={(sort) => setFilters((f) => ({ ...f, sort }))}
          options={[
            { value: "recent", label: "Recent" },
            { value: "risk", label: "Highest risk" },
          ]}
        />
        <Checkbox label="Include simulations" checked={filters.include_simulated} onChange={(include_simulated) => setFilters((f) => ({ ...f, include_simulated }))} />
      </div>
      {sessions.isLoading ? (
        <LoadingRows rows={6} />
      ) : sessions.error ? (
        <ErrorState error={sessions.error} onRetry={() => sessions.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<History className="h-5 w-5" />}
          title={filters.q ? "No sessions match this search" : "No sessions recorded yet"}
          description={
            filters.q
              ? "Search matches the integration's session id."
              : "Sessions appear once an integration reports events. Run a Simulation Lab scenario to replay a realistic attack without real agents."
          }
        />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Session</TH>
              <TH>Agent</TH>
              <TH>Risk (live)</TH>
              <TH>Events</TH>
              <TH>Open findings</TH>
              <TH>Last activity</TH>
            </tr>
          </THead>
          <tbody>
            {items.map((s) => (
              <TR key={s.id} onClick={() => open(s.id)}>
                <TD>
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        open(s.id);
                      }}
                      className="rounded-sm font-mono text-xs text-accent hover:underline focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent"
                      aria-label={`Replay session ${s.external_session_id}`}
                    >
                      {s.external_session_id}
                    </button>
                    <StatusBadge status={s.status} />
                    {s.is_simulation && <SimulationBadge />}
                  </span>
                </TD>
                <TD>
                  <EntityLink type="agent" id={s.agent.id} label={s.agent.name} />
                </TD>
                <TD>
                  <span className="inline-flex items-center gap-2">
                    <RiskMeter score={s.risk_score} level={s.risk_level} size="sm" label="Live session risk" />
                    {s.trifecta && <Badge tone="critical">Trifecta</Badge>}
                  </span>
                </TD>
                <TD>
                  <Mono className="text-fg">{s.event_count}</Mono>
                </TD>
                <TD>{s.open_findings > 0 ? <Badge tone="high">{s.open_findings}</Badge> : <span className="text-fg-faint">0</span>}</TD>
                <TD>
                  <time dateTime={s.last_event_at ?? s.started_at} title={formatDateTime(s.last_event_at ?? s.started_at)} className="text-xs text-fg-muted">
                    {timeAgo(s.last_event_at ?? s.started_at)}
                  </time>
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
      {sessions.data && sessions.data.total > items.length && (
        <p className="border-t border-border px-4 py-2 text-2xs text-fg-faint">
          Showing {items.length} of {sessions.data.total} sessions. Search by session id to find older ones.
        </p>
      )}
    </section>
  );
}
