/**
 * Replay Lab — answers "what exactly happened, and what if policy had been different?".
 *   /replay                       pick a recent session (with its live risk)
 *   /replay/:sessionId            step through the recorded events (?decision=<id> focuses that step)
 *   /replay/:sessionId?tab=counterfactual   re-evaluate recorded decisions under a hypothetical policy set
 * Recorded steps are facts (redacted); risk per step is recomputed from recorded events; the
 * counterfactual is a labelled simulation evaluated against recorded inputs only.
 */
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Activity, ArrowLeft, FlaskConical, History, Network } from "lucide-react";
import { EmptyState, ErrorState, LoadingRows, PageHeader, SimulationBadge, StatusBadge, TabPanel, Tabs } from "@/components/ui";
import { EntityLink, InlineStat, RiskMeter } from "@/components/data";
import { useDocumentTitle } from "@/hooks";
import { ApiError } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useCounterfactual, useReplay, useReplayLiveRefresh } from "./api";
import { CounterfactualTab } from "./counterfactual/CounterfactualTab";
import { EMPTY_POLICY_SET, type PolicySetState } from "./policySet";
import { ReplayPlayer } from "./player/ReplayPlayer";
import { SessionPicker } from "./SessionPicker";
import type { Replay } from "./types";

const linkButton =
  "inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded border border-border-strong px-2.5 text-xs text-fg transition-colors hover:bg-surface-2";

type Tab = "replay" | "counterfactual";

export function ReplayLabPage() {
  const { sessionId } = useParams();
  // The list and a replay share one route title; restore it when coming back from a session.
  useDocumentTitle(sessionId ? null : "Replay Lab");
  if (!sessionId) {
    return (
      <>
        <PageHeader
          title="Replay Lab"
          description="Step through exactly what an agent session consumed and did, what ContextOS decided at each point, and how session risk built up — then test how different policies would have decided the same recorded inputs."
        />
        <SessionPicker />
      </>
    );
  }
  return <SessionReplay key={sessionId} sessionId={sessionId} />;
}

function SessionReplay({ sessionId }: { sessionId: string }) {
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "counterfactual" ? "counterfactual" : "replay";
  const decisionId = params.get("decision");
  const offset = Math.max(0, Number(params.get("offset")) || 0);
  const replay = useReplay(sessionId, { offset, decisionId });
  useDocumentTitle(replay.data ? `Replay ${replay.data.session.external_session_id}` : null);
  const [policySet, setPolicySet] = useState<PolicySetState>(EMPTY_POLICY_SET);
  const run = useCounterfactual();
  useReplayLiveRefresh(sessionId);

  const setTab = (value: string) =>
    setParams((p) => {
      const next = new URLSearchParams(p);
      if (value === "counterfactual") next.set("tab", "counterfactual");
      else next.delete("tab");
      return next;
    });
  const setWindow = (nextOffset: number) =>
    setParams((p) => {
      const next = new URLSearchParams(p);
      next.delete("decision");
      if (nextOffset > 0) next.set("offset", String(nextOffset));
      else next.delete("offset");
      return next;
    });

  if (replay.isLoading) return <LoadingRows rows={10} />;
  if (replay.error instanceof ApiError && replay.error.status === 404) {
    return (
      <EmptyState
        icon={<Activity className="h-5 w-5" />}
        title="Session not found"
        description="It may belong to another organisation, or the link is wrong."
        action={
          <Link to="/replay" className="text-xs text-accent hover:underline">
            Choose another session
          </Link>
        }
      />
    );
  }
  if (replay.error || !replay.data) return <ErrorState error={replay.error} onRetry={() => replay.refetch()} />;
  const data = replay.data;
  const initialIndex = data.focus_index !== null ? data.focus_index - data.offset : 0;

  return (
    <>
      <Link to="/replay" className="mb-3 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> All sessions
      </Link>
      <ReplayHeader replay={data} />
      {decisionId && data.focus_index === null && (
        <p role="status" className="mb-4 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
          The linked policy decision was not found in this session, so the replay starts at the first step.
        </p>
      )}
      <Tabs
        value={tab}
        onValueChange={setTab}
        tabs={[
          { value: "replay", label: <span className="inline-flex items-center gap-1.5"><History className="h-3.5 w-3.5" aria-hidden />Replay</span>, count: data.total_steps },
          { value: "counterfactual", label: <span className="inline-flex items-center gap-1.5"><FlaskConical className="h-3.5 w-3.5" aria-hidden />Counterfactual</span>, count: data.decision_steps },
        ]}
      >
        <TabPanel value="replay" className="pt-4">
          <ReplayPlayer
            key={`${data.offset}:${data.focus_index ?? "start"}`}
            replay={data}
            initialIndex={Math.max(0, initialIndex)}
            onWindow={setWindow}
            keyboard={tab === "replay"}
          />
        </TabPanel>
        <TabPanel value="counterfactual" className="pt-4">
          <CounterfactualTab sessionId={sessionId} decisionSteps={data.decision_steps} state={policySet} onStateChange={setPolicySet} run={run} />
        </TabPanel>
      </Tabs>
    </>
  );
}

function ReplayHeader({ replay }: { replay: Replay }) {
  const s = replay.session;
  return (
    <PageHeader
      eyebrow="Replay Lab"
      title={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="font-mono text-lg">{s.external_session_id}</span>
          <StatusBadge status={s.status} />
          {s.is_simulation && <SimulationBadge />}
        </span>
      }
      description={
        <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="inline-flex items-center gap-1.5">
            Run by <EntityLink type="agent" id={s.agent.id} label={s.agent.name} />
          </span>
          <span>
            started{" "}
            <time dateTime={s.started_at} title={formatDateTime(s.started_at)}>
              {timeAgo(s.started_at)}
            </time>
          </span>
          <InlineStat label="Events" value={replay.total_steps} />
          <InlineStat label="Decisions" value={replay.decision_steps} />
          <span className="inline-flex items-center gap-1.5" title="The session's current, live risk — not a replayed value">
            <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">Live risk</span>
            <RiskMeter score={s.risk_score} level={s.risk_level} size="sm" label="Live session risk" />
          </span>
        </span>
      }
      actions={
        <>
          <Link to={`/sessions/${encodeURIComponent(s.id)}`} className={linkButton}>
            <Activity className="h-3.5 w-3.5" aria-hidden /> Session detail
          </Link>
          <Link to={`/provenance?session=${encodeURIComponent(s.id)}`} className={linkButton}>
            <Network className="h-3.5 w-3.5" aria-hidden /> Provenance graph
          </Link>
        </>
      }
    />
  );
}
