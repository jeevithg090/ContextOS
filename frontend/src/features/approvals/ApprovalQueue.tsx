/** The pending queue: oldest first (closest to timing out), with a live countdown per request. */
import { useEffect, useRef, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Clock, ScrollText, UserCheck } from "lucide-react";
import { Badge, Button, EmptyState, ErrorState, Kbd, LoadingRows, SimulationBadge } from "@/components/ui";
import { TONE_CLASSES } from "@/lib/domain";
import { cn, timeAgo } from "@/lib/format";
import { countdownLabel, countdownTone, deadlineOf, formatCountdown, ranWithoutApproval, riskChips, useNow } from "./meta";
import type { Approval } from "./types";

const MAX_CHIPS = 3;

export function Countdown({ deadline, now, className }: { deadline: number | null; now: number; className?: string }) {
  if (deadline === null) return null;
  const left = deadline - now;
  const tone = left <= 0 ? "neutral" : countdownTone(left);
  return (
    <span
      className={cn("num inline-flex items-center gap-1 text-xs font-medium", TONE_CLASSES[tone].text, className)}
      title={left > 0 ? "Time left before this request expires. An expired request is treated as not approved." : undefined}
    >
      <Clock className="h-3 w-3" aria-hidden />
      <span aria-hidden>{left > 0 ? formatCountdown(left) : "Expiring…"}</span>
      <span className="sr-only">{countdownLabel(left)}</span>
    </span>
  );
}

export interface ApprovalQueueProps {
  items: Approval[] | undefined;
  /** When the list response arrived (anchors the countdowns). */
  receivedAt: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  /** Called shortly after the earliest deadline passes, so the server can expire it. */
  onDeadline: () => void;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onShowHistory: () => void;
}

export function ApprovalQueue({ items, receivedAt, selectedId, onSelect, onDeadline, loading, error, onRetry, onShowHistory }: ApprovalQueueProps) {
  const now = useNow(1000, !!items?.length);
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});

  // Refetch just after the earliest deadline: the server expires the request on read.
  useEffect(() => {
    const deadlines = (items ?? []).map((a) => deadlineOf(a, receivedAt)).filter((d): d is number => d !== null);
    if (deadlines.length === 0) return;
    const wait = Math.max(0, Math.min(...deadlines) - Date.now()) + 1500;
    const timer = window.setTimeout(onDeadline, Math.min(wait, 2_147_000_000));
    return () => window.clearTimeout(timer);
  }, [items, receivedAt, onDeadline]);

  useEffect(() => {
    if (selectedId) refs.current[selectedId]?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  if (loading && !items) return <LoadingRows rows={4} />;
  if (error && !items) return <ErrorState error={error} onRetry={onRetry} />;
  if (!items || items.length === 0) return <QueueEmpty onShowHistory={onShowHistory} />;

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = e.key === "ArrowDown" ? index + 1 : e.key === "ArrowUp" ? index - 1 : null;
    if (next === null || next < 0 || next >= items.length) return;
    e.preventDefault();
    onSelect(items[next].id);
    refs.current[items[next].id]?.focus();
  };

  return (
    <ul role="listbox" aria-label="Requests waiting for a decision" className="divide-y divide-border/70">
      {items.map((a, index) => {
        const selected = a.id === selectedId;
        const chips = riskChips(a);
        const policy = a.policy_decision?.deciding_policy;
        return (
          <li key={a.id} role="presentation">
            <button
              ref={(el) => {
                refs.current[a.id] = el;
              }}
              type="button"
              role="option"
              aria-selected={selected}
              tabIndex={selected || (!selectedId && index === 0) ? 0 : -1}
              onClick={() => onSelect(a.id)}
              onKeyDown={(e) => onKeyDown(e, index)}
              className={cn(
                "relative block w-full px-4 py-3 text-left transition-colors hover:bg-surface-2/70 focus-visible:outline-offset-[-2px]",
                selected && "bg-accent/[0.06]",
              )}
            >
              {selected && <span className="absolute inset-y-0 left-0 w-0.5 bg-accent" aria-hidden />}
              <div className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate text-xs text-fg-muted">
                  <span className="font-medium text-fg">{a.agent.name ?? "Unknown agent"}</span>
                  {a.agent.environment && <span className="text-fg-faint"> · {a.agent.environment}</span>}
                </span>
                <Countdown deadline={deadlineOf(a, receivedAt)} now={now} />
              </div>
              <div className="mt-1 text-[13px] font-medium leading-snug text-fg">
                wants to <span className="break-words">{a.action}</span>
              </div>
              <div className="mt-1 flex min-w-0 items-center gap-1.5 text-xs text-fg-muted">
                <ScrollText className="h-3 w-3 shrink-0 text-fg-faint" aria-hidden />
                <span className="truncate" title={a.policy_decision?.explanation}>
                  {policy ? policy.name : a.policy_decision ? "Organisation default decision" : "Policy decision not found"}
                </span>
              </div>
              {(chips.length > 0 || a.is_simulation || ranWithoutApproval(a)) && (
                <div className="mt-2 flex flex-wrap items-center gap-1">
                  {ranWithoutApproval(a) && (
                    <Badge tone="danger" title="The integration reported this call as already run.">
                      <AlertTriangle className="h-3 w-3" aria-hidden /> Already ran
                    </Badge>
                  )}
                  {chips.slice(0, MAX_CHIPS).map((c) => (
                    <Badge key={c.key} tone={c.tone} title={c.title}>
                      {c.label}
                    </Badge>
                  ))}
                  {chips.length > MAX_CHIPS && (
                    <Badge tone="neutral" title={chips.slice(MAX_CHIPS).map((c) => c.label).join(", ")}>
                      +{chips.length - MAX_CHIPS}
                    </Badge>
                  )}
                  {a.is_simulation && <SimulationBadge />}
                </div>
              )}
              <div className="mt-1.5 text-2xs text-fg-faint">Requested {timeAgo(a.requested_at)}</div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function QueueEmpty({ onShowHistory }: { onShowHistory: () => void }) {
  return (
    <EmptyState
      icon={<UserCheck className="h-5 w-5" />}
      title="Nothing is waiting for a human"
      description={
        <>
          A request appears here when a policy with the <span className="font-mono text-fg">REQUIRE_APPROVAL</span> outcome matches a tool
          call reported through an enforcing integration (Claude Code hook, MCP gateway or Python SDK guard). The integration holds the
          call until someone decides here or the request expires.
        </>
      }
      action={
        <div className="flex flex-wrap items-center justify-center gap-2">
          <Link to="/policies" className="inline-flex h-7 items-center rounded bg-accent px-2.5 text-xs font-medium text-accent-fg hover:bg-accent-strong">
            Review approval policies
          </Link>
          <Button size="sm" variant="ghost" onClick={onShowHistory}>
            See past decisions
          </Button>
        </div>
      }
    />
  );
}

export function KeyboardHints({ canDecide }: { canDecide: boolean }) {
  return (
    <div className="hidden flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-fg-faint sm:flex" aria-hidden>
      <span>
        <Kbd>J</Kbd> <Kbd>K</Kbd> move
      </span>
      {canDecide && (
        <>
          <span>
            <Kbd>A</Kbd> approve
          </span>
          <span>
            <Kbd>R</Kbd> reject
          </span>
        </>
      )}
    </div>
  );
}
