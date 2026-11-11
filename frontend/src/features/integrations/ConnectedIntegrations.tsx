import { Plug } from "lucide-react";
import { Section } from "@/components/data";
import { Badge, Button, EmptyState, EnforcementBadge, Mono, StatusBadge, Table, TD, TH, THead, TR } from "@/components/ui";
import { ENFORCEMENT_META, type EnforcementMode } from "@/lib/domain";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { InlineCode } from "./InlineCode";
import type { ConnectedIntegration, EnforcementCounts } from "./types";

const MODES: EnforcementMode[] = ["enforced", "advisory", "observed"];

/** Decisions recorded for an integration, split by the enforcement claim stored with each one. */
export function DecisionSplit({ counts }: { counts: EnforcementCounts }) {
  const total = counts.enforced + counts.advisory + counts.observed;
  if (!total) return <span className="text-xs text-fg-faint">None yet</span>;
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1" aria-label="Decisions by enforcement">
      {MODES.filter((m) => counts[m] > 0).map((mode) => (
        <li key={mode} className="inline-flex items-center gap-1.5 text-xs" title={ENFORCEMENT_META[mode].description}>
          <span className="num font-medium text-fg">{formatNumber(counts[mode])}</span>
          <span className="text-fg-muted">{ENFORCEMENT_META[mode].label.toLowerCase()}</span>
        </li>
      ))}
    </ul>
  );
}

export function ConnectedIntegrations({
  items,
  staleWindow,
  onSetup,
}: {
  items: ConnectedIntegration[];
  /** The staleness window in words, e.g. "24 hours" (see meta.staleWindowLabel). */
  staleWindow: string;
  onSetup: (kind: string) => void;
}) {
  return (
    <Section
      title="Connected integrations"
      description={`Integrations that have sent real (non-simulated) events. Connected means an event arrived in the last ${staleWindow}.`}
      flush
    >
      {items.length === 0 ? (
        <EmptyState
          icon={<Plug className="h-5 w-5" aria-hidden />}
          title="No integration has sent events yet"
          description="Install an integration below. It appears here as soon as ContextOS receives its first event; Simulation Lab runs never count."
          action={
            <Button size="sm" variant="primary" onClick={() => onSetup("claude_code")}>
              Set up Claude Code
            </Button>
          }
        />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Integration</TH>
              <TH>Health</TH>
              <TH className="text-right">Events</TH>
              <TH className="hidden md:table-cell">Decisions</TH>
              <TH>Can enforce</TH>
            </tr>
          </THead>
          <tbody>
            {items.map((item) => (
              <TR key={item.id}>
                <TD>
                  <div className="flex min-w-0 flex-col gap-0.5">
                    <span className="flex items-center gap-2 font-medium text-fg">
                      {item.display_name}
                      {!item.supported && (
                        <Badge tone="neutral" title="ContextOS has no first-party adapter for this integration name">
                          No ContextOS adapter
                        </Badge>
                      )}
                    </span>
                    <span className="text-2xs text-fg-faint">
                      <Mono className="text-2xs">{item.kind}</Mono>
                      {" · "}
                      {item.agent_count === 1 ? "1 agent" : `${formatNumber(item.agent_count)} agents`}
                    </span>
                  </div>
                </TD>
                <TD>
                  <div className="flex flex-col items-start gap-1">
                    <span title={item.health_detail}>
                      <StatusBadge status={item.health} />
                    </span>
                    <span className="whitespace-nowrap text-2xs text-fg-faint" title={`Last event ${formatDateTime(item.last_event_at)} · first seen ${formatDateTime(item.first_seen_at)}`}>
                      {item.last_event_at ? `last event ${timeAgo(item.last_event_at)}` : "no events yet"}
                    </span>
                    {item.health !== "connected" && <span className="max-w-[240px] text-2xs leading-4 text-fg-faint">
                        <InlineCode text={item.health_detail} />
                      </span>}
                    {item.last_error && (
                      <span className="max-w-[260px] text-2xs leading-4 text-danger" role="note">
                        Last error: {item.last_error}
                      </span>
                    )}
                  </div>
                </TD>
                <TD className="text-right">
                  <div className="num text-[13px] text-fg">{formatNumber(item.event_count)}</div>
                  <div className="num text-2xs text-fg-faint">{formatNumber(item.events_24h)} in 24 h</div>
                </TD>
                <TD className="hidden md:table-cell">
                  <DecisionSplit counts={item.decisions} />
                </TD>
                <TD>
                  <EnforcementBadge mode={item.best_enforcement} />
                </TD>
              </TR>
            ))}
          </tbody>
        </Table>
      )}
    </Section>
  );
}
