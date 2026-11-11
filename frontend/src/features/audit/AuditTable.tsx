import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { Bot, ChevronRight, Filter, KeyRound, User } from "lucide-react";
import { CopyButton, EntityLink, JsonView } from "@/components/data";
import { Button, KeyValue, Mono, Table, TD, TH, THead, TR } from "@/components/ui";
import { cn, formatDateTime, shortId, timeAgo } from "@/lib/format";
import { actorTypeLabel, auditTarget } from "./meta";
import type { AuditEntry } from "./types";

export interface RowFilterActions {
  onActor: (entry: AuditEntry) => void;
  onTarget: (entry: AuditEntry) => void;
}

/** Action name that may wrap after its dots (never mid-word). */
function ActionText({ action }: { action: string }) {
  const parts = action.split(".");
  return (
    <span className="font-mono text-xs text-fg">
      {parts.map((part, i) => (
        <Fragment key={i}>
          {part}
          {i < parts.length - 1 && (
            <>
              .<wbr />
            </>
          )}
        </Fragment>
      ))}
    </span>
  );
}

function ActorCell({ entry }: { entry: AuditEntry }) {
  const Icon = entry.actor_type === "user" ? User : entry.actor_type === "api_key" ? KeyRound : Bot;
  const missing = entry.actor_type === "user" ? "Not a current member" : "Unknown API key";
  return (
    <div className="flex min-w-0 items-start gap-2">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
      <div className="min-w-0">
        {entry.actor_label ? (
          <div className="truncate text-fg">{entry.actor_label}</div>
        ) : entry.actor_id ? (
          <div className="truncate text-fg-muted" title={`${missing} (${entry.actor_id})`}>
            <Mono>{shortId(entry.actor_id)}</Mono>
          </div>
        ) : (
          <div className="text-fg-muted">{actorTypeLabel(entry.actor_type)}</div>
        )}
        <div className="truncate text-2xs text-fg-faint">
          {actorTypeLabel(entry.actor_type)}
          {entry.actor_detail ? ` · ${entry.actor_detail}` : !entry.actor_label && entry.actor_id ? ` · ${missing.toLowerCase()}` : ""}
        </div>
      </div>
    </div>
  );
}

export function TargetCell({ entry }: { entry: AuditEntry }) {
  const target = auditTarget(entry);
  if (!target) return <span className="text-fg-faint">—</span>;
  if (target.kind === "entity") return <EntityLink type={target.type} id={target.id} label={target.label} sessionId={target.sessionId} />;
  if (target.kind === "page") {
    return (
      <Link to={target.href} onClick={(e) => e.stopPropagation()} title={target.id} className="inline-flex max-w-full items-center gap-1 truncate text-accent hover:underline">
        <span className="truncate">{target.label}</span>
        <Mono className="text-2xs text-fg-faint">{shortId(target.id)}</Mono>
      </Link>
    );
  }
  return (
    <span className="inline-flex min-w-0 items-center gap-1 text-fg-muted" title={`${target.type} ${target.id}`}>
      <span className="text-xs">{target.type.replace(/_/g, " ")}</span>
      <Mono className="text-2xs">{shortId(target.id)}</Mono>
    </span>
  );
}

function ExpandedRow({ entry, actions }: { entry: AuditEntry; actions: RowFilterActions }) {
  const hasDetails = Object.keys(entry.details ?? {}).length > 0;
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,360px)]">
      <div className="min-w-0">
        <div className="label-caps mb-1.5">Details</div>
        {hasDetails ? (
          <JsonView value={entry.details} defaultExpandDepth={2} title={entry.action} maxHeightClassName="max-h-80" />
        ) : (
          <p className="text-xs text-fg-faint">No details were recorded with this entry.</p>
        )}
        <p className="mt-1.5 text-2xs text-fg-faint">Secrets in details are redacted before they are written and again before they are shown.</p>
      </div>
      <div className="min-w-0 space-y-3">
        <KeyValue
          className="text-xs"
          items={[
            { label: "Entry", value: <span className="flex items-center gap-1"><Mono>{entry.id}</Mono><CopyButton size="xs" value={entry.id} label="Copy entry id" /></span> },
            { label: "Time", value: formatDateTime(entry.occurred_at) },
            { label: "Actor id", value: entry.actor_id ? <Mono>{entry.actor_id}</Mono> : "—" },
            { label: "Hash", value: <Mono className="break-all">{entry.hash}</Mono> },
            { label: "Previous", value: entry.prev_hash ? <Mono className="break-all">{entry.prev_hash}</Mono> : <span className="text-fg-faint">First entry of the chain</span> },
          ]}
        />
        <div className="flex flex-wrap gap-2">
          {entry.actor_id && (
            <Button size="xs" variant="outline" icon={<Filter className="h-3 w-3" aria-hidden />} onClick={() => actions.onActor(entry)}>
              Only this actor
            </Button>
          )}
          {entry.target_type && entry.target_id && (
            <Button size="xs" variant="outline" icon={<Filter className="h-3 w-3" aria-hidden />} onClick={() => actions.onTarget(entry)}>
              Only this target
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export function AuditTable({ items, actions }: { items: AuditEntry[]; actions: RowFilterActions }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <Table>
      <THead>
        <tr>
          <TH className="w-8 !pl-3 !pr-0">
            <span className="sr-only">Expand</span>
          </TH>
          <TH className="w-12 !px-2 text-right">#</TH>
          <TH>Time</TH>
          <TH>Actor</TH>
          <TH>Action</TH>
          <TH className="hidden md:table-cell">Target</TH>
        </tr>
      </THead>
      <tbody>
        {items.map((entry) => {
          const expanded = open.has(entry.id);
          const panelId = `audit-${entry.id}`;
          return (
            <Fragment key={entry.id}>
              <TR onClick={() => toggle(entry.id)} selected={expanded}>
                <TD className="w-8 !pl-3 !pr-0">
                  <button
                    type="button"
                    aria-expanded={expanded}
                    aria-controls={panelId}
                    aria-label={`${expanded ? "Hide" : "Show"} details of entry ${entry.seq}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      toggle(entry.id);
                    }}
                    className="inline-flex h-6 w-6 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg"
                  >
                    <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-90")} aria-hidden />
                  </button>
                </TD>
                <TD className="num w-12 !px-2 text-right text-xs text-fg-faint">{entry.seq}</TD>
                <TD className="whitespace-nowrap text-xs text-fg-muted">
                  <span title={formatDateTime(entry.occurred_at)}>{timeAgo(entry.occurred_at)}</span>
                </TD>
                <TD className="max-w-[220px]">
                  <ActorCell entry={entry} />
                </TD>
                <TD className="max-w-[220px]">
                  <ActionText action={entry.action} />
                </TD>
                <TD className="hidden max-w-[220px] md:table-cell">
                  <TargetCell entry={entry} />
                </TD>
              </TR>
              {expanded && (
                <tr id={panelId} className="border-b border-border/70 bg-surface-2/40">
                  <td colSpan={6} className="px-4 py-3">
                    <div className="mb-3 md:hidden">
                      <span className="label-caps mr-2">Target</span>
                      <TargetCell entry={entry} />
                    </div>
                    <ExpandedRow entry={entry} actions={actions} />
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}
