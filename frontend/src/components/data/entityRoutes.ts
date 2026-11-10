/**
 * Single source of truth for "where does entity X live in the app". EntityLink, EvidenceList and
 * any feature that needs a URL for a record should call `entityHref` instead of hand-building
 * paths, so a route change only has to be made here.
 */
import {
  Activity,
  Bot,
  Database,
  FileText,
  FlaskConical,
  Globe,
  Radar,
  Scale,
  ScrollText,
  Siren,
  SquareCheck,
  UserCheck,
  Wrench,
  Zap,
  type LucideIcon,
} from "lucide-react";

export const ENTITY_TYPES = [
  "agent",
  "session",
  "context_item",
  "finding",
  "incident",
  "task",
  "policy",
  "source",
  "destination",
  "tool_invocation",
  "approval",
  "policy_decision",
  "simulation_run",
  "event",
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];

export interface EntityMeta {
  label: string;
  icon: LucideIcon;
}

export const ENTITY_META: Record<EntityType, EntityMeta> = {
  agent: { label: "Agent", icon: Bot },
  session: { label: "Session", icon: Activity },
  context_item: { label: "Context item", icon: FileText },
  finding: { label: "Finding", icon: Radar },
  incident: { label: "Incident", icon: Siren },
  task: { label: "Task", icon: SquareCheck },
  policy: { label: "Policy", icon: ScrollText },
  source: { label: "Source", icon: Database },
  destination: { label: "Destination", icon: Globe },
  tool_invocation: { label: "Tool call", icon: Wrench },
  approval: { label: "Approval", icon: UserCheck },
  policy_decision: { label: "Policy decision", icon: Scale },
  simulation_run: { label: "Simulation run", icon: FlaskConical },
  event: { label: "Event", icon: Zap },
};

export function isEntityType(value: unknown): value is EntityType {
  return typeof value === "string" && (ENTITY_TYPES as readonly string[]).includes(value);
}

/** Human label for an entity type, tolerant of unknown backend values ("tool_invocation" → "Tool call"). */
export function entityTypeLabel(type: string): string {
  if (isEntityType(type)) return ENTITY_META[type].label;
  const spaced = type.replace(/[_.]/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : "Record";
}

/**
 * App route for an entity, or `null` when it has no page of its own (events) or the route needs
 * context that was not supplied (tool calls and policy decisions live inside a session).
 */
export function entityHref(type: string, id: string, opts: { sessionId?: string | null } = {}): string | null {
  if (!id) return null;
  const e = encodeURIComponent(id);
  const session = opts.sessionId ? encodeURIComponent(opts.sessionId) : null;
  switch (type) {
    case "agent":
      return `/agents/${e}`;
    case "session":
      return `/sessions/${e}`;
    case "context_item":
      return `/context/${e}`;
    case "finding":
      return `/intelligence/${e}`;
    case "incident":
      return `/incidents/${e}`;
    case "task":
      return `/work/tasks/${e}`;
    case "policy":
      return `/policies?policy=${e}`;
    case "source":
      return `/trust?source=${e}`;
    case "destination":
      return `/trust?tab=destinations&destination=${e}`;
    case "tool_invocation":
      return session ? `/sessions/${session}?invocation=${e}` : null;
    case "approval":
      return `/approvals?approval=${e}`;
    case "policy_decision":
      return session ? `/replay/${session}?decision=${e}` : null;
    case "simulation_run":
      return `/simulation?run=${e}`;
    default:
      return null;
  }
}
