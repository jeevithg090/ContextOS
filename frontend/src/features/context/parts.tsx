/** Small building blocks shared by the Context Explorer tables, drawers and the receipt page. */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { KeyRound } from "lucide-react";
import { Badge, SeverityBadge } from "@/components/ui";
import { cn, pluralize, truncate } from "@/lib/format";
import { sensitivityMeta, sourceTypeMeta } from "./meta";
import type { DetectionCounts } from "./types";

export function SourceLabel({ type, identifier, displayName, className, compact = false }: { type: string; identifier: string; displayName?: string | null; className?: string; compact?: boolean }) {
  const meta = sourceTypeMeta(type);
  const Icon = meta.icon;
  const primary = displayName && displayName !== identifier ? displayName : identifier;
  return (
    <div className={cn("flex min-w-0 items-start gap-2", className)} title={identifier}>
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border border-border bg-surface-2 text-fg-muted" aria-hidden>
        <Icon className="h-3 w-3" />
      </span>
      <div className="min-w-0">
        <div className="truncate text-[13px] text-fg">{truncate(primary, 90)}</div>
        {!compact && (
          <div className="truncate text-2xs text-fg-faint">
            {meta.label}
            {primary !== identifier && <span className="font-mono"> · {truncate(identifier, 80)}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

export function SensitivityBadge({ sensitivity, containsSecrets }: { sensitivity: string; containsSecrets?: boolean }) {
  const meta = sensitivityMeta(sensitivity);
  return (
    <span className="inline-flex items-center gap-1">
      <Badge tone={meta.tone} title={meta.description}>
        {meta.label}
      </Badge>
      {containsSecrets && (
        <span className="text-sev-high" title="A credential was detected and redacted before storage">
          <KeyRound className="h-3.5 w-3.5" aria-label="Contains secrets" />
        </span>
      )}
    </span>
  );
}

export function DetectionCell({ detection }: { detection: DetectionCounts }) {
  if (!detection.hit_count) return <span className="text-xs text-fg-faint">None</span>;
  return (
    <span className="inline-flex items-center gap-1.5" title={detection.rule_ids.join(", ")}>
      <SeverityBadge severity={detection.max_severity} />
      <span className="num text-xs text-fg-muted">{pluralize(detection.hit_count, "hit")}</span>
    </span>
  );
}

/** A react-router link styled like an outline button (for navigation actions). */
export function ButtonLink({ to, children, icon, variant = "outline" }: { to: string; children: ReactNode; icon?: ReactNode; variant?: "outline" | "primary" }) {
  return (
    <Link
      to={to}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded px-2.5 text-xs transition-colors",
        variant === "primary" ? "bg-accent font-medium text-accent-fg hover:bg-accent-strong" : "border border-border-strong text-fg hover:bg-surface-2",
      )}
    >
      {icon}
      {children}
    </Link>
  );
}

/** Heading + body block used inside drawers (drawers are already a panel, so no extra border). */
export function DrawerSection({ title, description, actions, children }: { title: string; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="border-b border-border px-5 py-4 last:border-0" aria-label={title}>
      <div className="mb-2.5 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="label-caps">{title}</h3>
          {description && <p className="mt-1 text-xs text-fg-muted">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}
