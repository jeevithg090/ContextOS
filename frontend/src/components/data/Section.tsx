import { useId, type ReactNode } from "react";
import { TONE_CLASSES, type Tone } from "@/lib/domain";
import { cn } from "@/lib/format";

export interface SectionProps {
  title: ReactNode;
  description?: ReactNode;
  /** Right-aligned controls (filters, "View all" link, actions). */
  actions?: ReactNode;
  children: ReactNode;
  /** "panel" = bordered card; "plain" = heading over content (for use inside an existing panel). */
  variant?: "panel" | "plain";
  /** Removes body padding (tables and lists that run edge to edge). */
  flush?: boolean;
  id?: string;
  className?: string;
  bodyClassName?: string;
}

/** Titled block of content with optional actions. The building block of detail pages. */
export function Section({ title, description, actions, children, variant = "panel", flush = false, id, className, bodyClassName }: SectionProps) {
  const headingId = useId();
  const panel = variant === "panel";
  return (
    <section id={id} aria-labelledby={headingId} className={cn(panel && "panel", className)}>
      <div className={cn("flex flex-wrap items-start justify-between gap-x-3 gap-y-2", panel ? "border-b border-border px-4 py-3" : "pb-2")}>
        <div className="min-w-0">
          <h2 id={headingId} className="text-[13px] font-semibold text-fg">
            {title}
          </h2>
          {description && <p className="mt-0.5 text-xs text-fg-muted">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      <div className={cn(panel && !flush && "p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export interface InlineStatProps {
  label: string;
  value: ReactNode;
  tone?: Tone;
  /** Short explanation shown as a tooltip (what the number counts, where it comes from). */
  hint?: string;
  className?: string;
}

/** Compact "label value" pair for header metadata rows and summaries. */
export function InlineStat({ label, value, tone, hint, className }: InlineStatProps) {
  return (
    <div className={cn("inline-flex min-w-0 items-baseline gap-1.5", className)} title={hint}>
      <span className="text-2xs uppercase tracking-[0.06em] text-fg-faint">{label}</span>
      <span className={cn("num truncate text-[13px] font-medium", tone ? TONE_CLASSES[tone].text : "text-fg")}>{value}</span>
    </div>
  );
}
