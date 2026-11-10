import type { MouseEvent } from "react";
import { Link } from "react-router-dom";
import { Hash } from "lucide-react";
import { cn, shortId } from "@/lib/format";
import { ENTITY_META, entityHref, entityTypeLabel, isEntityType } from "./entityRoutes";

export interface EntityLinkProps {
  /** Entity kind (see ENTITY_TYPES). Unknown kinds render as plain mono text. */
  type: string;
  id: string | null | undefined;
  /** Human label (e.g. agent name). Without one, the shortened id is shown. */
  label?: string | null;
  /** Required for tool_invocation and policy_decision, which are shown inside their session. */
  sessionId?: string | null;
  showIcon?: boolean;
  className?: string;
}

/**
 * Cross-reference to any ContextOS record. Always use this rather than raw ids so every screen
 * links the same way. Click events do not bubble, so it is safe inside clickable table rows.
 */
export function EntityLink({ type, id, label, sessionId, showIcon = true, className }: EntityLinkProps) {
  if (!id) return <span className="text-fg-faint">—</span>;

  const Icon = isEntityType(type) ? ENTITY_META[type].icon : Hash;
  const href = entityHref(type, id, { sessionId });
  const typeLabel = entityTypeLabel(type);
  const text = label?.trim() ? label : shortId(id);
  const isId = !label?.trim();
  const title = label?.trim() ? `${typeLabel}: ${label} (${id})` : `${typeLabel} ${id}`;

  const content = (
    <>
      {showIcon && <Icon className="h-3.5 w-3.5 shrink-0 opacity-80" aria-hidden />}
      <span className={cn("truncate", isId && "font-mono text-xs")}>{text}</span>
    </>
  );

  const base = "inline-flex max-w-full min-w-0 items-center gap-1 align-middle";

  if (!href) {
    return (
      <span className={cn(base, "text-fg-muted", className)} title={title}>
        {content}
      </span>
    );
  }

  return (
    <Link
      to={href}
      title={title}
      aria-label={`${typeLabel} ${label?.trim() ? label : id}`}
      onClick={(e: MouseEvent) => e.stopPropagation()}
      className={cn(base, "rounded-sm text-accent transition-colors hover:text-accent-strong hover:underline hover:underline-offset-2", className)}
    >
      {content}
    </Link>
  );
}
