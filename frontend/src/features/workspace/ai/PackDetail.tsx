import { AlertTriangle, Info } from "lucide-react";
import { InlineStat } from "@/components/data";
import { cn } from "@/lib/format";
import { TokenBudgetMeter } from "./controls";
import { PackItemsTable } from "./PackItemsTable";
import type { ContextPack, ContextPackSummary } from "./types";

/** Counts line for a pack: what was included, verified, left out for budget or safety. */
export function PackCounts({ pack, className }: { pack: ContextPackSummary; className?: string }) {
  const c = pack.counts;
  return (
    <div className={cn("flex flex-wrap gap-x-5 gap-y-1.5", className)}>
      <InlineStat label="Included" value={`${c.included}/${c.total}`} hint="Items whose content or reference goes to the agent, of all items considered" />
      <InlineStat label="Verified" value={c.verified} tone={c.verified > 0 ? "trusted" : undefined} hint="Confirmed to exist in the repository or as a ContextOS record" />
      <InlineStat label="Unverified" value={c.unverified} tone={c.unverified > 0 ? "unknown" : undefined} hint="Could not be confirmed; the agent must check them" />
      <InlineStat label="Over budget" value={c.over_budget} tone={c.over_budget > 0 ? "warn" : undefined} hint="Left out because the token budget was used up" />
      <InlineStat label="Sensitive excluded" value={c.excluded_sensitive} tone={c.excluded_sensitive > 0 ? "danger" : undefined} hint="Sensitive files are never read or included" />
    </div>
  );
}

/** Notice when file references could not be checked against a repository. */
export function RepositoryNotice({ verified, configured }: { verified: boolean; configured?: boolean }) {
  if (verified) return null;
  return (
    <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn/[0.06] px-3 py-2 text-xs">
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
      <p className="text-fg-muted">
        <span className="font-medium text-fg">File references are unverified. </span>
        {configured === false
          ? "No repository root is configured on the ContextOS server, so files could not be checked or read. Only ContextOS records are verified."
          : "The repository was not readable when this pack was built, so files could not be checked or read. Only ContextOS records are verified."}
      </p>
    </div>
  );
}

/** Full view of a stored context pack: budget, counts, build notes and the inspectable items. */
export function PackDetail({ pack, canEdit, repositoryConfigured }: { pack: ContextPack; canEdit: boolean; repositoryConfigured?: boolean }) {
  return (
    <div className="space-y-4">
      <TokenBudgetMeter estimate={pack.token_estimate} budget={pack.token_budget} label={`${pack.profile_label} profile budget`} />
      <PackCounts pack={pack} />
      <RepositoryNotice verified={pack.repository_verified} configured={repositoryConfigured} />
      {pack.notes.length > 0 && (
        <ul className="space-y-1 rounded-md border border-border bg-surface-2/40 px-3 py-2" aria-label="How this pack was built">
          {pack.notes.map((note, i) => (
            <li key={i} className="flex items-start gap-2 text-2xs text-fg-muted">
              <Info className="mt-0.5 h-3 w-3 shrink-0 text-fg-faint" aria-hidden />
              {note}
            </li>
          ))}
        </ul>
      )}
      <PackItemsTable pack={pack} canEdit={canEdit} />
    </div>
  );
}
