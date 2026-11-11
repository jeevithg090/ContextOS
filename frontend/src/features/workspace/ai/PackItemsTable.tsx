import { Fragment, useMemo, useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight, CircleDashed, ShieldOff } from "lucide-react";
import { CodeBlock, FilterBar, FilterSelect, SegmentedControl } from "@/components/data";
import { Badge, EmptyState, Spinner, Table, TD, TH, THead, TR, useToast } from "@/components/ui";
import { cn } from "@/lib/format";
import { useToggleContextPackItems } from "./api";
import { KindBadge } from "./controls";
import { mutationMessage } from "./hooks";
import { formatTokens, isSafetyExcluded, ITEM_KINDS, itemKindLabel, itemStatusMeta, kindMeta, PACK_CATEGORIES } from "./meta";
import type { ContextPack, ContextPackItem } from "./types";

type Inclusion = "all" | "included" | "excluded";

export function VerifiedMark({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-2xs text-trust-trusted" title="Confirmed to exist (repository file or ContextOS record)">
      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
      Verified
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-2xs text-trust-unknown" title="Not confirmed to exist — the agent must check before relying on it">
      <CircleDashed className="h-3.5 w-3.5" aria-hidden />
      Unverified
    </span>
  );
}

function includeBlockedReason(item: ContextPackItem): string | null {
  if (item.included || item.can_include) return null;
  return itemStatusMeta(String(item.status)).description || "This item cannot be included.";
}

/**
 * Items of a context pack with category / kind / inclusion filters and include toggles
 * (PATCH /context-packs/{id}). Sensitive and rejected paths are listed separately with the reason
 * they were excluded; their contents are never read.
 */
export function PackItemsTable({ pack, canEdit, className }: { pack: ContextPack; canEdit: boolean; className?: string }) {
  const toast = useToast();
  const toggle = useToggleContextPackItems();
  const [category, setCategory] = useState("");
  const [kind, setKind] = useState("");
  const [inclusion, setInclusion] = useState<Inclusion>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const content = useMemo(() => pack.items.filter((i) => i.kind !== "note"), [pack.items]);
  const safety = useMemo(() => content.filter(isSafetyExcluded), [content]);
  const main = useMemo(() => content.filter((i) => !isSafetyExcluded(i)), [content]);
  const rows = main.filter(
    (i) => (!category || i.category === category) && (!kind || i.kind === kind) && (inclusion === "all" || (inclusion === "included" ? i.included : !i.included)),
  );
  const kindsPresent = ITEM_KINDS.filter((k) => k !== "note" && main.some((i) => i.kind === k));
  const categoriesPresent = PACK_CATEGORIES.filter((c) => main.some((i) => i.category === c));
  const filtered = !!(category || kind || inclusion !== "all");

  const setIncluded = (item: ContextPackItem, included: boolean) => {
    setPendingKey(item.key);
    toggle.mutate(
      { packId: pack.id, items: [{ key: item.key, included }] },
      {
        onSuccess: (next) => {
          const after = next.items.find((i) => i.key === item.key);
          if (after && after.included !== included) toast.error("No change", `${item.title || item.ref} could not be ${included ? "included" : "excluded"}.`);
        },
        onError: (err) => toast.error(included ? "Could not include item" : "Could not exclude item", mutationMessage(err)),
        onSettled: () => setPendingKey(null),
      },
    );
  };

  return (
    <div className={className}>
      <FilterBar
        canClear={filtered}
        onClear={() => {
          setCategory("");
          setKind("");
          setInclusion("all");
        }}
        actions={
          <SegmentedControl<Inclusion>
            aria-label="Show items"
            value={inclusion}
            onChange={setInclusion}
            options={[
              { value: "all", label: "All", count: main.length },
              { value: "included", label: "Included", count: main.filter((i) => i.included).length },
              { value: "excluded", label: "Not included", count: main.filter((i) => !i.included).length },
            ]}
          />
        }
      >
        <FilterSelect label="Category" value={category} onChange={setCategory} options={categoriesPresent.map((c) => ({ value: c, label: kindMeta(c).label, count: main.filter((i) => i.category === c).length }))} />
        <FilterSelect label="Kind" value={kind} onChange={setKind} options={kindsPresent.map((k) => ({ value: k, label: itemKindLabel(k), count: main.filter((i) => i.kind === k).length }))} />
      </FilterBar>

      {rows.length === 0 ? (
        <EmptyState
          className="rounded-md border border-border py-10"
          title={filtered ? "No items match these filters" : "This pack has no items"}
          description={filtered ? "Clear a filter to see more items." : "No related records or repository files were found for this task."}
        />
      ) : (
        <Table className="rounded-md border border-border">
          <THead>
            <tr>
              <TH className="w-10 pl-3 pr-0">
                <span className="sr-only">Included</span>
              </TH>
              <TH className="pl-2">Item</TH>
              <TH>Category</TH>
              <TH>Verified</TH>
              <TH className="hidden md:table-cell">Status</TH>
              <TH className="text-right">Tokens</TH>
              <TH className="hidden xl:table-cell">Reason</TH>
              <TH className="w-8 px-2">
                <span className="sr-only">Details</span>
              </TH>
            </tr>
          </THead>
          <tbody>
            {rows.map((item) => {
              const blocked = includeBlockedReason(item);
              const status = itemStatusMeta(String(item.status));
              const open = expanded === item.key;
              const busy = pendingKey === item.key;
              return (
                <Fragment key={item.key}>
                  <TR className={cn(!item.included && "text-fg-muted")}>
                    <TD className="py-2 pl-3 pr-0">
                      {busy ? (
                        <Spinner className="h-3.5 w-3.5" />
                      ) : (
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 rounded border-border-strong bg-surface-2 accent-[rgb(var(--accent))] disabled:cursor-not-allowed disabled:opacity-40"
                          checked={item.included}
                          disabled={!canEdit || !!blocked || pendingKey !== null}
                          title={blocked ?? (canEdit ? (item.included ? "Exclude from the pack" : "Include in the pack") : "You need write access to change the pack")}
                          aria-label={`${item.included ? "Exclude" : "Include"} ${item.title || item.ref}`}
                          onChange={(e) => setIncluded(item, e.target.checked)}
                        />
                      )}
                    </TD>
                    <TD className="max-w-[340px] py-2 pl-2">
                      <div className={cn("truncate text-[13px]", item.included ? "text-fg" : "text-fg-muted")} title={item.title}>
                        {item.title || item.ref}
                      </div>
                      <div className="flex min-w-0 items-center gap-1.5 text-2xs text-fg-faint">
                        <span className="shrink-0">{itemKindLabel(item.kind)}</span>
                        <span aria-hidden>·</span>
                        <span className="truncate font-mono" title={item.ref}>
                          {item.ref}
                        </span>
                      </div>
                    </TD>
                    <TD className="py-2">
                      <KindBadge kind={item.category} />
                    </TD>
                    <TD className="py-2">
                      <VerifiedMark verified={item.verified} />
                    </TD>
                    <TD className="hidden py-2 md:table-cell">
                      <Badge tone={status.tone} title={status.description}>
                        {status.label}
                      </Badge>
                    </TD>
                    <TD className="num py-2 text-right text-xs">{item.token_estimate > 0 ? formatTokens(item.token_estimate, false) : <span className="text-fg-faint">—</span>}</TD>
                    <TD className="hidden max-w-[320px] py-2 xl:table-cell">
                      <span className="line-clamp-2 text-2xs text-fg-muted" title={item.reason}>
                        {item.reason}
                      </span>
                    </TD>
                    <TD className="px-2 py-2">
                      <button
                        type="button"
                        onClick={() => setExpanded(open ? null : item.key)}
                        aria-expanded={open}
                        aria-label={`${open ? "Hide" : "Show"} details for ${item.title || item.ref}`}
                        className="inline-flex h-6 w-6 items-center justify-center rounded text-fg-faint hover:bg-surface-2 hover:text-fg"
                      >
                        {open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
                      </button>
                    </TD>
                  </TR>
                  {open && (
                    <tr className="border-b border-border/70 bg-surface-2/40">
                      <td colSpan={8} className="space-y-2 px-4 py-3">
                        <p className="text-xs text-fg-muted">
                          <span className="font-medium text-fg">Why: </span>
                          {item.reason || "No reason recorded."}
                        </p>
                        {blocked && <p className="text-2xs text-warn">Cannot be included: {blocked}</p>}
                        {item.excerpt ? (
                          <CodeBlock code={item.excerpt} title={item.ref} maxHeight={220} wrap />
                        ) : (
                          <p className="text-2xs text-fg-faint">No excerpt stored — the agent receives the reference only.</p>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </Table>
      )}

      {safety.length > 0 && (
        <div className="mt-4 rounded-md border border-danger/25 bg-danger/[0.04]">
          <div className="flex items-center gap-2 border-b border-danger/20 px-3 py-2">
            <ShieldOff className="h-3.5 w-3.5 text-danger" aria-hidden />
            <h4 className="text-xs font-medium text-fg">Excluded for safety ({safety.length})</h4>
            <span className="text-2xs text-fg-muted">Never read and never sent — these cannot be included.</span>
          </div>
          <ul className="divide-y divide-danger/10">
            {safety.map((item) => (
              <li key={item.key} className="flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2">
                <span className="min-w-0 max-w-full truncate font-mono text-xs text-fg" title={item.ref}>
                  {item.ref}
                </span>
                <Badge tone={itemStatusMeta(String(item.status)).tone}>{itemStatusMeta(String(item.status)).label}</Badge>
                <span className="w-full text-2xs text-fg-muted">{item.reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
