import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, KeyRound, Plus } from "lucide-react";
import { ConfirmDialog, CopyButton, EntityLink, SegmentedControl, Section } from "@/components/data";
import { Badge, Button, EmptyState, ErrorState, LoadingRows, Mono, StatusBadge, Table, TD, TH, THead, TR, useToast } from "@/components/ui";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useApiKeys, useRevokeApiKey, type ApiKey, type ApiKeyCreated } from "./api";
import { SCOPE_META } from "./meta";
import { CreateApiKeyDialog } from "./CreateApiKeyDialog";

type View = "usable" | "all";

export function ApiKeysTab({ canAdmin }: { canAdmin: boolean }) {
  const toast = useToast();
  const keys = useApiKeys(canAdmin);
  const revoke = useRevokeApiKey();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const [view, setView] = useState<View>("usable");

  const items = useMemo(() => keys.data?.items ?? [], [keys.data]);
  const counts = useMemo(() => ({ usable: items.filter((k) => k.status === "active").length, all: items.length }), [items]);
  const visible = view === "usable" ? items.filter((k) => k.status === "active") : items;

  if (!canAdmin) {
    return (
      <Section title="API keys" description="Credentials integrations use to report events and request decisions.">
        <EmptyState
          icon={<KeyRound className="h-4 w-4" />}
          title="Only owners and admins can manage API keys"
          description="Ask an administrator for a key scoped to your integration. Keys are shown once, when created, and ContextOS stores only their hash."
        />
      </Section>
    );
  }

  return (
    <div className="space-y-5">
      {created && <NewKeyPanel created={created} onDismiss={() => setCreated(null)} />}

      <Section
        title="API keys"
        description="Credentials integrations use to report events (ingest), request decisions before a tool runs (decide) or read data (read)."
        flush
        actions={
          <>
            <SegmentedControl
              aria-label="Which keys to show"
              value={view}
              onChange={setView}
              options={[
                { value: "usable", label: "Active", count: counts.usable },
                { value: "all", label: "All", count: counts.all },
              ]}
            />
            <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
              Create API key
            </Button>
          </>
        }
      >
        {keys.isLoading ? (
          <LoadingRows rows={3} />
        ) : keys.isError ? (
          <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />
        ) : visible.length === 0 ? (
          <EmptyState
            icon={<KeyRound className="h-4 w-4" />}
            title={items.length ? "No active keys" : "No API keys yet"}
            description={
              items.length
                ? "Every key in this organisation has been revoked or has expired. Switch to “All” to see them."
                : "Create a key for each integration — for example one per developer machine running the Claude Code hooks — so each can be revoked on its own."
            }
            action={
              <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setCreating(true)}>
                Create API key
              </Button>
            }
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Key</TH>
                <TH>Scopes</TH>
                <TH className="hidden lg:table-cell">Agent</TH>
                <TH className="hidden md:table-cell">Created</TH>
                <TH>Last used</TH>
                <TH className="hidden sm:table-cell">Expires</TH>
                <TH>Status</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </tr>
            </THead>
            <tbody>
              {visible.map((k) => (
                <TR key={k.id} className={k.status !== "active" ? "opacity-60" : undefined}>
                  <TD>
                    <div className="font-medium text-fg">{k.name}</div>
                    <Mono title="Key prefix — not enough to authenticate">{k.prefix}…</Mono>
                  </TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {k.scopes.map((s) => (
                        <Badge key={s} tone="neutral" title={SCOPE_META[s]?.description}>
                          {SCOPE_META[s]?.label ?? s}
                        </Badge>
                      ))}
                    </div>
                  </TD>
                  <TD className="hidden lg:table-cell">
                    {k.agent_id ? <EntityLink type="agent" id={k.agent_id} label={k.agent_name} /> : <span className="text-xs text-fg-faint">Any agent</span>}
                  </TD>
                  <TD className="hidden whitespace-nowrap text-xs text-fg-muted md:table-cell">
                    <span title={formatDateTime(k.created_at)}>{timeAgo(k.created_at)}</span>
                    <div className="text-fg-faint">{k.created_by_name ? `by ${k.created_by_name}` : "by CLI / system"}</div>
                  </TD>
                  <TD className="whitespace-nowrap text-xs text-fg-muted">
                    {k.last_used_at ? <span title={formatDateTime(k.last_used_at)}>{timeAgo(k.last_used_at)}</span> : "Never"}
                  </TD>
                  <TD className="hidden whitespace-nowrap text-xs text-fg-muted sm:table-cell">
                    {k.revoked_at ? (
                      <span title={formatDateTime(k.revoked_at)}>Revoked {timeAgo(k.revoked_at)}</span>
                    ) : k.expires_at ? (
                      <span title={formatDateTime(k.expires_at)}>{timeAgo(k.expires_at)}</span>
                    ) : (
                      "Never"
                    )}
                  </TD>
                  <TD>
                    <StatusBadge status={k.status} />
                  </TD>
                  <TD className="text-right">
                    {k.status !== "revoked" && (
                      <Button size="xs" variant="ghost" className="text-danger hover:text-danger" onClick={() => setRevoking(k)}>
                        Revoke
                      </Button>
                    )}
                  </TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <CreateApiKeyDialog open={creating} onOpenChange={setCreating} onCreated={setCreated} />

      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={revoking ? `Revoke “${revoking.name}”?` : "Revoke key?"}
        description={revoking ? `${revoking.prefix}… · ${revoking.scopes.join(", ")}` : undefined}
        confirmLabel="Revoke key"
        destructive
        onConfirm={async () => {
          if (!revoking) return;
          await revoke.mutateAsync(revoking.id);
          if (created?.id === revoking.id) setCreated(null);
          toast.success("API key revoked", `${revoking.name} can no longer authenticate.`);
        }}
      >
        <p>Any integration using this key is rejected (HTTP 401) from its next request. This cannot be undone — create a new key to restore access.</p>
        {revoking?.last_used_at && <p>It was last used {timeAgo(revoking.last_used_at)}.</p>}
      </ConfirmDialog>
    </div>
  );
}

/** Shown once, right after creation. The raw key is held only in component state and never refetched. */
function NewKeyPanel({ created, onDismiss }: { created: ApiKeyCreated; onDismiss: () => void }) {
  return (
    <section aria-labelledby="new-key-title" className="panel border-warn/40 bg-warn/[0.04] p-4">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
        <div className="min-w-0 flex-1">
          <h2 id="new-key-title" className="text-[13px] font-semibold text-fg">
            Copy “{created.name}” now — it will not be shown again
          </h2>
          <p className="mt-1 text-xs text-fg-muted">
            ContextOS stores only a hash of this key. Put it in your secret manager or the integration's configuration; if it is lost, revoke it
            and create a new one.
          </p>
          <div className="mt-3 flex items-center gap-2 rounded border border-border-strong bg-bg px-3 py-2">
            <code className="min-w-0 flex-1 select-all break-all font-mono text-xs text-fg" aria-label="New API key">
              {created.key}
            </code>
            <CopyButton value={created.key} label="Copy API key" />
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-fg-muted">
            <span>Scopes: {created.scopes.map((s) => SCOPE_META[s]?.label ?? s).join(", ")}</span>
            <span>Agent: {created.agent_name ?? "any"}</span>
            <span>Expires: {created.expires_at ? formatDateTime(created.expires_at) : "never"}</span>
            <Link to="/integrations" className="text-accent hover:underline">
              Set up an integration
            </Link>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={onDismiss}>
          I’ve stored it
        </Button>
      </div>
    </section>
  );
}
