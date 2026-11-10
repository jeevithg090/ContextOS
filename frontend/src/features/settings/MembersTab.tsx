import { useMemo, useState } from "react";
import { UserPlus, Users } from "lucide-react";
import { ConfirmDialog, SearchInput, Section } from "@/components/data";
import { Badge, Button, EmptyState, ErrorState, LoadingRows, Select, Table, TD, TH, THead, TR, Tooltip, useToast } from "@/components/ui";
import type { Role } from "@/lib/domain";
import { formatDateTime, pluralize, timeAgo } from "@/lib/format";
import { useAuth } from "@/features/auth/AuthProvider";
import { useMembers, useRemoveMember, useUpdateMemberRole, type Member } from "./api";
import { AddMemberDialog } from "./AddMemberDialog";
import { PERMISSION_LABELS, ROLE_META, ROLE_ORDER } from "./meta";
import { AdminOnlyNotice } from "./SettingsControls";

type PendingRole = { member: Member; role: Role };

export function MembersTab() {
  const { me, can } = useAuth();
  const toast = useToast();
  const members = useMembers();
  const updateRole = useUpdateMemberRole();
  const remove = useRemoveMember();
  const [adding, setAdding] = useState(false);
  const [pendingRole, setPendingRole] = useState<PendingRole | null>(null);
  const [removing, setRemoving] = useState<Member | null>(null);
  const [query, setQuery] = useState("");

  const canAdmin = can("admin");
  const isOwner = me?.role === "owner";
  const items = useMemo(() => members.data?.items ?? [], [members.data]);
  const ownerCount = items.filter((m) => m.role === "owner").length;
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? items.filter((m) => m.name.toLowerCase().includes(q) || m.email.toLowerCase().includes(q)) : items;
  }, [items, query]);

  /** Why the current user cannot change this member's role (null = they can). */
  const roleLock = (m: Member): string | null => {
    if (!canAdmin) return "Only owners and admins can change roles.";
    if (m.role === "owner" && !isOwner) return "Only an owner can change another owner's role.";
    if (m.role === "owner" && ownerCount <= 1) return "Last owner — make someone else an owner first.";
    return null;
  };
  const removeLock = (m: Member): string | null => {
    if (m.user_id === me?.user.id) return "You cannot remove yourself. Ask another admin.";
    if (m.role === "owner" && !isOwner) return "Only an owner can remove an owner.";
    if (m.role === "owner" && ownerCount <= 1) return "The last owner cannot be removed.";
    return null;
  };

  return (
    <div className="space-y-5">
      {!canAdmin && <AdminOnlyNotice>You can see who has access. Only owners and admins can add, change or remove members.</AdminOnlyNotice>}
      <Section
        title="Members"
        description={members.data ? `${pluralize(members.data.total, "person", "people")} can sign in to this organisation.` : "People who can sign in to this organisation."}
        flush
        actions={
          <>
            <SearchInput value={query} onChange={setQuery} placeholder="Filter by name or email" className="w-56" />
            {canAdmin && (
              <Button size="sm" variant="primary" icon={<UserPlus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setAdding(true)}>
                Add member
              </Button>
            )}
          </>
        }
      >
        {members.isLoading ? (
          <LoadingRows rows={4} />
        ) : members.isError ? (
          <ErrorState error={members.error} onRetry={() => void members.refetch()} />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<Users className="h-4 w-4" />}
            title={items.length ? "No members match this filter" : "No members"}
            description={items.length ? "Try a different name or email." : undefined}
          />
        ) : (
          <Table>
            <THead>
              <tr>
                <TH>Member</TH>
                <TH>Role</TH>
                <TH className="hidden md:table-cell">Added</TH>
                <TH className="hidden sm:table-cell">Last sign-in</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </tr>
            </THead>
            <tbody>
              {filtered.map((m) => {
                const lock = roleLock(m);
                const removeBlocked = removeLock(m);
                const isSelf = m.user_id === me?.user.id;
                return (
                  <TR key={m.id}>
                    <TD>
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate font-medium text-fg">{m.name}</span>
                        {isSelf && <Badge tone="accent">You</Badge>}
                        {!m.is_active && <Badge tone="warn">Disabled</Badge>}
                      </div>
                      <div className="truncate text-xs text-fg-muted">{m.email}</div>
                    </TD>
                    <TD>
                      {lock && !canAdmin ? (
                        <span className="text-[13px] text-fg">{ROLE_META[m.role]?.label ?? m.role}</span>
                      ) : (
                        <Tooltip content={lock ?? ROLE_META[m.role]?.summary}>
                          <span className="inline-block">
                            <Select
                              aria-label={`Role for ${m.name}`}
                              value={m.role}
                              disabled={!!lock || updateRole.isPending}
                              onChange={(e) => setPendingRole({ member: m, role: e.target.value as Role })}
                              className="h-7 w-44 text-xs"
                            >
                              {ROLE_ORDER.map((r) => (
                                <option key={r} value={r} disabled={r === "owner" && !isOwner}>
                                  {ROLE_META[r].label}
                                </option>
                              ))}
                            </Select>
                          </span>
                        </Tooltip>
                      )}
                    </TD>
                    <TD className="hidden whitespace-nowrap text-xs text-fg-muted md:table-cell">{formatDateTime(m.created_at)}</TD>
                    <TD className="hidden whitespace-nowrap text-xs text-fg-muted sm:table-cell">
                      {m.last_login_at ? <span title={formatDateTime(m.last_login_at)}>{timeAgo(m.last_login_at)}</span> : "Never"}
                    </TD>
                    <TD className="text-right">
                      {canAdmin && (
                        <Tooltip content={removeBlocked ?? `Remove ${m.name} from this organisation`}>
                          <span className="inline-block">
                            <Button size="xs" variant="ghost" disabled={!!removeBlocked} onClick={() => setRemoving(m)}>
                              Remove
                            </Button>
                          </span>
                        </Tooltip>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>

      <RoleReference />

      <AddMemberDialog open={adding} onOpenChange={setAdding} isOwner={isOwner} />

      <ConfirmDialog
        open={!!pendingRole}
        onOpenChange={(open) => !open && setPendingRole(null)}
        title={pendingRole ? `Change ${pendingRole.member.name}'s role?` : "Change role?"}
        description={pendingRole ? `${ROLE_META[pendingRole.member.role].label} → ${ROLE_META[pendingRole.role].label}` : undefined}
        confirmLabel="Change role"
        destructive={pendingRole?.member.user_id === me?.user.id}
        onConfirm={async () => {
          if (!pendingRole) return;
          await updateRole.mutateAsync({ id: pendingRole.member.id, role: pendingRole.role });
          toast.success("Role updated", `${pendingRole.member.name} is now ${ROLE_META[pendingRole.role].label}.`);
        }}
      >
        {pendingRole && (
          <>
            <p>{ROLE_META[pendingRole.role].summary}</p>
            <p>The change applies to their next request; they do not need to sign in again.</p>
            {pendingRole.member.user_id === me?.user.id && (
              <p className="text-warn">You are changing your own role. You may lose access to this page.</p>
            )}
          </>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={removing ? `Remove ${removing.name}?` : "Remove member?"}
        description={removing?.email}
        confirmLabel="Remove member"
        destructive
        onConfirm={async () => {
          if (!removing) return;
          await remove.mutateAsync(removing.id);
          toast.success("Member removed", `${removing.email} no longer has access to this organisation.`);
        }}
      >
        <p>They lose access to this organisation immediately. Their user account and memberships in other organisations are not affected.</p>
        <p>API keys they created keep working — revoke them on the API keys tab if needed.</p>
      </ConfirmDialog>
    </div>
  );
}

function RoleReference() {
  return (
    <Section title="Roles" description="What each role can do. Permissions are checked on the server for every request.">
      <dl className="grid gap-x-8 gap-y-4 md:grid-cols-2">
        {ROLE_ORDER.map((r) => (
          <div key={r} className="min-w-0">
            <dt className="text-[13px] font-medium text-fg">{ROLE_META[r].label}</dt>
            <dd className="mt-0.5 text-xs leading-relaxed text-fg-muted">{ROLE_META[r].summary}</dd>
            <dd className="mt-1.5 flex flex-wrap gap-1">
              {ROLE_META[r].permissions.map((p) => (
                <Badge key={p} tone="neutral">
                  {PERMISSION_LABELS[p] ?? p}
                </Badge>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}
