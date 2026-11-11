/** Ownership and classification: severity, assignee (org members only) and when/by whom it was opened. */
import { useId } from "react";
import { KeyValue, Select, SeverityBadge, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { SEVERITY_META, type Severity } from "@/lib/domain";
import { formatDateTime, timeAgo } from "@/lib/format";
import { errorMessage, useMembers, useUpdateIncident } from "../api";
import { SEVERITY_OPTIONS } from "../meta";
import type { IncidentDetail } from "../types";

export function DetailsPanel({ incident, canWrite }: { incident: IncidentDetail; canWrite: boolean }) {
  const severityId = useId();
  const assigneeId = useId();
  const toast = useToast();
  const { me } = useAuth();
  const members = useMembers(canWrite);
  const update = useUpdateIncident(incident.id);

  const change = (body: Parameters<typeof update.mutate>[0], success: string) =>
    update.mutate(body, {
      onSuccess: () => toast.success(success),
      onError: (err) => toast.error("Could not update the incident", errorMessage(err)),
    });

  const memberList = members.data ?? [];
  const assigneeKnown = !incident.assignee || memberList.some((m) => m.user_id === incident.assignee?.id);

  const severity = canWrite ? (
    <div className="flex items-center gap-2">
      <label htmlFor={severityId} className="sr-only">
        Severity
      </label>
      <Select
        id={severityId}
        value={incident.severity}
        disabled={update.isPending}
        onChange={(e) => change({ severity: e.target.value as Severity }, `Severity set to ${SEVERITY_META[e.target.value as Severity].label.toLowerCase()}`)}
        className="!h-7 !w-36 !text-xs"
      >
        {SEVERITY_OPTIONS.map((s) => (
          <option key={s} value={s}>
            {SEVERITY_META[s].label}
          </option>
        ))}
      </Select>
      {incident.max_finding_severity && SEVERITY_META[incident.max_finding_severity].rank > SEVERITY_META[incident.severity].rank && (
        <span className="text-2xs text-warn" title="The most severe linked finding is rated higher than the incident">
          finding is {incident.max_finding_severity}
        </span>
      )}
    </div>
  ) : (
    <SeverityBadge severity={incident.severity} />
  );

  const assignee = canWrite ? (
    <div className="flex flex-wrap items-center gap-2">
      <label htmlFor={assigneeId} className="sr-only">
        Assignee
      </label>
      <Select
        id={assigneeId}
        value={incident.assignee?.id ?? ""}
        disabled={update.isPending || members.isLoading}
        onChange={(e) => {
          const value = e.target.value || null;
          const name = memberList.find((m) => m.user_id === value)?.name;
          change({ assignee_user_id: value }, value ? `Assigned to ${name ?? "member"}` : "Unassigned");
        }}
        className="!h-7 !w-44 !text-xs"
      >
        <option value="">Unassigned</option>
        {!assigneeKnown && incident.assignee && <option value={incident.assignee.id}>{incident.assignee.name}</option>}
        {memberList.map((m) => (
          <option key={m.user_id} value={m.user_id}>
            {m.name}
          </option>
        ))}
      </Select>
      {me && incident.assignee?.id !== me.user.id && (
        <button type="button" className="text-2xs text-accent hover:underline disabled:opacity-50" disabled={update.isPending} onClick={() => change({ assignee_user_id: me.user.id }, "Assigned to you")}>
          Assign to me
        </button>
      )}
      {members.error && <span className="text-2xs text-danger">Members unavailable</span>}
    </div>
  ) : (
    <span>{incident.assignee?.name ?? <span className="text-fg-faint">Unassigned</span>}</span>
  );

  return (
    <KeyValue
      items={[
        { label: "Severity", value: severity },
        { label: "Assignee", value: assignee },
        {
          label: "Opened",
          value: (
            <time dateTime={incident.opened_at} title={formatDateTime(incident.opened_at)}>
              {timeAgo(incident.opened_at)} by {incident.created_by.type === "system" ? "ContextOS (automatic)" : incident.created_by.name}
            </time>
          ),
        },
        { label: "Last update", value: <time dateTime={incident.updated_at} title={formatDateTime(incident.updated_at)}>{timeAgo(incident.updated_at)}</time> },
      ]}
    />
  );
}
