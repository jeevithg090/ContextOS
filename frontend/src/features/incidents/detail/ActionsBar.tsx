/**
 * Investigation actions: export the evidence bundle, open the provenance graph, replay the primary
 * session and create remediation tasks in the Engineering Workspace.
 */
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Download, GitBranch, History, ListPlus } from "lucide-react";
import { ConfirmDialog } from "@/components/data";
import { Button, useToast } from "@/components/ui";
import { pluralize } from "@/lib/format";
import { errorMessage, useCreateRemediationTasks, useExportIncident } from "../api";
import type { IncidentDetail } from "../types";

const linkButton =
  "inline-flex h-8 items-center gap-2 whitespace-nowrap rounded border border-border-strong px-3 text-[13px] text-fg transition-colors hover:bg-surface-2";

export function ActionsBar({ incident, canWrite }: { incident: IncidentDetail; canWrite: boolean }) {
  const toast = useToast();
  const navigate = useNavigate();
  const exporter = useExportIncident(incident.id, incident.key);
  const remediate = useCreateRemediationTasks(incident.id);
  const [confirming, setConfirming] = useState(false);

  const session = incident.primary_session ?? (incident.involved.sessions[0] ? { id: incident.involved.sessions[0].id } : null);
  const provenance = session
    ? `/provenance?session=${encodeURIComponent(session.id)}`
    : incident.findings[0]
      ? `/provenance?finding=${encodeURIComponent(incident.findings[0].id)}`
      : null;
  const grouped = incident.open_finding_count > 1;

  const exportBundle = () =>
    exporter.mutate(undefined, {
      onSuccess: (r) => toast.success("Evidence bundle downloaded", r.sha256 ? `SHA-256 ${r.sha256.slice(0, 16)}… is recorded in the audit log.` : r.filename),
      onError: (err) => toast.error("Export failed", errorMessage(err)),
    });

  const createTasks = async () => {
    const result = await remediate.mutateAsync(grouped ? "parent_with_subtasks" : "per_finding");
    const created = result.created_count;
    toast.success(
      created ? `${pluralize(created, "remediation task")} created` : "Remediation tasks already exist",
      result.existing_count ? `${pluralize(result.existing_count, "existing task")} reused.` : undefined,
    );
    const target = result.parent_task_id ?? (result.tasks.length === 1 ? result.tasks[0].task.id : null);
    navigate(target ? `/work/tasks/${encodeURIComponent(target)}` : "/work/remediation");
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        icon={<Download className="h-3.5 w-3.5" aria-hidden />}
        onClick={exportBundle}
        loading={exporter.isPending}
        title="Download a JSON evidence bundle (findings, decisions with their inputs, signed receipts, redacted events, audit entries). The export is audited."
      >
        Export evidence
      </Button>
      {provenance ? (
        <Link to={provenance} className={linkButton} title="Observed relationships around this incident, as a graph">
          <GitBranch className="h-3.5 w-3.5" aria-hidden />
          Provenance graph
        </Link>
      ) : (
        <Button icon={<GitBranch className="h-3.5 w-3.5" aria-hidden />} disabled title="Link a finding or session first">
          Provenance graph
        </Button>
      )}
      {session ? (
        <Link to={`/replay/${encodeURIComponent(session.id)}`} className={linkButton} title="Step through the primary session and try what-if policy changes (a simulation)">
          <History className="h-3.5 w-3.5" aria-hidden />
          Replay session
        </Link>
      ) : (
        <Button icon={<History className="h-3.5 w-3.5" aria-hidden />} disabled title="No session is linked to this incident">
          Replay session
        </Button>
      )}
      {canWrite && (
        <Button
          variant="primary"
          icon={<ListPlus className="h-3.5 w-3.5" aria-hidden />}
          onClick={() => setConfirming(true)}
          disabled={incident.open_finding_count === 0}
          title={incident.open_finding_count === 0 ? "No open findings to fix" : "Create Engineering Workspace tasks for the open findings"}
        >
          Create remediation tasks
        </Button>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Create remediation tasks"
        description={
          grouped
            ? `Creates one task for each of the ${incident.open_finding_count} open findings, grouped under a parent task for ${incident.key}, on the Security Remediation board. Findings that already have an open task reuse it.`
            : `Creates a task for the open finding of ${incident.key} on the Security Remediation board, or reuses its existing open task.`
        }
        confirmLabel="Create tasks"
        onConfirm={createTasks}
      />
    </div>
  );
}
