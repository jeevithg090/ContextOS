/** Destination detail: verification checks (and what was NOT verified), why it is classified this
 * way, recent calls and the decisions made, and pinning a classification with an exact-match rule. */
import { useId, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Pin } from "lucide-react";
import {
  Badge,
  Button,
  DecisionBadge,
  Drawer,
  EmptyState,
  EnforcementBadge,
  ErrorState,
  Field,
  KeyValue,
  LoadingRows,
  Select,
  SeverityBadge,
  SimulationBadge,
  StatusBadge,
  Textarea,
  TrustBadge,
  useToast,
} from "@/components/ui";
import { ConfirmDialog, CopyButton, EntityLink, Section } from "@/components/data";
import { useAuth } from "@/features/auth/AuthProvider";
import { ApiError } from "@/lib/api";
import { TRUST_LEVELS, TRUST_META, type TrustLevel } from "@/lib/domain";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { errorMessage, useClassifyDestination, useDeleteRule, useTrustDestination } from "./api";
import { NotVerified } from "./AssessmentView";
import { CheckList, ReasonList } from "./components";
import { DESTINATION_KIND_LABELS, reassessMessage } from "./meta";
import type { TrustDestinationDetail } from "./types";

export function DestinationDrawer({ destinationId, onClose }: { destinationId: string; onClose: () => void }) {
  const dest = useTrustDestination(destinationId);
  const data = dest.data;
  return (
    <Drawer
      open
      onOpenChange={(open) => !open && onClose()}
      title={data ? data.identifier : "Destination"}
      subtitle={data ? `${DESTINATION_KIND_LABELS[data.kind] ?? data.kind} · first seen ${timeAgo(data.first_seen_at)}` : undefined}
    >
      {dest.isLoading ? (
        <LoadingRows rows={8} />
      ) : dest.error ? (
        dest.error instanceof ApiError && dest.error.status === 404 ? (
          <EmptyState title="Destination not found" description="It may belong to another organisation or have been removed by retention." />
        ) : (
          <ErrorState error={dest.error} onRetry={() => void dest.refetch()} />
        )
      ) : data ? (
        <DestinationBody dest={data} />
      ) : null}
    </Drawer>
  );
}

function ClassifyDestinationForm({ dest }: { dest: TrustDestinationDetail }) {
  const toast = useToast();
  const classify = useClassifyDestination(dest.id);
  const [level, setLevel] = useState<TrustLevel>(dest.classification);
  const [note, setNote] = useState("");
  const levelId = useId();
  const noteId = useId();
  const canSave = note.trim().length > 0 && !classify.isPending;
  const submit = async () => {
    if (!canSave) return;
    try {
      const saved = await classify.mutateAsync({ classification: level, note: note.trim() });
      setNote("");
      toast.success(`Pinned as ${TRUST_META[saved.classification].label}`, "An exact-match destination rule now keeps this classification.");
    } catch {
      /* shown inline */
    }
  };
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <p className="text-xs text-fg-muted">
        Saving creates or updates the rule <span className="font-mono text-fg">Destination override: {dest.identifier}</span>, which matches only this
        identifier and has a priority above every other rule that matches it. Policies see the new classification on the next tool call.
      </p>
      <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
        <Field label="Classification" htmlFor={levelId}>
          <Select
            id={levelId}
            value={level}
            onChange={(e) => {
              if (classify.error) classify.reset();
              setLevel(e.target.value as TrustLevel);
            }}
          >
            {TRUST_LEVELS.map((l) => (
              <option key={l} value={l}>
                {TRUST_META[l].label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Note (required)" htmlFor={noteId} hint="Recorded on the rule and in the audit trail; secrets are redacted.">
          <Textarea
            id={noteId}
            value={note}
            maxLength={1000}
            onChange={(e) => {
              if (classify.error) classify.reset();
              setNote(e.target.value);
            }}
            placeholder="e.g. Partner ingestion endpoint confirmed with their security team"
            className="min-h-[56px]"
          />
        </Field>
      </div>
      {(level === "TRUSTED" || level === "APPROVED") && (
        <p className="text-2xs text-fg-faint">
          Approving a destination says the organisation accepts sending data there. ContextOS cannot confirm who operates it or who reads what is sent.
        </p>
      )}
      {classify.error && (
        <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-2.5 py-2 text-xs text-danger">
          {errorMessage(classify.error)}
        </p>
      )}
      <div className="flex justify-end">
        <Button type="submit" variant="primary" size="sm" loading={classify.isPending} disabled={!canSave}>
          Pin classification
        </Button>
      </div>
    </form>
  );
}

function DestinationBody({ dest }: { dest: TrustDestinationDetail }) {
  const { can } = useAuth();
  const canManage = can("trust:manage");
  const toast = useToast();
  const removeRule = useDeleteRule();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const decisions = Object.entries(dest.decision_counts).sort((a, b) => b[1] - a[1]);
  const enforcement = Object.entries(dest.enforcement_counts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-5 p-5">
      <section aria-label="Classification" className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <TrustBadge level={dest.classification} />
          {dest.override_rule_id && (
            <Badge tone="accent">
              <Pin className="h-3 w-3" aria-hidden /> Pinned
            </Badge>
          )}
          <span className="text-xs text-fg-muted">
            {dest.trust_rule_id ? (
              <>
                by rule{" "}
                <Link to={`/trust?tab=rules&rule=${encodeURIComponent(dest.trust_rule_id)}`} className="text-accent hover:underline">
                  “{dest.trust_rule_name ?? dest.trust_rule_id}”
                </Link>
              </>
            ) : (
              "by default (no destination rule matches)"
            )}
          </span>
          {dest.override_rule_id && canManage && (
            <Button size="xs" variant="ghost" onClick={() => setConfirmRemove(true)}>
              Remove pin
            </Button>
          )}
        </div>
        {dest.stale && (
          <p role="note" className="flex items-start gap-1.5 text-xs text-warn">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            With the current rules this destination would be {TRUST_META[dest.assessment.level].label}; the stored classification updates on its next call.
          </p>
        )}
      </section>

      <Section variant="plain" title="Verification checks" description="Recorded at the last assessment. Every check looks at the name or address only.">
        <div className="space-y-3">
          <CheckList checks={dest.checks} />
          <NotVerified items={dest.assessment.not_verified} />
        </div>
      </Section>

      <Section variant="plain" title="Why it has this classification" description="Re-evaluated now with the current rules.">
        <ReasonList reasons={dest.assessment.reasons} />
      </Section>

      {canManage && (
        <Section title="Pin a classification" description="Use this when you have decided about this exact destination.">
          <ClassifyDestinationForm key={`${dest.id}:${dest.classification}`} dest={dest} />
        </Section>
      )}

      <Section variant="plain" title={`Calls to this destination (${formatNumber(dest.invocations_total)})`}>
        {decisions.length > 0 && (
          <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-fg-muted">
            <span className="flex flex-wrap items-center gap-1.5">
              Decisions:
              {decisions.map(([d, n]) => (
                <span key={d} className="inline-flex items-center gap-1">
                  {d === "none" ? <Badge>Not decided</Badge> : <DecisionBadge decision={d} />}
                  <span className="num text-fg">{n}</span>
                </span>
              ))}
            </span>
            <span className="flex flex-wrap items-center gap-1.5">
              Enforcement:
              {enforcement.map(([m, n]) => (
                <span key={m} className="inline-flex items-center gap-1">
                  <EnforcementBadge mode={m} />
                  <span className="num text-fg">{n}</span>
                </span>
              ))}
            </span>
          </div>
        )}
        {dest.invocations.length === 0 ? (
          <p className="text-xs text-fg-muted">No tool calls are stored for this destination (they may have been removed by retention).</p>
        ) : (
          <ul className="divide-y divide-border/70 rounded-md border border-border">
            {dest.invocations.map((inv) => (
              <li key={inv.id} className="space-y-1 px-3 py-2 text-[13px]">
                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                  <EntityLink type="tool_invocation" id={inv.id} label={inv.tool_name} sessionId={inv.session_id} />
                  <EntityLink type="agent" id={inv.agent_id} label={inv.agent_name} />
                  <span className="ml-auto flex items-center gap-1.5">
                    {inv.is_simulation && <SimulationBadge />}
                    {inv.sensitive_data_detected && <Badge tone="high">Sensitive data</Badge>}
                    {inv.decision ? <DecisionBadge decision={inv.decision} /> : <Badge>Not decided</Badge>}
                    <EnforcementBadge mode={inv.enforcement} />
                    <StatusBadge status={inv.status} />
                    <span className="w-20 text-right text-2xs text-fg-faint" title={formatDateTime(inv.requested_at)}>
                      {timeAgo(inv.requested_at)}
                    </span>
                  </span>
                </div>
                {inv.decision_explanation && <p className="line-clamp-2 text-xs text-fg-muted">{inv.decision_explanation}</p>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {dest.findings.length > 0 && (
        <Section variant="plain" title="Findings involving this destination">
          <ul className="divide-y divide-border/70 rounded-md border border-border">
            {dest.findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]">
                <SeverityBadge severity={f.severity} />
                <span className="min-w-0 flex-1">
                  <EntityLink type="finding" id={f.id} label={f.title} showIcon={false} />
                </span>
                {f.is_simulation && <SimulationBadge />}
                <StatusBadge status={f.status} />
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section variant="plain" title="Details">
        <KeyValue
          items={[
            {
              label: "Identifier",
              value: (
                <span className="inline-flex items-center gap-1">
                  <span className="break-all font-mono text-xs">{dest.identifier}</span>
                  <CopyButton value={dest.identifier} label="Copy identifier" />
                </span>
              ),
            },
            { label: "Kind", value: DESTINATION_KIND_LABELS[dest.kind] ?? dest.kind },
            { label: "Calls not stopped", value: formatNumber(dest.transfer_count) },
            { label: "Calls blocked (enforced)", value: formatNumber(dest.blocked_count) },
            { label: "Not stopped, with sensitive data", value: formatNumber(dest.sensitive_transfer_count) },
            { label: "First seen", value: formatDateTime(dest.first_seen_at) },
            { label: "Last seen", value: formatDateTime(dest.last_seen_at) },
            { label: "Destination id", value: <span className="font-mono text-xs">{dest.id}</span> },
          ]}
        />
      </Section>

      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title="Remove the pinned classification?"
        description={`Deletes the rule “${dest.trust_rule_name ?? "Destination override"}”. The destination is then classified by the remaining rules and checks.`}
        confirmLabel="Remove pin"
        destructive
        onConfirm={async () => {
          if (!dest.override_rule_id) return;
          const result = await removeRule.mutateAsync(dest.override_rule_id);
          toast.success("Pin removed", reassessMessage(result.reassessment));
        }}
      >
        <p>Policies that depend on this destination's classification use the new classification from the next tool call. The deletion is audited.</p>
      </ConfirmDialog>
    </div>
  );
}
