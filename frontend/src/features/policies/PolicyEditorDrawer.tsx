/** Policy editor side panel: definition (visual builder), JSON, dry-run test and recorded matches. */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Lock, Trash2 } from "lucide-react";
import { Badge, Button, DecisionBadge, Drawer, ErrorState, LoadingRows, TabPanel, Tabs, useToast } from "@/components/ui";
import { ConfirmDialog } from "@/components/data";
import { useDebounce } from "@/hooks";
import { useAuth } from "@/features/auth/AuthProvider";
import { ApiError } from "@/lib/api";
import { useConditionValidation, useCreatePolicy, useDeletePolicy, usePolicy, usePolicyFields, usePolicyOperators, useUpdatePolicy, validationErrors } from "./api";
import { DefinitionForm, type ValidationState } from "./DefinitionForm";
import { VERSIONED_FIELDS, draftFromPolicy, draftPatch, draftToInput, effectiveRestrictions, emptyDraft, isDirty, stopsEnforcingDeny, type PolicyDraft } from "./draft";
import { JsonConditionsEditor, parseConditionsText, prettyJson } from "./JsonConditionsEditor";
import { PolicyMatchesTab } from "./PolicyMatchesTab";
import { PolicyTestPanel } from "./PolicyTestPanel";
import type { Policy } from "./types";

type Tab = "definition" | "json" | "test" | "matches";

export function PolicyEditorDrawer({ policyId, onClose, onCreated }: { policyId: string; onClose: () => void; onCreated: (id: string) => void }) {
  const isNew = policyId === "new";
  const policy = usePolicy(isNew ? null : policyId);
  const [open, setOpen] = useState(true);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  // Read by the drawer's close handler, which Radix calls outside the editor's render.
  const dirtyRef = useRef(false);
  const onDirtyChange = useCallback((dirty: boolean) => {
    dirtyRef.current = dirty;
  }, []);

  const requestClose = (dirty: boolean) => (dirty ? setConfirmDiscard(true) : setOpen(false));
  useEffect(() => {
    if (!open) onClose();
  }, [open, onClose]);

  const title = isNew ? "New policy" : (policy.data?.name ?? "Policy");
  let body;
  if (!isNew && policy.isLoading) body = <LoadingRows rows={8} />;
  else if (!isNew && policy.error)
    body = (
      <ErrorState
        error={policy.error instanceof ApiError && policy.error.status === 404 ? new Error("This policy does not exist or was deleted.") : policy.error}
        onRetry={() => void policy.refetch()}
      />
    );
  else
    body = (
      <PolicyEditor
        key={policyId}
        policy={isNew ? null : (policy.data ?? null)}
        onRequestClose={requestClose}
        onDirtyChange={onDirtyChange}
        onCreated={onCreated}
        onDeleted={() => setOpen(false)}
      />
    );

  return (
    <>
      <Drawer
        open={open}
        onOpenChange={(next) => (next ? setOpen(true) : requestClose(dirtyRef.current))}
        title={title}
        subtitle={isNew ? "Define which tool calls this policy matches and what ContextOS decides." : policy.data ? <PolicySubtitle policy={policy.data} /> : undefined}
        width="w-[min(860px,100vw)]"
      >
        {body}
      </Drawer>
      <ConfirmDialog
        open={confirmDiscard}
        onOpenChange={setConfirmDiscard}
        title="Discard unsaved changes?"
        description="Your edits to this policy have not been saved."
        confirmLabel="Discard"
        destructive
        onConfirm={() => {
          dirtyRef.current = false;
          setOpen(false);
        }}
      />
    </>
  );
}

function PolicySubtitle({ policy }: { policy: Policy }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <DecisionBadge decision={policy.outcome} />
      <Badge tone={policy.mode === "enforce" ? "ok" : "neutral"}>{policy.mode === "enforce" ? "Enforce" : "Monitor"}</Badge>
      {!policy.enabled && <Badge tone="neutral">Disabled</Badge>}
      {policy.is_builtin && <Badge tone="accent" title="Seeded built-in policy. It can be edited or disabled, not deleted.">Built-in</Badge>}
      <span className="font-mono text-2xs text-fg-faint">v{policy.version}</span>
    </span>
  );
}

function PolicyEditor({
  policy,
  onRequestClose,
  onDirtyChange,
  onCreated,
  onDeleted,
}: {
  policy: Policy | null;
  onRequestClose: (dirty: boolean) => void;
  onDirtyChange: (dirty: boolean) => void;
  onCreated: (id: string) => void;
  onDeleted: () => void;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const canManage = can("policy:manage");
  const fields = usePolicyFields();
  const operators = usePolicyOperators();
  const create = useCreatePolicy();
  const update = useUpdatePolicy();
  const remove = useDeletePolicy();

  const [baseline, setBaseline] = useState<Policy | null>(policy);
  const [draft, setDraft] = useState<PolicyDraft>(() => (policy ? draftFromPolicy(policy) : emptyDraft()));
  const [jsonText, setJsonText] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("definition");
  const [testDecision, setTestDecision] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | "delete" | "stop-deny">(null);

  const dirty = isDirty(baseline, draft) || jsonText !== null;
  useEffect(() => {
    onDirtyChange(dirty);
    return () => onDirtyChange(false);
  }, [dirty, onDirtyChange]);

  // A live update (another user, or a list toggle) refreshed the policy: adopt it if nothing is edited.
  const changedElsewhere = !!policy && !!baseline && policy.updated_at !== baseline.updated_at;
  useEffect(() => {
    if (changedElsewhere && !dirty && policy) {
      setBaseline(policy);
      setDraft(draftFromPolicy(policy));
    }
  }, [changedElsewhere, dirty, policy]);

  const syntaxError = jsonText !== null ? parseConditionsText(jsonText).error : null;
  const validationBody = useMemo(
    () => ({ conditions: draft.conditions, outcome: draft.outcome, restrictions: effectiveRestrictions(draft) }),
    [draft],
  );
  const debouncedBody = useDebounce(validationBody, 300);
  const validationQuery = useConditionValidation(syntaxError ? null : debouncedBody);
  const validation: ValidationState = {
    data: validationQuery.data,
    loading: validationQuery.isFetching || debouncedBody !== validationBody,
    error: validationQuery.error,
    syntaxError,
  };
  const valid = !syntaxError && validation.data?.valid === true && !validation.loading;

  const change = useCallback((patch: Partial<PolicyDraft>) => {
    setDraft((d) => ({ ...d, ...patch }));
    if ("conditions" in patch) setJsonText(null);
  }, []);
  const editJson = (text: string) => {
    setJsonText(text);
    const parsed = parseConditionsText(text);
    if (parsed.error === null) setDraft((d) => ({ ...d, conditions: parsed.value }));
  };

  const patch = baseline ? draftPatch(baseline, draft) : null;
  const bumpsVersion = !!patch && VERSIONED_FIELDS.some((f) => f in patch);
  const nameMissing = !draft.name.trim();
  const saveBlocked = !canManage
    ? "Editing policies requires the policy:manage permission."
    : nameMissing
      ? "Give the policy a name."
      : syntaxError
        ? "Fix the JSON syntax error first."
        : validation.loading
          ? "Checking…"
          : !valid
            ? "Fix the validation errors first."
            : null;
  const saveError = create.error ?? update.error;
  const serverErrors = validationErrors(saveError);

  const save = async () => {
    if (saveBlocked || !dirty) return;
    if (!baseline) {
      const created = await create.mutateAsync(draftToInput(draft));
      toast.success("Policy created", created.mode === "monitor" ? "Monitor mode: matches are recorded only." : "Enforce mode: decisions are returned to integrations.");
      onDirtyChange(false);
      onCreated(created.id);
      return;
    }
    if (!patch || !Object.keys(patch).length) return;
    const saved = await update.mutateAsync({ id: baseline.id, patch });
    setBaseline(saved);
    setDraft(draftFromPolicy(saved));
    setJsonText(null);
    toast.success("Policy saved", `Now at version ${saved.version}.`);
  };
  const onSave = () => {
    if (baseline && patch && stopsEnforcingDeny(baseline, patch)) setConfirm("stop-deny");
    else void save().catch(() => undefined);
  };

  if (fields.isLoading || operators.isLoading) return <LoadingRows rows={8} />;
  if (fields.error || operators.error) {
    const retry = () => {
      void fields.refetch();
      void operators.refetch();
    };
    return <ErrorState error={fields.error ?? operators.error} onRetry={retry} />;
  }
  const catalog = fields.data ?? [];
  const ops = operators.data ?? [];
  const readOnly = !canManage;

  const tabs = [
    { value: "definition", label: "Definition" },
    { value: "json", label: "JSON" },
    { value: "test", label: "Test" },
    ...(baseline ? [{ value: "matches", label: "Recorded matches", count: baseline.stats ? baseline.stats.matched + baseline.stats.monitor_matched : undefined }] : []),
  ];

  return (
    <div className="flex h-full flex-col">
      {readOnly && (
        <div className="flex items-center gap-2 border-b border-border bg-surface-2/60 px-5 py-2 text-xs text-fg-muted">
          <Lock className="h-3.5 w-3.5" aria-hidden /> Read only — editing policies requires the policy:manage permission. You can still run tests.
        </div>
      )}
      {changedElsewhere && dirty && policy && (
        <div role="status" className="flex flex-wrap items-center gap-2 border-b border-warn/30 bg-warn/10 px-5 py-2 text-xs text-fg-muted">
          This policy was changed elsewhere (now v{policy.version}). Saving will overwrite those changes with yours.
          <Button
            size="xs"
            variant="outline"
            onClick={() => {
              setBaseline(policy);
              setDraft(draftFromPolicy(policy));
              setJsonText(null);
            }}
          >
            Load latest
          </Button>
        </div>
      )}
      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} tabs={tabs} className="flex min-h-0 flex-1 flex-col [&>[role=tablist]]:px-5">
        <div className="min-h-0 flex-1 overflow-y-auto">
          <TabPanel value="definition">
            <DefinitionForm draft={draft} onChange={change} catalog={catalog} operators={ops} validation={validation} readOnly={readOnly} onOpenJson={() => setTab("json")} />
          </TabPanel>
          <TabPanel value="json" className="space-y-4 p-5">
            <JsonConditionsEditor text={jsonText ?? prettyJson(draft.conditions)} onTextChange={editJson} syntaxError={syntaxError} readOnly={readOnly} />
            <ValidationSummary validation={validation} />
          </TabPanel>
          <TabPanel value="test">
            <PolicyTestPanel policyId={baseline?.id ?? null} draft={draft} blockedReason={syntaxError ? "Fix the JSON syntax error first." : validation.data && !validation.data.valid ? "Fix the validation errors before testing." : null} preselectedDecisionId={testDecision} />
          </TabPanel>
          {baseline && (
            <TabPanel value="matches">
              <PolicyMatchesTab
                policyId={baseline.id}
                onTest={(id) => {
                  setTestDecision(id);
                  setTab("test");
                }}
              />
            </TabPanel>
          )}
        </div>
      </Tabs>

      <footer className="flex flex-wrap items-center gap-2 border-t border-border bg-surface px-5 py-3">
        {baseline && !baseline.is_builtin && canManage && (
          <Button size="sm" variant="ghost" className="text-danger hover:text-danger" icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />} onClick={() => setConfirm("delete")}>
            Delete
          </Button>
        )}
        <div className="min-w-0 flex-1 text-xs text-fg-muted" aria-live="polite">
          {saveError ? (
            <span className="text-danger">
              {saveError instanceof Error ? saveError.message : "Save failed"}
              {serverErrors.length > 0 && `: ${serverErrors.join("; ")}`}
            </span>
          ) : dirty ? (
            (saveBlocked ?? (baseline ? (bumpsVersion ? `Unsaved changes · saving creates v${baseline.version + 1}` : "Unsaved changes") : "New policy · not saved yet"))
          ) : baseline ? (
            `Saved · v${baseline.version}`
          ) : null}
        </div>
        <Button size="sm" variant="ghost" onClick={() => onRequestClose(dirty)}>
          {dirty ? "Cancel" : "Close"}
        </Button>
        {canManage && (
          <Button size="sm" variant="primary" disabled={!dirty || !!saveBlocked} loading={create.isPending || update.isPending} onClick={onSave}>
            {baseline ? "Save changes" : "Create policy"}
          </Button>
        )}
      </footer>

      {baseline && (
        <>
          <ConfirmDialog
            open={confirm === "delete"}
            onOpenChange={(o) => !o && setConfirm(null)}
            title={`Delete “${baseline.name}”?`}
            description="The policy stops being evaluated immediately. Recorded decisions keep its name and version."
            confirmLabel="Delete policy"
            destructive
            requireText={baseline.name}
            onConfirm={async () => {
              await remove.mutateAsync(baseline.id);
              onDirtyChange(false);
              toast.success("Policy deleted");
              onDeleted();
            }}
          />
          <ConfirmDialog
            open={confirm === "stop-deny"}
            onOpenChange={(o) => !o && setConfirm(null)}
            title="Stop enforcing this DENY policy?"
            description="Tool calls it blocks today will no longer be denied. Matches will at most be recorded."
            confirmLabel="Save anyway"
            destructive
            onConfirm={save}
          >
            <p>Integrations that enforce decisions (Claude Code hook, MCP gateway, SDK guard) will let these calls run.</p>
          </ConfirmDialog>
        </>
      )}
    </div>
  );
}

function ValidationSummary({ validation }: { validation: ValidationState }) {
  if (validation.syntaxError) return null;
  if (!validation.data) return null;
  if (validation.data.valid) return <p className="text-xs text-ok">Valid · {validation.data.explanation}</p>;
  return (
    <ul className="space-y-1 rounded-md border border-danger/30 bg-danger/10 px-3 py-2" aria-label="Validation errors">
      {validation.data.errors.map((e) => (
        <li key={e} className="font-mono text-2xs text-danger">
          {e}
        </li>
      ))}
    </ul>
  );
}
