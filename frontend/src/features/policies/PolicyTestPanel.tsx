/** Dry-run the draft (unsaved edits included) against a recorded decision or a custom input. */
import { useEffect, useId, useState } from "react";
import { Play } from "lucide-react";
import { Button, Field, Input, Textarea } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { cn } from "@/lib/format";
import { useDebounce } from "@/hooks";
import { usePolicyDecisions, useRecentDecisions, useTestPolicy, validationErrors } from "./api";
import { DecisionPicker } from "./DecisionPicker";
import { draftForTest, type PolicyDraft } from "./draft";
import { TestResultView } from "./TestResultView";

/** Starting point for a hand-written input: every EvaluationInput key, with neutral values. */
const INPUT_TEMPLATE = {
  agent: { name: "release-bot", environment: "production", labels: [], framework: "claude_code" },
  tool: { name: "Bash", category: "shell", provider: "claude_code", server: null, risk_level: "high" },
  arguments: { command: "ls -la" },
  resources: [],
  sensitive_resources: [],
  destination: {},
  secrets_in_arguments: [],
  session_secret_matches: [],
  session: { score: 0, level: "low", untrusted_exposure: false, sensitive_access: false, outbound_channel: false, trifecta: false },
  context: { lowest_trust: "TRUSTED", untrusted_item_count: 0, suspicious_source_ids: [], injection_detected: false, max_detection_severity: null },
  detection: { rule_ids: [], max_severity: null, categories: [] },
  integration: { kind: "claude_code", supports_enforcement: true },
};

type Scope = "policy" | "org";
type Source = "recorded" | "custom";
type RecordedList = "matched" | "recent";

export function PolicyTestPanel({
  policyId,
  draft,
  blockedReason,
  preselectedDecisionId,
}: {
  policyId: string | null;
  draft: PolicyDraft;
  /** Why the draft cannot be tested yet (invalid conditions, JSON syntax error), or null. */
  blockedReason: string | null;
  preselectedDecisionId: string | null;
}) {
  const sessionFieldId = useId();
  const jsonId = useId();
  const [scope, setScope] = useState<Scope>("policy");
  const [source, setSource] = useState<Source>("recorded");
  const [list, setList] = useState<RecordedList>(policyId ? "matched" : "recent");
  const [sessionFilter, setSessionFilter] = useState("");
  const [selected, setSelected] = useState<string | null>(preselectedDecisionId);
  const [customText, setCustomText] = useState(() => JSON.stringify(INPUT_TEMPLATE, null, 2));
  const debouncedSession = useDebounce(sessionFilter.trim(), 300);
  const test = useTestPolicy();

  useEffect(() => {
    if (preselectedDecisionId) {
      setSource("recorded");
      setSelected(preselectedDecisionId);
    }
  }, [preselectedDecisionId]);

  const matched = usePolicyDecisions(policyId && source === "recorded" && list === "matched" ? policyId : null, true);
  const recent = useRecentDecisions({ session_id: debouncedSession || undefined }, source === "recorded" && list === "recent");
  const active = list === "matched" ? matched : recent;

  let customInput: Record<string, unknown> | null = null;
  let customError: string | null = null;
  if (source === "custom") {
    try {
      const parsed: unknown = JSON.parse(customText);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) customError = "The input must be a JSON object";
      else customInput = parsed as Record<string, unknown>;
    } catch (err) {
      customError = err instanceof Error ? err.message : "Invalid JSON";
    }
  }

  const inputMissing = source === "recorded" ? (!selected ? "Pick a recorded decision to re-evaluate." : null) : customError;
  const disabledReason = blockedReason ?? inputMissing;

  const run = () => {
    if (disabledReason) return;
    test.mutate({
      policy: draftForTest(draft, policyId),
      with_org_policies: scope === "org",
      ...(source === "recorded" && selected ? { policy_decision_id: selected } : { input: customInput ?? {} }),
    });
  };

  const serverErrors = validationErrors(test.error);

  return (
    <div className="space-y-5 p-5">
      <p className="text-xs text-fg-muted">
        Runs the policy as currently edited, including unsaved changes, against an input. Nothing is saved or sent to any agent; the result is a
        simulation. Recorded decisions are re-evaluated against their stored, redacted input exactly as it was captured.
      </p>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <span className="block text-xs font-medium text-fg-muted">Evaluate</span>
          <SegmentedControl<Scope>
            aria-label="Policies to evaluate"
            value={scope}
            onChange={setScope}
            options={[
              { value: "policy", label: "This policy only" },
              { value: "org", label: "With all enabled policies" },
            ]}
          />
          <p className="text-2xs text-fg-faint">
            {scope === "policy" ? "Shows whether this policy alone matches." : "Shows what ContextOS would decide if this draft were saved."}
          </p>
        </div>
        <div className="space-y-1.5">
          <span className="block text-xs font-medium text-fg-muted">Input</span>
          <SegmentedControl<Source>
            aria-label="Test input"
            value={source}
            onChange={setSource}
            options={[
              { value: "recorded", label: "Recorded decision" },
              { value: "custom", label: "Custom JSON" },
            ]}
          />
        </div>
      </div>

      {source === "recorded" ? (
        <div className="space-y-2">
          <div className="flex flex-wrap items-end gap-3">
            <SegmentedControl<RecordedList>
              aria-label="Which decisions"
              value={list}
              onChange={setList}
              options={[
                { value: "matched", label: "Where this policy matched", disabled: !policyId },
                { value: "recent", label: "All recent decisions" },
              ]}
            />
            {list === "recent" && (
              <div className="flex items-center gap-1.5">
                <label htmlFor={sessionFieldId} className="text-xs text-fg-faint">
                  Session
                </label>
                <Input id={sessionFieldId} value={sessionFilter} onChange={(e) => setSessionFilter(e.target.value)} placeholder="asn_… (optional)" className="!h-7 !w-56 font-mono !text-xs" />
              </div>
            )}
          </div>
          <DecisionPicker
            label="Recorded decisions"
            items={active.data?.items}
            loading={active.isLoading}
            error={active.error}
            onRetry={() => void active.refetch()}
            selectedId={selected}
            onSelect={setSelected}
            emptyText={
              list === "matched"
                ? "This policy has not matched any recorded decision in the last 30 days."
                : debouncedSession
                  ? "No recorded decisions for this session."
                  : "No decisions recorded yet. Decisions appear once an integration asks ContextOS to decide a tool call."
            }
          />
        </div>
      ) : (
        <Field label="Evaluation input (JSON)" htmlFor={jsonId} error={customError ? `JSON: ${customError}` : null} hint="Same shape as a recorded input snapshot. Secrets in arguments are redacted before evaluation.">
          <Textarea id={jsonId} value={customText} spellCheck={false} onChange={(e) => setCustomText(e.target.value)} className={cn("!min-h-[260px] font-mono text-xs leading-5", customError && "border-danger/60")} />
        </Field>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" size="sm" icon={<Play className="h-3.5 w-3.5" aria-hidden />} loading={test.isPending} disabled={!!disabledReason} onClick={run}>
          Run simulation
        </Button>
        {disabledReason && <span className="text-xs text-fg-muted">{disabledReason}</span>}
      </div>

      {test.error && (
        <div role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
          {test.error instanceof Error ? test.error.message : "The simulation failed"}
          {serverErrors.length > 0 && (
            <ul className="mt-1 list-disc pl-4 font-mono text-2xs">
              {serverErrors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {test.data && !test.isPending && (
        <>
          <TestResultView result={test.data} policyId={policyId} />
          <Button
            size="xs"
            variant="ghost"
            onClick={() => {
              setCustomText(JSON.stringify(test.data.evaluated_input, null, 2));
              setSource("custom");
            }}
          >
            Edit this input as custom JSON
          </Button>
        </>
      )}
    </div>
  );
}
