/** Live dry run inside the rule editor: how an example identifier is classified with this draft. */
import { useId, useMemo, useState } from "react";
import { FlaskConical } from "lucide-react";
import { Badge, Input, Select, Spinner, TrustBadge } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { useDebounce } from "@/hooks";
import { useRuleTestQuery, errorMessage } from "./api";
import { MatchingRules } from "./AssessmentView";
import { CapabilityChips } from "./components";
import { DESTINATION_KIND_LABELS, SOURCE_TYPE_LABELS } from "./meta";
import { draftToInput, type RuleDraft } from "./ruleDraft";
import { SOURCE_TYPES, type DestinationKind, type RuleTestRequest, type Scope, type SourceType } from "./types";

const KINDS: DestinationKind[] = ["unknown", "domain", "ip", "email", "service", "agent"];

export function RuleLiveTest({ draft, ruleId }: { draft: RuleDraft; ruleId: string | null }) {
  const [example, setExample] = useState("");
  const [scope, setScope] = useState<Scope>(draft.applies_to === "destination" ? "destination" : "source");
  const [sourceType, setSourceType] = useState<SourceType>("web");
  const [kind, setKind] = useState<DestinationKind>("unknown");
  const exampleId = useId();
  const effectiveScope: Scope = draft.applies_to === "both" ? scope : draft.applies_to;
  const effectiveType: SourceType = draft.source_type || sourceType;

  const requestJson = useMemo(() => {
    if (!example.trim() || !draft.pattern.trim() || !draft.name.trim()) return "";
    const body: RuleTestRequest = {
      applies_to: effectiveScope,
      source_type: effectiveType,
      kind,
      identifier: example.trim(),
      draft: draftToInput(draft),
      replace_rule_id: ruleId,
    };
    return JSON.stringify(body);
  }, [example, draft, effectiveScope, effectiveType, kind, ruleId]);
  const debounced = useDebounce(requestJson, 350);
  const body = useMemo(() => (debounced ? (JSON.parse(debounced) as RuleTestRequest) : null), [debounced]);
  const test = useRuleTestQuery(body);
  const result = body ? test.data : undefined;

  return (
    <section aria-labelledby={`${exampleId}-title`} className="space-y-2.5 rounded-md border border-border bg-surface-2/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id={`${exampleId}-title`} className="flex items-center gap-1.5 text-xs font-semibold text-fg">
          <FlaskConical className="h-3.5 w-3.5 text-fg-muted" aria-hidden /> Live test
          <span className="font-normal text-fg-faint">· dry run, nothing is saved</span>
        </h3>
        {draft.applies_to === "both" && (
          <SegmentedControl<Scope>
            aria-label="Test as"
            value={scope}
            onChange={setScope}
            options={[
              { value: "source", label: "Source" },
              { value: "destination", label: "Destination" },
            ]}
          />
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        <label htmlFor={exampleId} className="sr-only">
          Example identifier
        </label>
        <Input
          id={exampleId}
          value={example}
          onChange={(e) => setExample(e.target.value)}
          placeholder={effectiveScope === "source" ? "https://docs.acme.com/guide or github.com/acme/api" : "api.partner.com or ops@acme.com"}
          className="min-w-[220px] flex-1 font-mono text-xs"
        />
        {effectiveScope === "source" && !draft.source_type && (
          <Select aria-label="Source type" value={sourceType} onChange={(e) => setSourceType(e.target.value as SourceType)} className="!w-auto">
            {SOURCE_TYPES.map((t) => (
              <option key={t} value={t}>
                {SOURCE_TYPE_LABELS[t]}
              </option>
            ))}
          </Select>
        )}
        {effectiveScope === "destination" && (
          <Select aria-label="Destination kind" value={kind} onChange={(e) => setKind(e.target.value as DestinationKind)} className="!w-auto">
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {DESTINATION_KIND_LABELS[k]}
              </option>
            ))}
          </Select>
        )}
      </div>

      <div aria-live="polite">
        {!body ? (
          <p className="text-xs text-fg-faint">Enter an example identifier to see whether this rule matches it and what the result would be.</p>
        ) : test.isLoading ? (
          <Spinner />
        ) : test.error ? (
          <p className="text-xs text-danger">{errorMessage(test.error)}</p>
        ) : result ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              {result.draft_matches ? (
                result.draft_decides ? (
                  <Badge tone="ok">This rule matches and decides</Badge>
                ) : (
                  <Badge tone="warn">Matches, but another rule takes precedence</Badge>
                )
              ) : (
                <Badge tone="neutral">This rule does not match</Badge>
              )}
              <span className="text-fg-faint">Result:</span>
              <TrustBadge level={result.assessment.level} />
              {result.assessment.scope === "source" ? (
                <CapabilityChips capabilities={result.assessment.capabilities} />
              ) : (
                <Badge tone={result.assessment.capabilities.includes("send") ? "allow" : "neutral"}>
                  {result.assessment.capabilities.includes("send") ? "May send" : "Not approved for sending"}
                </Badge>
              )}
              {test.isFetching && <Spinner className="h-3 w-3" />}
            </div>
            <p className="font-mono text-2xs text-fg-faint" title="Canonical identifier the rule is compared with">
              compared as: {result.assessment.canonical_identifier || "—"}
            </p>
            {result.assessment.matching_rules.length > 0 && <MatchingRules assessment={result.assessment} />}
            {result.draft_errors.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-5 text-xs text-danger" aria-label="Problems that prevent saving">
                {result.draft_errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}
