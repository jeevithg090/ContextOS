/** Tester tab: enter any identifier and see exactly how ContextOS would classify it, and why. */
import { useId, useState } from "react";
import { FlaskConical } from "lucide-react";
import { Button, EmptyState, Input, Select } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { errorMessage, useDestinationVerify, useRuleTest } from "./api";
import { AssessmentView, ExistingRecordView } from "./AssessmentView";
import { DESTINATION_KIND_LABELS, SOURCE_TYPE_LABELS } from "./meta";
import { SOURCE_TYPES, type Assessment, type DestinationKind, type ExistingRecord, type Scope, type SourceType } from "./types";

const KINDS: DestinationKind[] = ["unknown", "domain", "ip", "email", "service", "agent"];
const EXAMPLES: Record<Scope, string[]> = {
  source: ["https://docs.python.org/3/library/os.html", "github.com/acme/billing", "/srv/app/README.md"],
  destination: ["https://abc.webhook.site/x", "169.254.169.254", "api.anthropic.com"],
};

export function TesterTab() {
  const [scope, setScope] = useState<Scope>("source");
  const [identifier, setIdentifier] = useState("");
  const [sourceType, setSourceType] = useState<SourceType>("web");
  const [kind, setKind] = useState<DestinationKind>("unknown");
  const sourceTest = useRuleTest();
  const destinationTest = useDestinationVerify();
  const inputId = useId();
  const active = scope === "source" ? sourceTest : destinationTest;
  const result: { assessment: Assessment; existing: ExistingRecord | null } | undefined = active.data;

  const run = () => {
    const value = identifier.trim();
    if (!value) return;
    if (scope === "source") sourceTest.mutate({ applies_to: "source", source_type: sourceType, identifier: value });
    else destinationTest.mutate({ kind, identifier: value });
  };

  return (
    <div className="space-y-4">
      <form
        className="panel space-y-3 p-4"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SegmentedControl<Scope>
            aria-label="What to test"
            value={scope}
            onChange={(v) => {
              setScope(v);
              sourceTest.reset();
              destinationTest.reset();
            }}
            options={[
              { value: "source", label: "Source (content an agent reads)" },
              { value: "destination", label: "Destination (where data is sent)" },
            ]}
          />
          <span className="text-2xs text-fg-faint">Dry run with the saved rules — nothing is recorded.</span>
        </div>
        <div className="flex flex-wrap gap-2">
          <label htmlFor={inputId} className="sr-only">
            Identifier
          </label>
          <Input
            id={inputId}
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            placeholder={scope === "source" ? "URL, file path, repository or MCP server" : "Host, URL, IP address, email or service"}
            className="min-w-[260px] flex-1 font-mono text-xs"
            spellCheck={false}
            autoComplete="off"
          />
          {scope === "source" ? (
            <Select aria-label="Source type" value={sourceType} onChange={(e) => setSourceType(e.target.value as SourceType)} className="!w-48">
              {SOURCE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {SOURCE_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
          ) : (
            <Select aria-label="Destination kind" value={kind} onChange={(e) => setKind(e.target.value as DestinationKind)} className="!w-40">
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {DESTINATION_KIND_LABELS[k]}
                </option>
              ))}
            </Select>
          )}
          <Button type="submit" variant="primary" size="md" loading={active.isPending} disabled={!identifier.trim()}>
            Assess
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-2xs text-fg-faint">
          Try:
          {EXAMPLES[scope].map((ex) => (
            <button key={ex} type="button" className="rounded border border-border px-1.5 py-0.5 font-mono text-fg-muted hover:bg-surface-2 hover:text-fg" onClick={() => setIdentifier(ex)}>
              {ex}
            </button>
          ))}
        </div>
      </form>

      {active.error ? (
        <p role="alert" className="panel px-4 py-3 text-xs text-danger">
          {errorMessage(active.error)}
        </p>
      ) : result ? (
        <div className="panel space-y-4 p-4" aria-live="polite">
          {result.existing && <ExistingRecordView existing={result.existing} />}
          <AssessmentView assessment={result.assessment} />
          {scope === "source" && (
            <p className="text-2xs text-fg-faint">
              This is the classification from rules alone. A stored source can be lower: findings recorded for it, a manual classification, or what
              produced it (sub-agent and MCP tool output) are applied on top.
            </p>
          )}
        </div>
      ) : (
        <div className="panel">
          <EmptyState
            icon={<FlaskConical className="h-5 w-5" aria-hidden />}
            title="Test how something would be classified"
            description="Enter a source or destination to see its trust level, what it may do, which rule decides and every check performed."
          />
        </div>
      )}
    </div>
  );
}
