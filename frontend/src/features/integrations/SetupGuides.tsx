import { Link } from "react-router-dom";
import { CheckCircle2, ExternalLink, Info } from "lucide-react";
import { CodeBlock, CopyButton, Section } from "@/components/data";
import { Badge, ErrorState, LoadingRows } from "@/components/ui";
import { cn } from "@/lib/format";
import { useSetupGuide } from "./api";
import { InlineCode } from "./InlineCode";
import type { CatalogEntry, SetupGuide } from "./types";

function GuideNav({ entries, selected, onSelect }: { entries: CatalogEntry[]; selected: string; onSelect: (kind: string) => void }) {
  const groups: Array<{ label: string; items: CatalogEntry[] }> = [
    { label: "Supported", items: entries.filter((e) => e.status === "supported") },
    { label: "Planned · interim path", items: entries.filter((e) => e.status === "planned" && e.interim_kind) },
  ];
  return (
    <nav aria-label="Setup guides" className="space-y-4">
      {groups.map((group) =>
        group.items.length ? (
          <div key={group.label}>
            <div className="label-caps mb-1.5 px-2">{group.label}</div>
            <ul className="flex flex-wrap gap-1 lg:flex-col">
              {group.items.map((entry) => {
                const active = entry.kind === selected;
                return (
                  <li key={entry.kind}>
                    <button
                      type="button"
                      onClick={() => onSelect(entry.kind)}
                      aria-current={active ? "true" : undefined}
                      className={cn(
                        "flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-[13px] transition-colors",
                        active ? "bg-accent/10 text-fg" : "text-fg-muted hover:bg-surface-2 hover:text-fg",
                      )}
                    >
                      <span className="truncate">{entry.name}</span>
                      {entry.health === "connected" && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok" aria-label="connected" />}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null,
      )}
    </nav>
  );
}

function GuideBody({ guide }: { guide: SetupGuide }) {
  return (
    <div className="min-w-0 space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="flex flex-wrap items-center gap-2 text-[15px] font-semibold text-fg">
            {guide.name}
            {guide.status === "planned" ? <Badge tone="neutral">Planned</Badge> : <Badge tone="ok">Supported</Badge>}
          </h3>
          {guide.status === "planned" && guide.interim_kind && (
            <p className="mt-1 text-xs text-fg-muted">
              Interim path through the <span className="font-mono">{guide.interim_kind}</span> integration — not a native {guide.name} integration.
            </p>
          )}
        </div>
        <div className="min-w-0 rounded border border-border bg-surface-2/60 px-3 py-2">
          <div className="label-caps">Server URL</div>
          <div className="mt-0.5 flex items-center gap-1">
            <span className="truncate font-mono text-xs text-fg">{guide.server_url}</span>
            <CopyButton size="xs" value={guide.server_url} label="Copy server URL" />
          </div>
        </div>
      </div>
      <p className="flex gap-2 text-xs text-fg-muted">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
        {guide.server_url_note}
      </p>

      <div>
        <h4 className="label-caps mb-2">API key scopes</h4>
        <ul className="divide-y divide-border rounded border border-border">
          {guide.api_key_scopes.map((s) => (
            <li key={s.scope} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2 text-xs">
              <span className="w-14 font-mono text-fg">{s.scope}</span>
              <Badge tone={s.required ? "accent" : "neutral"}>{s.required ? "Required" : "Optional"}</Badge>
              <span className="min-w-0 flex-1 text-fg-muted">{s.purpose}</span>
            </li>
          ))}
        </ul>
      </div>

      <ol className="space-y-5" aria-label={`${guide.name} setup steps`}>
        {guide.steps.map((step, i) => (
          <li key={step.title} className="grid grid-cols-[24px_1fr] gap-3">
            <span className="num flex h-6 w-6 items-center justify-center rounded-full border border-border-strong bg-surface-2 text-2xs font-semibold text-fg-muted" aria-hidden>
              {i + 1}
            </span>
            <div className="min-w-0 space-y-2">
              <div className="text-[13px] font-medium text-fg">{step.title}</div>
              <p className="text-xs leading-5 text-fg-muted">
                <InlineCode text={step.description} />
              </p>
              {step.link && (
                <Link to={step.link.href} className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
                  {step.link.label}
                  <ExternalLink className="h-3 w-3" aria-hidden />
                </Link>
              )}
              {step.commands.map((cmd, j) => (
                <CodeBlock key={j} code={cmd.code} language={cmd.language} title={cmd.title ?? undefined} maxHeight={260} />
              ))}
            </div>
          </li>
        ))}
      </ol>

      <div className="flex gap-2 rounded border border-ok/30 bg-ok/5 px-3 py-2.5 text-xs text-fg">
        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ok" aria-hidden />
        <div>
          <div className="font-medium">How to know it worked</div>
          <p className="mt-0.5 text-fg-muted">{guide.verification}</p>
        </div>
      </div>

      {guide.notes.length > 0 && (
        <div>
          <h4 className="label-caps mb-2">Keep in mind</h4>
          <ul className="list-disc space-y-1.5 pl-4 text-xs leading-5 text-fg-muted marker:text-fg-faint">
            {guide.notes.map((note) => (
              <li key={note}>
                <InlineCode text={note} />
              </li>
            ))}
          </ul>
        </div>
      )}
      {guide.docs_path && (
        <p className="text-2xs text-fg-faint">
          Full reference in the repository: <span className="font-mono">{guide.docs_path}</span>
        </p>
      )}
    </div>
  );
}

export function SetupGuides({ entries, selected, onSelect }: { entries: CatalogEntry[]; selected: string; onSelect: (kind: string) => void }) {
  const guide = useSetupGuide(selected);
  return (
    <Section
      id="setup"
      title="Setup guides"
      description="Commands are filled in with this server's address. API keys are never shown here — create one in Settings and paste it where the command says ctxk_your_key."
    >
      <div className="grid gap-6 lg:grid-cols-[200px_1fr]">
        <GuideNav entries={entries} selected={selected} onSelect={onSelect} />
        <div className="min-w-0" aria-live="polite">
          {guide.isLoading ? (
            <LoadingRows rows={6} />
          ) : guide.isError || !guide.data ? (
            <ErrorState error={guide.error} onRetry={() => void guide.refetch()} />
          ) : (
            <GuideBody guide={guide.data} />
          )}
        </div>
      </div>
    </Section>
  );
}
