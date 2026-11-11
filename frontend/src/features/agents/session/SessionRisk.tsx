import { useState } from "react";
import { ChevronRight, KeyRound, Radio, ShieldQuestion } from "lucide-react";
import { Badge, Mono, TrustBadge } from "@/components/ui";
import { EntityLink, Section } from "@/components/data";
import { cn } from "@/lib/format";
import type { RiskEvidence, SessionDetail, TrifectaCondition, TrifectaKey } from "../types";

const ICONS: Record<TrifectaKey, typeof KeyRound> = { sensitive_access: KeyRound, untrusted_exposure: ShieldQuestion, outbound_channel: Radio };
const EVIDENCE_PREVIEW = 4;

function EvidenceRow({ ev, sessionId }: { ev: RiskEvidence; sessionId: string }) {
  const link =
    ev.type === "tool" ? (
      <span className="inline-flex items-center gap-1">
        <Mono className="text-fg">{ev.id}</Mono>
        <span className="text-2xs text-fg-faint">declared capability</span>
      </span>
    ) : (
      <EntityLink type={ev.type} id={ev.id} label={ev.label} sessionId={ev.session_id ?? sessionId} />
    );
  return (
    <li className="space-y-0.5">
      <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-xs">
        {link}
        {ev.trust_level && <TrustBadge level={ev.trust_level} />}
      </div>
      <p className="text-2xs text-fg-muted">{ev.detail}</p>
    </li>
  );
}

export function EvidenceItems({ evidence, sessionId, emptyLabel }: { evidence: RiskEvidence[]; sessionId: string; emptyLabel: string }) {
  const [all, setAll] = useState(false);
  if (evidence.length === 0) return <p className="text-2xs text-fg-faint">{emptyLabel}</p>;
  const shown = all ? evidence : evidence.slice(0, EVIDENCE_PREVIEW);
  return (
    <div>
      <ul className="space-y-2">
        {shown.map((ev, i) => (
          <EvidenceRow key={`${ev.type}:${ev.id}:${i}`} ev={ev} sessionId={sessionId} />
        ))}
      </ul>
      {evidence.length > EVIDENCE_PREVIEW && (
        <button type="button" onClick={() => setAll((v) => !v)} className="mt-2 text-2xs text-accent hover:underline">
          {all ? "Show fewer" : `Show all ${evidence.length}`}
        </button>
      )}
    </div>
  );
}

function ConditionCard({ c, sessionId, trifecta }: { c: TrifectaCondition; sessionId: string; trifecta: boolean }) {
  const Icon = ICONS[c.key] ?? ShieldQuestion;
  return (
    <div className={cn("rounded-md border p-3", c.active ? (trifecta ? "border-sev-critical/35 bg-sev-critical/[0.05]" : "border-sev-medium/35 bg-sev-medium/[0.05]") : "border-border")}>
      <div className="flex items-center gap-2">
        <Icon className={cn("h-4 w-4 shrink-0", c.active ? (trifecta ? "text-sev-critical" : "text-sev-medium") : "text-fg-faint")} aria-hidden />
        <span className="text-[13px] font-medium text-fg">{c.label}</span>
        <Badge tone={c.active ? (trifecta ? "critical" : "medium") : "neutral"} className="ml-auto">
          {c.active ? "Present" : "Not observed"}
        </Badge>
      </div>
      <p className="mt-1 text-xs text-fg-muted">{c.description}</p>
      <div className="mt-3 border-t border-border/70 pt-2.5">
        <EvidenceItems evidence={c.evidence} sessionId={sessionId} emptyLabel="No evidence recorded for this condition." />
      </div>
    </div>
  );
}

/** The three lethal-trifecta conditions with the records that established each one. */
export function TrifectaPanel({ session }: { session: SessionDetail }) {
  const { risk } = session;
  const present = risk.conditions.filter((c) => c.active).length;
  return (
    <Section
      title={
        <span className="inline-flex items-center gap-2">
          Lethal trifecta
          <Badge tone={risk.trifecta ? "critical" : present ? "medium" : "neutral"}>{risk.trifecta ? "All three conditions present" : `${present} of 3 conditions`}</Badge>
        </span>
      }
      description={risk.note}
    >
      <p className="mb-3 text-[13px] text-fg">{risk.summary}</p>
      <div className="grid gap-3 md:grid-cols-3">
        {risk.conditions.map((c) => (
          <ConditionCard key={c.key} c={c} sessionId={session.id} trifecta={risk.trifecta} />
        ))}
      </div>
    </Section>
  );
}

/** Every point of the risk score comes from a named factor with its own explanation and evidence. */
export function RiskFactors({ session }: { session: SessionDetail }) {
  const factors = [...session.risk.factors].sort((a, b) => b.weight - a.weight);
  const sum = factors.reduce((total, f) => total + f.weight, 0);
  const description =
    sum > session.risk.score
      ? `Factors add up to ${sum} points; the score is capped at 100. Expand a factor for its evidence.`
      : "Each factor's points, explanation and evidence, as computed by the risk engine.";
  return (
    <Section title={`Why the risk score is ${session.risk.score}`} description={description} flush>
      {factors.length === 0 ? (
        <p className="px-4 py-4 text-xs text-fg-faint">No risk factors recorded.</p>
      ) : (
        <ul className="divide-y divide-border/70">
          {factors.map((f) => (
            <li key={f.key} className="px-4 py-2.5">
              <details className="group">
                <summary className="flex cursor-pointer list-none items-start gap-2 [&::-webkit-details-marker]:hidden">
                  <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-faint transition-transform group-open:rotate-90" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <span className="text-[13px] font-medium text-fg">{f.label}</span>
                      <span className="num ml-auto font-mono text-xs text-fg-muted">+{f.weight}</span>
                    </span>
                    <span className="mt-0.5 block text-xs text-fg-muted">{f.explanation}</span>
                  </span>
                </summary>
                <div className="ml-5 mt-2">
                  <EvidenceItems evidence={f.evidence} sessionId={session.id} emptyLabel="No individual records attached." />
                </div>
              </details>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
