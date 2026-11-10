/** How policies decide: the two modes, outcome precedence and the default when nothing matches. */
import { Eye, ShieldCheck } from "lucide-react";
import { DecisionBadge } from "@/components/ui";
import { useDefaultDecision } from "./api";

const PRECEDENCE = ["DENY", "REQUIRE_APPROVAL", "RESTRICT", "AUDIT", "ALLOW"] as const;

export function ModesBanner() {
  const defaultDecision = useDefaultDecision();
  return (
    <section aria-label="How policies decide" className="panel grid gap-px overflow-hidden bg-border md:grid-cols-[1fr_1fr_1.15fr]">
      <div className="bg-surface p-4">
        <div className="flex items-center gap-2 text-[13px] font-semibold text-fg">
          <ShieldCheck className="h-4 w-4 text-ok" aria-hidden /> Enforce
        </div>
        <p className="mt-1.5 text-xs leading-relaxed text-fg-muted">
          The decision is returned to the integration and enforced where the integration supports it: the Claude Code PreToolUse hook, the MCP
          gateway and the SDK <span className="font-mono">guard()</span>. Elsewhere the same decision is advisory or only observed.
        </p>
      </div>
      <div className="bg-surface p-4">
        <div className="flex items-center gap-2 text-[13px] font-semibold text-fg">
          <Eye className="h-4 w-4 text-fg-muted" aria-hidden /> Monitor
        </div>
        <p className="mt-1.5 text-xs leading-relaxed text-fg-muted">
          Recorded only — a dry run. Matches are stored with each decision so you can measure how often a policy would fire, but they never
          change what the agent is told.
        </p>
      </div>
      <div className="bg-surface p-4">
        <div className="text-[13px] font-semibold text-fg">When several policies match</div>
        <div className="mt-2 flex flex-wrap items-center gap-1">
          {PRECEDENCE.map((d, i) => (
            <span key={d} className="inline-flex items-center gap-1">
              {i > 0 && <span className="text-2xs text-fg-faint" aria-hidden>›</span>}
              <DecisionBadge decision={d} />
            </span>
          ))}
        </div>
        <p className="mt-2 text-xs leading-relaxed text-fg-muted">
          The strongest enforce-mode outcome wins; ties go to the higher priority. If nothing matches, the default applies:{" "}
          {defaultDecision.data ? <DecisionBadge decision={defaultDecision.data} /> : <span className="text-fg-faint">see Settings</span>}
        </p>
      </div>
    </section>
  );
}
