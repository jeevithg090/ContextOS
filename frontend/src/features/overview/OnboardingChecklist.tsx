/** First-run checklist: connect a real agent (API key → Claude Code hooks) or see the controls work by
 * running a Simulation Lab scenario. Each step is ticked from persisted state, never assumed. */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Circle } from "lucide-react";
import { CodeBlock } from "@/components/data";
import { cn } from "@/lib/format";
import { claudeCodeCommands } from "./meta";
import type { Onboarding } from "./types";

function Step({ n, done, title, children }: { n: number; done: boolean; title: string; children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className={cn("mt-0.5 shrink-0", done ? "text-ok" : "text-fg-faint")} aria-hidden>
        {done ? <CheckCircle2 className="h-4 w-4" /> : <Circle className="h-4 w-4" />}
      </span>
      <div className="min-w-0 flex-1 space-y-2">
        <div className="text-[13px] font-medium text-fg">
          <span className="sr-only">{done ? "Done: " : "To do: "}</span>
          {n}. {title}
        </div>
        {children}
      </div>
    </li>
  );
}

export function OnboardingChecklist({ onboarding, compact = false }: { onboarding: Onboarding; compact?: boolean }) {
  const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost:8000";
  return (
    <section aria-labelledby="onboarding-title" className="panel p-5">
      <h2 id="onboarding-title" className="text-sm font-semibold text-fg">
        {compact ? "Connect a real agent" : "Connect your first agent"}
      </h2>
      <p className="mt-1 max-w-2xl text-xs text-fg-muted">
        {compact
          ? "Everything below comes from the Simulation Lab. Connect an agent to see what your own agents read and do."
          : "ContextOS shows what your agents read and do once an integration reports their activity. Nothing is shown until real or simulated events arrive."}
      </p>
      <ol className="mt-4 space-y-5">
        <Step n={1} done={onboarding.has_api_key} title="Create an API key">
          <p className="text-xs text-fg-muted">
            Integrations authenticate with a key that has the <code className="font-mono">ingest</code> and <code className="font-mono">decide</code> scopes. The full key is shown once.{" "}
            <Link to="/settings?tab=api-keys" className="text-accent hover:underline">
              Open API keys
            </Link>
          </p>
        </Step>
        <Step n={2} done={onboarding.has_events} title="Install the Claude Code hooks">
          <p className="text-xs text-fg-muted">
            Run these in your project. <code className="font-mono">init</code> checks the server and the key before it writes anything, then installs the hooks in <code className="font-mono">.claude/settings.json</code>; <code className="font-mono">doctor</code> verifies them. The PreToolUse hook is enforced; the others only report.
          </p>
          <CodeBlock code={claudeCodeCommands(origin)} language="bash" title="Terminal" />
          <p className="text-xs text-fg-muted">
            Using MCP servers or your own Python agent instead?{" "}
            <Link to="/integrations" className="text-accent hover:underline">
              See all integrations
            </Link>
          </p>
        </Step>
        <Step n={3} done={onboarding.has_simulations} title="Or run a simulation">
          <p className="text-xs text-fg-muted">
            Replay a scripted attack (for example a prompt injection that tries to exfiltrate a credential) through the real pipeline. Results are labelled as simulated and never mark an integration as connected.{" "}
            <Link to="/simulation" className="text-accent hover:underline">
              Open the Simulation Lab
            </Link>{" "}
            or run <code className="font-mono">contextos simulate --list</code>.
          </p>
        </Step>
      </ol>
    </section>
  );
}
