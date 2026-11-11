# Product specification

What each area of ContextOS does **today**. Routes are the SPA paths (`frontend/src/app/routes.tsx`,
sidebar in `frontend/src/app/nav.ts`); the API behind each is in
[API_SPECIFICATION.md](API_SPECIFICATION.md). Every view has loading, error and empty states and
refreshes live from `GET /api/v1/stream`. Simulation Lab data is hidden unless a page's
**Include simulated** switch is on, and is labelled when shown.

## Roles

| Role | Can |
|---|---|
| `owner`, `admin` | everything, including members, API keys, organisation settings and audit export |
| `security_analyst` | read, triage and investigate (`write`), decide approvals, manage policies and trust rules |
| `developer` | read, triage findings, work incidents and Engineering Workspace tasks |
| `viewer` | read only |

## Getting started

- **First run** (`/login`): while the server has no organisation, the login page becomes
  "Create your organisation" (owner name, email, password ≥ 10 characters) and seeds the 13 built-in
  policies and 21 default trust rules. Afterwards it is a normal sign-in (5 failures per email and
  IP in 5 minutes → temporarily refused).
- **Onboarding checklist** on the Overview: 1. create an API key, 2. install the Claude Code
  hooks (copy-ready commands), 3. or run a simulation — each step is ticked from persisted data
  (simulations never mark an integration as connected).
- **Integrations** (`/integrations`) gives copy-ready setup steps per integration kind.

## Security

### Overview (`/`)
"What is the security posture of my agents right now?" KPI tiles (critical & high findings,
pending approvals, open incidents, blocked actions, trifecta sessions, enforcement coverage), needs
attention, riskiest agents, recently denied or paused tool calls, activity charts (events,
findings, decisions over the window), source trust and integration health. Window
24h / 7d / 30d; every number comes from persisted rows.

### Agents (`/agents`, `/agents/:agentId`, `/sessions/:sessionId`)
Inventory (filter by environment, framework, status; sort by last seen, highest session risk,
name, newest) and an **identity & delegation graph** of observed delegation/messaging between
agents. Register an agent with its declared tools before it reports. Agent detail: sessions,
observed and declared tools (server-side category and risk, decision breakdown), findings,
configuration, and an explainable 0–100 **posture** with per-dimension evidence and fix hints.
**Quarantine** sets the agent's status to `quarantined`; the page says whether an enabled
enforce-mode policy actually blocks it and offers a suggested policy (changing status, environment
or labels needs `policy:manage`). Session detail: lethal-trifecta conditions with evidence,
counts, delegation (parent/child sessions), findings and the server-ordered event timeline.

### Context Explorer (`/context`, `/context/:itemId`)
"What information entered my agents, and from where?" **Items** and **Sources** views with facets
by trust, sensitivity and source type. An item shows its redacted preview (with a legend of
redaction placeholders), detections with plain-language explanations and the technique that
revealed them (decoded base64, hidden HTML, zero-width characters, …), findings and the observed
provenance chain. The **Context Receipt** page re-verifies the item's HMAC signature now and states
what the receipt proves (and what it does not).

### Provenance Graph (`/provenance`)
"How did information flow from sources to actions?" Open the graph for a session, agent, source,
finding and other scopes; nodes for sources, items, sessions, tools, invocations, resources,
destinations, findings and decisions. A **risky paths** list ranks untrusted origin → session →
sensitive access / non-approved destination paths and states the outcome (`prevented`,
`awaiting approval`, `advisory only`, `not prevented`). The inspector explains each node. The page
says that edges are observed relationships, not causation.

### Trust Centre (`/trust`)
"Which sources and destinations do we trust, and for what?" Tabs:
- **Sources** — level (`TRUSTED`, `APPROVED`, `EXTERNAL`, `UNKNOWN`, `SUSPICIOUS`, `BLOCKED`),
  capabilities (`read`, `instruct`, `execute`, `credential_access`), reasons and evidence; classify
  manually (evidence can still keep a source `SUSPICIOUS`) or re-assess.
- **Destinations** — classification, the checks actually performed (allow/blocklist match, raw IP,
  paste/webhook/tunnel services, punycode/lookalike, first seen), transfers and blocked calls; pin a
  classification.
- **Rules** — trust rules in evaluation order, with a live test while editing.
- **Tester** — dry-run how an identifier or destination would be classified (no DNS, no connection).
A summary panel shows counts per level and recent downgrades from the audit trail.

### Security Intelligence (`/intelligence`, `/intelligence/:findingId`)
"What suspicious behaviour has been detected?" Summary strip and insight panels (backlog, new
findings by severity/category, trend, top sources, mean time to resolve), the findings list (most
severe first) with filters, and triage: acknowledge, resolve, mark false positive (reason
required) or reopen. Finding detail: what happened, evidence resolved to records (redacted
excerpts), related agent/session/source/tool call/decision/destination, incident (attach to an
open one or open a new one) and remediation tasks.

### Policy Studio (`/policies`)
"What are agents allowed to do?" Policies in evaluation order with last-7-days match statistics;
filter by outcome, mode, status, source (built-in/custom). The editor offers a visual condition
builder over the field catalogue and a JSON editor (`all`/`any`/`not`, 17 operators), restrictions
for RESTRICT (`redact_secrets`, path globs, `max_argument_bytes`), outcome, priority, severity and
**mode**: `enforce` (decides) or `monitor` (dry run, recorded only). The test panel evaluates a
draft against recorded decisions' input snapshots; a matches tab lists recorded decisions in which
the policy matched. Built-in policies can be edited or disabled, not deleted.

### Approval Centre (`/approvals`)
"Which sensitive actions are waiting for a human?" A queue ordered by deadline and a history. Each
request shows what the agent wants to do (redacted arguments, resources with sensitive ones
flagged, destination and its checks), why the policy paused it (matched policy, trifecta evidence)
and the context the agent had received. Approve or reject with a note; the integration receives the
outcome on its next poll. Requests expire after the organisation's approval timeout, and an
integration that stops waiting withdraws its request (`cancelled`).

### Incidents (`/incidents`, `/incidents/:incidentId`)
"What needs investigating?" Incidents are opened automatically for critical findings (and high
ones in exfiltration, lethal trifecta, secret exposure and cross-agent contamination) or manually
from findings. Detail: status workflow (validated transitions; closing needs a resolution),
severity, assignee, summary, an **investigation timeline** merged from the involved sessions'
events, findings, decisions, approvals and activity (an observed sequence, not causation), linked
findings, involved agents/sessions/sources/destinations, notes (redacted), remediation tasks and an
**evidence export** (JSON bundle whose SHA-256 is written to the audit chain).

### Replay Lab (`/replay`, `/replay/:sessionId`)
"What exactly happened — and what if policy had been different?" A player steps through a
session's recorded events in server order, showing each recorded decision and the session risk
recomputed from recorded events. The **counterfactual** tab is labelled a simulation: choose the
current policies or none, disable or override policies, add drafts, and see how every recorded
decision would change — evaluated only against recorded input snapshots; steps without one are
reported as not evaluable. Nothing is persisted.

### Simulation Lab (`/simulation`)
"Would our controls catch these attacks?" Nine scenarios — malicious README, malicious website,
poisoned MCP server, sensitive file exposure, multi-agent contamination, destructive shell
command, agent permission escalation, lethal trifecta, and a benign coding session (false-positive
guard). Each runs through the real ingestion pipeline (nothing is executed; every row is flagged
`is_simulation`) and checks expectations (findings, trust, decisions, fingerprint matches,
incidents, redaction). History of runs, regression **suites**, and a check-by-check comparison of
two suites. The same scenarios run from the CLI (`contextos simulate`).

## Engineering

| Page | What it does |
|---|---|
| My Work (`/work/my`) | Tasks assigned to you by stage, what is due soon or overdue, and what changed recently. |
| Kanban Boards (`/work/boards`, `/work/boards/:boardId`) | Boards from 7 templates (software development, security remediation, incident response, bug tracking, feature development, technical debt, research). Drag-and-drop cards; columns with WIP limits, a status key, "requires verification" gates and automation (move on PR linked, verification passed/failed, fix attempt started). Duplicate, archive and restore boards. |
| All Tasks (`/work/tasks`), Task (`/work/tasks/:taskId`) | Search and filter every task. A task holds description, reproduction/expected/actual behaviour, acceptance criteria, assignees, labels, dependencies (no `blocks` cycles), references to security records, comments and attachments (redacted), branch/commit/PR/deployment links, fix attempts, verifications and an activity log. Deterministic breakdown into subtasks. |
| Security Remediation (`/work/remediation`) | Findings and their remediation state (no task, task open, done but unverified, verified); create a task from a finding (one open task per finding) or an incident. |
| AI Fix Context (`/work/fix-context`) | Builds a prompt for a coding agent from a task: 8 modes (investigate only, root-cause analysis, implementation plan, implement fix, security hardening, refactor, test and verify, full autonomous remediation), presets for Claude Code, Codex, Cursor or generic agents, depth and autonomy options and approval gates. Sections are generated from records and a context pack; each can be edited or regenerated; export as Markdown or JSON. Deterministic, on the server; no external AI call. |
| Prompt Library (`/work/prompts`) | Saved prompts (versioned) and templates (read-only built-ins per mode, plus custom). |
| Context Packs (`/work/context-packs`) | Token-budgeted packs (`minimal`, `standard`, `deep`, `security_critical`, `full`) of records and — when `CONTEXTOS_WORKSPACE_REPO_ROOT` is set — verified repository files; include/exclude items; audited JSON export. |
| Engineering Analytics (`/work/analytics`) | Open tasks by priority/type/status, overdue, completed in the window, mean and median resolution time, findings awaiting remediation, remediation completion rate — from persisted rows. |

## Platform

### Integrations (`/integrations`)
"Which agent frameworks are connected and what can they enforce?" Summary (connected now, can
enforce, enforced decisions, advisory or observed), connected integrations (connected = an event in
the last 24 hours, otherwise stale), the **capability matrix** per integration (what is enforced,
observed or not covered) and setup guides. Supported: Claude Code, MCP gateway, Python SDK.
Planned (no native adapter yet; interim path shown): OpenAI Codex, Cursor, LangGraph, CrewAI,
OpenAI Agents SDK, Claude Agent SDK.

### Audit Log (`/audit`)
"Who did what, and is the record intact?" Filterable audit entries (actor, action, target);
**Verify** recomputes the organisation's keyed hash chain and reports the first broken entry if
any; admins can download the chain as JSON Lines (the export itself is audited).

### Settings (`/settings`)
- **Organisation** — name, default fail mode for generated setup (`closed`/`ask`/`open`), default
  decision when no policy matches (`ALLOW`/`AUDIT`), approval timeout.
- **Members** — add members, change roles, remove (an organisation always keeps an owner).
- **API keys** — create (scopes `ingest`, `decide`, `read`; optional agent binding and expiry; the
  key is shown once), revoke.
- **Data & privacy** — retention period (applied by `contextos-server purge`) and whether redacted
  content previews are stored (hashes, detections and redacted tool arguments are kept either way,
  because decisions and replay need them).

## CLI

- `contextos-server` (operators): `init-db`, `create-org`, `create-api-key`, `seed-demo`,
  `purge`, `serve`.
- `contextos` (developers and integrations): `init`, `status`, `doctor`, `flush`, `agents`,
  `events`, `policies`, `incidents`, `replay`, `simulate`, `scan`, `hook`, `mcp-gateway`
  ([../sdk/README.md](../sdk/README.md)).

## Limitations visible to users

See [PRODUCT_IMPROVEMENTS.md](PRODUCT_IMPROVEMENTS.md) and the Limitations sections of
[integrations/claude-code.md](integrations/claude-code.md) and [integrations/mcp.md](integrations/mcp.md).
