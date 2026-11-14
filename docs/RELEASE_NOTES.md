# Release notes

## Unreleased

On `main` after `v0.1.0`; not part of that tag.

### OpenAI Codex integration (2026-11-13, merged 2026-11-14)

- **Codex hooks** (`sdk/contextos/integrations/codex/`, `contextos codex-hook <Event>`): Codex's
  `PreToolUse` hook asks ContextOS before every tool call that reaches it — shell commands (`Bash`),
  `apply_patch` edits, MCP tools and `spawn_agent` — and blocks with exit code 2 (reason on stderr).
  `REQUIRE_APPROVAL` waits for the Approval Centre and blocks when undecided (Codex hooks cannot
  ask); `RESTRICT` with secret redaction hands Codex the masked input (`allow` + `updatedInput`,
  which keeps Codex's own approval policy and sandbox). Fail mode `closed` by default. Sessions,
  prompts, successful tool results and sub-agent delegation are observed.
- `contextos init --codex [--scope project|user]` merges the hooks into `.codex/hooks.json` (backup,
  idempotent, existing hooks keep their position and trust); Codex runs them after you trust them in
  `/hooks`. `contextos doctor` reports the hooks, the trust Codex recorded, `[features] hooks`,
  project trust and whether the login shell prints to stdout.
- Server: `openai_codex` is an enforcing integration (`ENFORCING_INTEGRATIONS`); the catalogue entry
  moved from planned to supported with its limitations; setup guide with the trust step. The risk
  engine knows Codex's built-in tools (provider `openai_codex`; `apply_patch` is a file write and
  its patched files are resources), and writes to `.codex/` count as agent-configuration tampering
  (`TOOL-AGENT-CONFIG-WRITE`).
- Shared hook helpers moved to `sdk/contextos/integrations/hookkit.py` (used by both hooks; no
  behaviour change for Claude Code).
- Verified live against Codex CLI 0.158.0-alpha.2.1 with an offline scripted model
  (`examples/codex/live_verify.py`, `backend/tests/e2e/test_live_codex.py`); see
  [integrations/codex.md](integrations/codex.md#live-verification). Limitations: hosted tools,
  `write_stdin`, untrusted or disabled hooks and failed-call results are not covered.

## 0.1.0 — first release (tagged `v0.1.0` at `f9980b5`, 2026-11-14)

The first complete ContextOS: server (`contextos-server` 0.1.0), Python SDK and CLI (`contextos`
0.1.0), web UI, three integrations, Simulation Lab and the Engineering Workspace.

### Features

- **Ingestion pipeline** for the event contract v1.0 (`POST /events`, `POST /decide`): validation
  that rejects client-supplied trust/risk/decisions, idempotency, server-side redaction with keyed
  secret fingerprints, entity resolution, trust classification, detection, provenance, lethal-trifecta
  session risk, policy evaluation, findings with deduplication and automatic incident escalation,
  audit and live notifications. Per-event isolation: a failing event is recorded as a processing
  error, never dropped.
- **Context observability**: Context Explorer (items and sources), signed and re-verifiable
  Context Receipts, redacted previews (optional per organisation), SHA-256 content hashes.
- **Trust Centre**: sources and destinations with reasons and evidence, trust rules (21 defaults),
  manual classification, re-assessment, rule and destination dry runs (no DNS, no connections).
- **Detection**: deterministic prompt-injection, instruction-override, credential-seeking,
  exfiltration, MCP tool-poisoning, cross-agent contamination and dangerous-tool rules over
  normalised views (decoding, hidden text, homoglyphs, leetspeak, 13 languages for core families).
  Measured: content test split precision 0.968 / recall 0.931; tool requests 1.000 / 0.895 after a
  disclosed post-review fix (0.850 / 0.895 on the first held-out run)
  ([DETECTION_EVALUATION.md](DETECTION_EVALUATION.md)).
- **Policy Studio**: condition DSL with 17 operators and a field catalogue, visual and JSON editors,
  enforce and monitor (dry-run) modes, restrictions, tests against recorded decisions, match
  history. **13 built-in policies**, including two added after Simulation Lab runs
  (`malicious-web-page`, `poisoned-mcp-server`) found gaps:
  - "Deny credentials in tool arguments after prompt injection" (DENY, critical)
  - "Require approval for outbound calls after prompt injection" (REQUIRE_APPROVAL, high)
- **Approval Centre** with reviewer context, notes, expiry and integration withdrawal
  (`POST /decide/approvals/{id}/cancel`).
- **Security Intelligence** (findings, triage, statistics), **Incidents** (workflow, timeline,
  notes, evidence export with SHA-256 in the audit chain), **Provenance Graph** with risky paths,
  **Replay Lab** with counterfactual policy simulation over recorded input snapshots.
- **Simulation Lab**: 9 scenarios through the real pipeline (flagged `is_simulation`), regression
  suites and comparison; `contextos-server seed-demo` builds demo data the same way.
- **Engineering Workspace**: Kanban boards (7 templates, WIP limits, verification gates,
  automation), tasks linked to findings and incidents, deterministic AI fix context (8 modes, 4 agent
  presets) and context packs (5 profiles) without external AI calls, prompt library, fix attempts,
  verification (including Simulation Lab), engineering analytics.
- **Platform**: first-run setup, five roles, scoped and agent-bound API keys, CSRF header, sign-in
  rate limiting, keyed HMAC audit chain with verify and export, retention purge
  (`contextos-server purge`), Alembic migrations, production settings validation, SSE live updates.

### Integrations and their real enforcement level

| Integration | Enforced | Observed | Verified by |
|---|---|---|---|
| Claude Code hooks (`contextos init --claude-code`) | tool calls through `PreToolUse` (`deny` / `ask`; never `allow`) | sessions, prompts, tool results, subagents | SDK tests, live subprocess tests, a recorded live run against Claude Code 2.1.319 |
| MCP security gateway (`contextos mcp-gateway`) | every `tools/call`, before the upstream server is contacted | listings (poisoning scan), results, resources, prompts | SDK tests incl. in-memory MCP stack, live gateway test against the real backend |
| Python SDK `guard()` | each guarded call | `AgentSession` events | SDK tests, live example test |
| Other HTTP clients | — (`advisory`) | what they send to `/events` | |
| OpenAI Codex, Cursor, LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK | planned — no native adapter; interim paths via the gateway or `guard()` | | |

### Verification for this release

Release-readiness review on 2026-11-11 (`.claude/skills/release-readiness/SKILL.md`), on a clean copy
of the working tree (base commit `60765bd` plus the uncommitted wave-2 changes) with a new virtualenv
(`uv pip install --offline -e "backend[dev,postgres]" -e "sdk[mcp]"`), `npm ci --offline`, an empty
SQLite database and a scratch port:

- Suites: backend **1751 passed** on SQLite and on PostgreSQL 17.11 (scratch database); SDK, CLI and
  adapters **387 passed**; frontend `tsc` and ESLint clean, **367 tests passed** (47 files),
  `npm run build` OK; `ruff check app tests` clean.
- `smoke.py`: 12 of 12 checks passed (migrations, organisations and keys, server, SPA served, owner
  sign-in, ingestion, exfiltration DENY `enforced`, approval end to end, records, incident and audit
  chain, organisation isolation, canary absent from database, WAL and server log).
- README quick start as written (`init-db`, `create-org` with the password prompt, `create-api-key`,
  `seed-demo` — 9 of 9 scenarios met their expectations — `make serve`), the Vite dev proxy, and the
  Claude Code setup (`contextos init --claude-code`, `contextos doctor` all green, a real
  `contextos hook PreToolUse` process answering `deny` for `rm -rf ~/`).
- MCP gateway in front of `examples/mcp/malicious_server.py`: after the injected `get_forecast`
  result, `add_note` with a credential in its arguments was denied; the server's call log shows it
  never ran.
- Alembic `upgrade head` → `check` → `downgrade base` → `upgrade head` clean on SQLite and PostgreSQL.
- Signed-in browser click-through after the review (built SPA served by `contextos-server serve`,
  fresh database with `seed-demo`): all 22 navigation pages plus agent, session, finding, incident,
  replay, provenance and simulation-run detail views and a not-found finding render at 1280 px with
  no console errors and no stuck loading state; the same 26 views at 375 px have no horizontal
  scroll. "blocked" appears only where an enforcing integration received DENY (and as the `BLOCKED`
  trust level).
- Not repeated in this review: the live `claude -p` run (recorded the same day against Claude Code
  2.1.319 in [integrations/claude-code.md](integrations/claude-code.md#live-verification)).

The full Definition-of-Done checklist with evidence is in [../CONTEXT.md](../CONTEXT.md#release-readiness-010).

### Changes made during the release review

- The remediation text for `exfiltration` findings no longer tells the reader to treat a credential
  as compromised unconditionally (an exfiltration instruction found in content is not proof that
  anything was sent); it asks them to check whether data left first
  (`services/ingestion_findings.py`, `test_findings_api.py::test_exfiltration_remediation_does_not_assume_data_left`).
- Dependencies: `react-router-dom` 6.28 → 6.30.6 (open-redirect advisories in `@remix-run/router`),
  `vite` 6.0.5 → 6.4.6 and `vitest` 2.1.8 → 2.1.9 (dev-server file-read advisories), plus
  `npm audit fix` for non-breaking transitive updates. `backend/pyproject.toml` now sets floors
  `starlette>=0.49.1` and `h11>=0.16` (FastAPI/uvicorn alone allowed vulnerable releases).

### Changes after the release review (2026-11-13)

- **One name and default for simulated data (API change).** `GET /policies/{id}/decisions` and
  `GET /policies/recent-decisions` took `include_simulation` (default `true`); `GET /workspace/analytics`
  and `/workspace/analytics/remediation` took `include_simulations` (default `true`, and the response
  field was named the same); `GET /events` took a tri-state `is_simulation`. All now take
  `include_simulated`, default `false`, like every other route, and the analytics response field is
  `include_simulated`. The dashboard's switches default to off; the Policy Studio test-input picker
  still offers simulated decisions, labelled. `contextos events` gained `--include-simulated`.
- **Simulation Lab run detail.** Each step reports its `enforcement` and the `session_id` it was
  recorded in, and evidence rows carry their record's session, so a delegated sub-agent's tool call
  opens in the sub-agent's session rather than the parent's.
- **Detection.** TOOL-CRED-ENV's `echo $VAR` clause now fires only for secret-looking variable names
  (`echo $PATH` no longer raises a high-severity finding; `echo $AWS_SECRET_ACCESS_KEY` still does,
  and `printf` is covered too).
- **Claude Code `ToolSearch`** is recognised as an internal tool (category `other`) instead of a web
  search.
- **Tests.** A single end-to-end Workspace test (`tests/e2e/test_workspace_remediation_flow.py`)
  covers finding → task → fix context → edit and export → fix attempt → claim (rejected as proof)
  → verification → done → analytics. The 19 pages that lacked one now have a page-level render
  test (loading, error, empty and data states; honest enforcement wording), with a shared
  `frontend/src/test/pageHarness.tsx`. Suites after these changes: backend 1780, SDK 387, frontend
  492 (66 files).

### Known limitations

- The Docker image and compose stack have **not been built or run** (Docker was unavailable).
- Enforcement only covers the boundaries above; disabled hooks, servers outside the gateway and
  unwrapped code are not enforced. Path restrictions on opaque tools deny.
- Detection is lexical (paraphrases without trigger vocabulary are missed); tool-request precision
  is below the 0.90 target.
- MCP tool calls have no default `mcp:<server>` destination; the new "Deny credentials in tool
  arguments after prompt injection" policy covers the poisoned-server credential case.
- MCP gateway: stdio upstreams only; sampling, elicitation, roots and subscriptions not proxied.
- One API replica (in-process event bus and rate limiter).
- Audit chain cannot detect rewriting by an attacker holding both the database and the secret;
  export the head hash externally. Rotating the secret invalidates fingerprints, receipts and chain
  verification.
- Retention purge must be scheduled by the operator. Local accounts only (no SSO/MFA).
- Remaining npm advisories: two moderate `react-router` 6.x advisories are fixed only in v7 (a
  breaking upgrade). Neither applies to this SPA as built — it has no SSR hydration, and every
  `<Link>`/`navigate` target is an app-defined path (the login return path comes from in-app router
  state, not the URL). Dev/test tooling (`vitest` 2 with `tinypool`, `@vitest/mocker`, its bundled
  `vite` 5/`esbuild` 0.21; `typescript-eslint`'s `minimatch`; `eslint`) still carries advisories that
  need major upgrades; they affect developer machines running the test UI or dev server, not the
  shipped bundle.

More: [PRODUCT_IMPROVEMENTS.md](PRODUCT_IMPROVEMENTS.md), [ROADMAP.md](ROADMAP.md).
