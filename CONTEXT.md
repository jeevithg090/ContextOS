# ContextOS — current state

Read after `CONTRIBUTING.md`. Update this file after significant work (what works, what changed, known
problems, next steps). Last updated 2026-11-14: 0.1.0 is tagged `v0.1.0` at `f9980b5` (release review
2026-11-11, follow-up fixes 2026-11-13); the OpenAI Codex integration was merged afterwards and is
not part of 0.1.0 (see "Changes since 0.1.0").

## Current milestone

**First release, version 0.1.0** (`backend/pyproject.toml`, `sdk/pyproject.toml`): released and tagged
`v0.1.0` (commit `f9980b5`, 2026-11-14) after the wave-2 verification, security review, documentation
and release-readiness work. Release notes: [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## Architecture summary

FastAPI modular monolith (`backend/app`): pure engines (redaction, detection, trust, policy, risk,
provenance) → services (ingestion pipeline, persistence, audit, notify) → thin routes under
`/api/v1` (163 operations, 22 modules). SQLAlchemy 2 with 41 tables, schema owned by Alembic
(`0001_initial`, `0002_incident_seq`); SQLite for development, PostgreSQL in production. In-process SSE bus for live
updates. React 18 SPA (`frontend/`). Integrations in `sdk/` speak HTTP only. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Features completed (verified this phase)

- Ingestion pipeline: validate → attribution → idempotency → redact → entities → trust → detect →
  provenance → risk → policy → findings/incidents → persist/audit/notify; per-event SAVEPOINT and
  visible processing errors.
- Engines: secret redaction with keyed fingerprints; deterministic injection/credential/exfiltration
  detection (content test split P 0.968 / R 0.931; tool requests P 1.000 / R 0.895 after a disclosed
  post-hoc fix, 0.850 on the first held-out run —
  [docs/DETECTION_EVALUATION.md](docs/DETECTION_EVALUATION.md)); trust rules + evidence; policy DSL
  with enforce/monitor modes; lethal-trifecta session risk; agent posture; provenance risky paths;
  signed Context Receipts.
- Integrations: Claude Code hooks (PreToolUse enforced, never `allow`; live-verified against Claude
  Code 2.1.319), OpenAI Codex hooks (PreToolUse enforced by exit 2, never `ask`; live-verified against
  Codex CLI 0.158.0-alpha.2.1 with an offline scripted model), MCP stdio gateway (`tools/call`
  enforced), Python SDK `guard()` (enforced), CLI.
  Approvals are withdrawn (`POST /decide/approvals/{id}/cancel`) when an adapter stops waiting.
- Dashboard: Overview, Agents/Sessions, Context Explorer + receipts, Provenance Graph, Trust Centre,
  Security Intelligence, Policy Studio, Approval Centre, Incidents, Replay Lab (with counterfactual
  simulation), Simulation Lab, Integrations, Audit Log, Settings.
- Engineering Workspace: boards, tasks, remediation from findings/incidents, deterministic AI fix
  context and context packs (no external AI calls), fix attempts, verification incl. Simulation Lab.
- Platform: first-run setup, roles, API keys (scoped, agent-bound), CSRF header, login rate
  limiting, keyed HMAC audit chain with verify/export, incident evidence export, retention purge,
  9 Simulation Lab scenarios, `seed-demo` through the real pipeline, Alembic migrations,
  production settings validation, Dockerfile and docker-compose.

Verification on 2026-11-11 (release review) and 2026-11-13 (after the follow-up fixes), this machine:

| Suite | Command | Result |
|---|---|---|
| Backend (SQLite) | `cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests` | 1780 passed (2026-11-13; 1751 at the X1 release review) |
| Backend (PostgreSQL 17.11, scratch DB) | same with `CONTEXTOS_TEST_DATABASE_URL=postgresql+psycopg://…/contextos_test` | 1751 passed (X1 release review) |
| SDK / CLI / adapters | `make test-sdk` | 387 passed (2026-11-13) |
| Frontend | `cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run`; `npm run build` | clean, clean, 492 passed (66 files, every page has a page-level render test); build OK (2026-11-13) |
| Backend lint / types | `cd backend && .venv/bin/ruff check app tests`; `.venv/bin/mypy app/engines app/workspace app/core app/domain app/events` | clean; clean (services/routes are not mypy-clean: ~320 mostly SQLAlchemy typing errors) |
| Quick start | `init-db`, `create-org`, `create-api-key`, `serve`, `contextos init --claude-code`, `contextos doctor`, hook `deny`, `contextos simulate`, `seed-demo`, `purge --dry-run` | all as documented (SQLite and PostgreSQL) |

## Changes since 0.1.0

**OpenAI Codex integration (2026-11-13)** — [docs/integrations/codex.md](docs/integrations/codex.md).

- `sdk/contextos/integrations/codex/` + `contextos codex-hook <Event>`: PreToolUse → `POST /decide`;
  DENY / undecided approval / unapplicable RESTRICT / fail mode `closed` → exit 2 with the reason on
  stderr (Codex blocks); ALLOW/AUDIT → no output (Codex's approval policy and sandbox still apply);
  RESTRICT `redact_secrets` → `allow` + masked `updatedInput` after a `/scan` re-check. Observation:
  `SessionStart`, `UserPromptSubmit` (a sub-agent's task → `agent.message`), `PostToolUse`,
  `SubagentStop` (child session ended), `SessionEnd` (spooled first, Codex allows 3 s).
- `contextos init --codex [--scope project|user]` writes `.codex/hooks.json` (merge, backup, keeps
  existing hooks' positions so their Codex trust stays valid); trust in Codex `/hooks` is the user's
  step. `contextos doctor` reads the trust Codex recorded (`[hooks.state]` in `config.toml`),
  `[features] hooks`, project trust and login-shell stdout.
- Server: `openai_codex` in `ENFORCING_INTEGRATIONS`; catalogue entry supported (was planned);
  setup guide; Approval Centre / overview labels. Risk engine: Codex built-ins for provider
  `openai_codex` (`apply_patch` = file write, not shell; patch files extracted as resources;
  `multi_agent_v1<tool>` names); `.codex/` writes → `TOOL-AGENT-CONFIG-WRITE` (denied by the
  built-in tampering policy).
- `sdk/contextos/integrations/hookkit.py`: helpers shared by both hooks (budget, approval polling,
  reason text, cross-process records); the Claude Code hook now uses them (behaviour unchanged).
- Live: `examples/codex/live_verify.py` and `backend/tests/e2e/test_live_codex.py` run the real
  Codex binary against a real server with `examples/codex/fake_model_server.py` as the model
  (offline): `.env` read and exfiltration blocked (the command never ran), `apply_patch`, an MCP call
  through the gateway (decided by hook and gateway) and a sub-agent ran, all decisions `enforced`.

Verification on 2026-11-13 (Codex integration, this machine; worktree virtualenv from
`uv pip install --offline -e "backend[dev,postgres]" -e "sdk[mcp]"`):

| Suite | Command | Result |
|---|---|---|
| Backend (SQLite) | `cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests` | 1769 passed (18 new, incl. `tests/e2e/test_live_codex.py` with the real Codex binary) |
| SDK / CLI / adapters | `cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests` | 478 passed (91 new Codex tests) |
| Backend lint | `cd backend && .venv/bin/ruff check app tests` | clean |
| Frontend (labels only changed) | `npx tsc -b --noEmit`; `npx vitest run src/features/agents src/features/overview src/features/integrations` | clean; 28 passed |
| Live | `backend/.venv/bin/python examples/codex/live_verify.py` | PASS (Codex CLI 0.158.0-alpha.2.1, offline scripted model) |

After merging into `main` on 2026-11-14 (on top of `v0.1.0` and its follow-up commit `8bc8130`; only
`CONTEXT.md`, the release notes and the improvements list conflicted): backend **1798 passed** (no
skips; `tests/e2e/test_live_codex.py` 4 passed with Codex CLI 0.158.0-alpha.2.1 from the ChatGPT
app), SDK **478 passed**, frontend `tsc` and ESLint clean, **492 passed** (66 files), `npm run build`
OK, `ruff check app tests` clean, `smoke.py` 12 of 12, `doc_paths.py` 0 missing references.

## Release readiness (0.1.0)

Reviewed 2026-11-11 with `docs/engineering/checklists/release-readiness.md` on a clean copy of the working
tree (`git ls-files -co --exclude-standard`), a new virtualenv (`uv venv` + `uv pip install --offline
-e "backend[dev,postgres]" -e "sdk[mcp]"` — `make install` itself downloads from PyPI and was not
run), `npm ci --offline`, a fresh SQLite database and scratch ports. **Verdict: ready to tag** (tagged `v0.1.0` at `f9980b5` on 2026-11-14) — no
blocker found in the product. Item 22 was partial in that review (no signed-in browser walk); the
walk was done afterwards (below) and found no problem.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Launches from a clean environment | met | `init-db` → `create-org` (password prompt) → `create-api-key` → `seed-demo` (9/9 scenarios met expectations) → `contextos-server serve` with the SPA; `make serve PORT=…`; `smoke.py` 12/12 PASS |
| 2 | Backend ↔ frontend | met | SPA, deep links and assets served by the API; browser loaded `/login`, which called `/auth/me` and `/auth/setup-status`; Vite dev proxy (scratch ports) → `/api/v1/health` 200; 47 GET routes + 9 detail routes answered as the signed-in owner |
| 3 | Migrations | met | `upgrade head` / `alembic check` / `downgrade base` / `upgrade head` clean on SQLite and PostgreSQL 17.11; `tests/integration/test_migrations.py` |
| 4 | Agent registration | met | smoke `records via API` (auto-registered by name); `test_agents_api.py` |
| 5 | Real events ingested | met | smoke `events ingested`; API-key ingestion 3/3 accepted; `test_events_api.py`, `test_ingestion_pipeline.py` |
| 6 | Context sources recorded | met | sources with trust `SUSPICIOUS`/`UNKNOWN`; `test_context_api.py` |
| 7 | Trust classification | met | computed server-side; an event carrying `trust_level` → 422 (`extra_forbidden`); `test_trust_*.py` |
| 8 | Provenance persisted | met | 46 edges for the review session; UI says edges "do not prove the content caused an action" (`ProvenancePage.tsx`); `test_provenance_api.py` |
| 9 | Findings include evidence | met | finding detail evidence items resolve (`found: true`); `test_findings_api.py` |
| 10 | Understandable explanations | met | three findings and three decisions read in plain language; one misleading remediation fixed (exfiltration, see `docs/RELEASE_NOTES.md`) |
| 11 | Policy evaluation | met | DENY by "Block credential exfiltration" with matched conditions; `test_policy_engine.py`, `test_decide_api.py` |
| 12 | Enforcement path | met | real `contextos hook PreToolUse` process → `deny` for `rm -rf ~/`; MCP gateway blocked `add_note` with a credential after an injected result (server call log: never ran); live Claude Code run recorded in `docs/integrations/claude-code.md` (not repeated) |
| 13 | Approvals end to end | met | smoke pending → approved by owner → integration poll `approved`; `test_approvals_api.py` |
| 14 | Incident investigation | met | auto-escalated incident, 28 timeline entries, note, export with canary absent; audit chain valid (81 entries) |
| 15 | Replay uses recorded events | met | 9 steps from the recorded session; counterfactual `simulation: true` with the SIMULATION label; `test_replay_api.py` |
| 16 | One meaningful integration | met | Claude Code: `contextos init --claude-code` (key mode 600), `contextos doctor` all green, "enforcing via PreToolUse" |
| 17 | Redaction | met | canary absent from database, WAL, SHM, server log, incident export and a note that contained it; `test_ingestion_redaction.py` |
| 18 | Organisation isolation | met | smoke cross-org 404s; `route_audit.py`: 0 unexpected public routes, 0 read-guarded writes, 0 empty modules; its 3 listed gaps are explained (stream isolation is tested in process by `test_stream.py::test_committed_notifications_reach_only_the_same_org`; `/simulations/scenarios/{id}` and `/integrations/{kind}/setup` are global catalogues) |
| 19 | Automated tests pass | met | counts in the table above; ruff, tsc, ESLint clean |
| 20 | Installation docs | met | README quick start run as written (ports moved to 18000–18999 for this review); `doc_paths.py`: 42 documents, 0 missing references |
| 21 | Limitations documented | met | "Known problems" below, `docs/RELEASE_NOTES.md`, `docs/PRODUCT_IMPROVEMENTS.md` |
| 22 | No placeholder interfaces | met | no TODO/"coming soon"/lorem text in `backend/app`, `sdk/contextos`, `frontend/src`; every route module has routes; every page's GET endpoints answer with data. Signed-in browser walk (built SPA from `contextos-server serve`, fresh DB + `seed-demo`): all 22 nav pages, 7 detail/drawer views and a not-found page render at 1280 px with 0 console errors; the same 26 views at 375 px have no horizontal scroll; "blocked" only for DENY to an enforcing integration. Every page now has a page-level render test (loading, error, empty and data states) |

## Known problems and limitations

- **No scripted browser walk**: every page has a Vitest render test, but the signed-in click-through
  in a real browser was done by hand for 0.1.0 and is not automated
  ([PRODUCT_IMPROVEMENTS.md](docs/PRODUCT_IMPROVEMENTS.md) #21). The provenance page test stands in
  a stub for the React Flow canvas (jsdom has no layout); its layout logic has unit tests.
- **npm advisories needing major upgrades**: two moderate `react-router` 6.x advisories are fixed
  only in v7 (they do not apply to this SPA: no SSR, all navigation targets are app-defined paths);
  dev/test tooling (`vitest` 2, `typescript-eslint`, `eslint`) has advisories that need majors. The
  shipped bundle's other runtime dependencies audit clean (`npm audit --omit=dev`).
- **Docker image build not verified**: `Dockerfile` and `docker-compose.yml` exist, but Docker is
  not installed on the build machine, so `docker build` / `docker compose up` have never been run.
- **Enforcement gaps** (by design of the hosts): disabled or bypassed Claude Code hooks, MCP servers
  not behind the gateway, code not wrapped by `guard()`, and files touched inside shell commands are
  not covered. Path RESTRICTs on opaque tools deny.
- **Codex**: hosted tools (web search) and `write_stdin` into a running command never reach
  PreToolUse; hooks Codex does not run (untrusted/modified in `/hooks`, `[features] hooks = false`)
  cover nothing; Codex reports no result for failed calls or for `apply_patch` run through a shell
  command; a RESTRICT rewrite is lost if the login shell prints to stdout (doctor checks); a hook
  that crashes or times out lets the tool run (Codex's rule; the hook answers inside its budget).
  Not live-verified: the `/hooks` trust UI, Windows, the interactive TUI.
- **Detection is lexical**: semantic paraphrases without trigger vocabulary are missed; secrets are
  recognised in `echo`/`printf` by variable name only, so a credential under an innocuous name is not.
- **MCP tool calls have no default `mcp:<server>` destination** (would make local MCP servers count
  as outbound). Mitigation: the built-in "Deny credentials in tool arguments after prompt injection".
- **Lock ordering (PostgreSQL)**: WIP-limit checks, "task from finding" and default-board seeding take the
  organisation row lock (`org_counters.lock_org`) before writing, as ingestion does. A request that
  updates a task row first and audits afterwards can still deadlock with one of them on the same task;
  PostgreSQL aborts one transaction (an error the client can retry), it never hangs.
- **Single-replica assumptions**: the SSE bus and the login rate limiter are in-process; several API
  replicas would need a shared bus/limiter.
- **MCP gateway**: stdio upstreams only; sampling, elicitation, roots and subscriptions are not
  proxied; `tools/list` is flattened (≤ 100 upstream pages); text-only scanning.
- **Audit chain**: detects tampering by anyone without `CONTEXTOS_SECRET_KEY`; an attacker with DB
  write access *and* the secret can rewrite it (export `audit_head_hash` externally). Rotating the
  secret invalidates fingerprints, receipt signatures and chain verification.
- **Operations**: retention purge must be scheduled externally (`contextos-server purge`); accounts
  are local email/password (no SSO/MFA).
- Planned integrations (Cursor, LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK) have no
  native adapter; the catalogue lists their interim paths.

Full list with impact and decisions: [docs/PRODUCT_IMPROVEMENTS.md](docs/PRODUCT_IMPROVEMENTS.md).

## Important decisions

Modular monolith; pure engines; SQLite dev / PostgreSQL prod via SQLAlchemy + Alembic; opaque
session tokens + CSRF header; keyed HMAC audit chain; server-side classification only (envelope
`extra="forbid"`); Claude Code hooks never emit `allow`; MCP gateway as a stdio proxy; Simulation
Lab through the real pipeline (`is_simulation`); counterfactuals from recorded `input_snapshot`;
deterministic fix context without external AI. Two built-in policies were added after Simulation
Lab runs found gaps: "Deny credentials in tool arguments after prompt injection" and "Require
approval for outbound calls after prompt injection". Rationale: [docs/ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md).

## Priorities and next steps

1. Plan the React Router v7 and Vitest 3+ upgrades (clears the remaining npm advisories).
2. Verify the Docker image and compose stack on a machine with Docker; record the result here.
3. Decide the MCP destination question and close the remaining detection blind spots worth fixing.
4. Next integration from the catalogue (Cursor) and a shared bus for multi-replica deployments.
5. Codex: re-verify the hook contract on each Codex release (the hooks engine is new and its
   output rules are strict); verify the `/hooks` trust flow and the TUI by hand.
See [docs/ROADMAP.md](docs/ROADMAP.md).
