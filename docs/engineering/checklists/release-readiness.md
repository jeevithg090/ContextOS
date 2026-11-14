# Release readiness

> Decide whether ContextOS meets its Definition of Done for a release or milestone by verifying each checklist item with evidence from this repo — a clean-environment smoke run of the real server, test suites, isolation and redaction checks, docs and limitations — and report met / partial / not met with the gap for each. Use when asked "is it ready?", before tagging or demoing a release, at the end of a build wave, or when updating the release status in CONTEXT.md.

The answer is the checklist with evidence. "Met" requires a command output, a test node id or a
file reference you checked today; anything else is "partial" or "not met". Do not round up.

## 1. Collect evidence (run all; ≈10 minutes)
```bash
# 1. Whole system from an empty database: CLI init-db → orgs/keys → uvicorn → real HTTP traffic
#    (frontend served if frontend/dist exists — run `cd frontend && npm run build` first)
backend/.venv/bin/python scripts/smoke.py --json
# 2. Suites (see test-and-verify for interpretation)
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests
cd backend && .venv/bin/ruff check app tests
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests
cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run && npm run build
# 3. API surface: auth, placeholders, isolation coverage
backend/.venv/bin/python scripts/audit/route_audit.py
# 4. Migrations agree with the models and round-trip
cd backend && S=$(mktemp -d) && export CONTEXTOS_DATABASE_URL=sqlite:///$S/a.db \
  && .venv/bin/alembic upgrade head && .venv/bin/alembic check \
  && .venv/bin/alembic downgrade base && .venv/bin/alembic upgrade head; rm -rf "$S"; unset CONTEXTOS_DATABASE_URL
# 5. Docs reference real files
backend/.venv/bin/python scripts/audit/doc_paths.py
```
`smoke.py` checks (names as printed): `init-db (migrations)`, `organisations + API keys`,
`server starts`, `frontend served`, `owner login`, `events ingested`, `policy decision on exfiltration`,
`approval end to end`, `records via API`, `incident + audit chain`, `org isolation`,
`redaction at rest + logs`. A WARN is never "met".

## 2. Definition of Done — verify each item
| # | Item | How to verify in this repo | Met when |
|---|---|---|---|
| 1 | App launches from a clean environment | smoke `init-db`, `server starts`; follow the installation guide literally in a fresh clone (no extra steps) | both PASS; guide needed no undocumented step |
| 2 | Backend/frontend communicate | smoke `frontend served` + `owner login`; dev path: `frontend/vite.config.ts` proxies `/api` → `127.0.0.1:8000` | PASS (not WARN) and a page loads data in the browser |
| 3 | Migrations run | smoke `init-db (migrations)` PASS; §1.4 round trip; `alembic check` clean; `backend/tests/integration/test_migrations.py` | all |
| 4 | Agent registration | smoke `records via API` (auto-registered by name); `tests/integration/test_agents_api.py` (explicit `POST /agents`) | both |
| 5 | Real events ingested | smoke `events ingested`; `tests/integration/test_events_api.py`, `test_ingestion_pipeline.py` | both; no hand-inserted rows in product paths |
| 6 | Context sources recorded | smoke `records via API` (sources); `tests/integration/test_context_api.py` | both |
| 7 | Trust classification | smoke lists trust levels per source; `tests/unit/test_trust_*.py`, `tests/integration/test_trust_api.py` | computed server-side only (envelope forbids client values) |
| 8 | Provenance persisted | smoke provenance edges > 0; `tests/integration/test_provenance_api.py`; UI copy says "observed relationship" | all |
| 9 | Findings include evidence | smoke finding detail has `evidence`; `tests/integration/test_findings_api.py` | evidence resolves to records (`found: true`) |
| 10 | Understandable risk explanations | read 3 findings (`explanation`, `remediation`) and 3 decisions (`reason`) from the smoke run or Simulation Lab data in the UI; `tests/unit/test_risk_session.py` | a non-expert can tell what happened and why, without raw content |
| 11 | Policy evaluation | smoke `policy decision on exfiltration`; `tests/unit/test_policy_engine.py`, `tests/integration/test_decide_api.py` | decision + matched policy recorded with `input_snapshot` |
| 12 | One enforcement path | smoke DENY with `enforcement=enforced`; `sdk/tests/test_claude_code_enforce.py`, `test_mcp_gateway_enforcement.py`, `test_guard.py`; live record in `docs/integrations/claude-code.md` → "Live verification" (`examples/claude_code/live_verify.py`) | a denied call demonstrably does not run in a real host |
| 13 | Approvals end to end | smoke `approval end to end`; `tests/integration/test_approvals_api.py`; SDK approval polling tests | pending → human decision in UI/API → integration resumes or blocks |
| 14 | Incident investigation | smoke `incident + audit chain`; `tests/integration/test_incidents_api.py`; incident detail page timeline + export | timeline built from recorded events; export redacted |
| 15 | Replay uses real events | smoke replay steps; `tests/integration/test_replay_api.py` (counterfactuals on `input_snapshot`, labelled simulation) | no reconstructed history |
| 16 | One meaningful integration | Claude Code hooks: install via `contextos init --claude-code`, `contextos doctor`, live verification record, `docs/integrations/claude-code.md` | documented, tested, live-verified |
| 17 | Redaction | smoke `redaction at rest + logs`; `tests/integration/test_ingestion_redaction.py`; `tests/unit/test_redaction*.py` | canary absent from DB, WAL, logs, responses, notifications |
| 18 | Org isolation | smoke `org isolation`; `route_audit.py` (no unexpected public routes, no uncovered org-data routes); `other_org` tests | every org-data route has a cross-org 404 test |
| 19 | Tests pass | §1.2 commands | 0 failures in backend, SDK, frontend; ruff/tsc/eslint clean; counts recorded in `CONTEXT.md` |
| 20 | Installation docs | the guide exists, `doc_paths.py` clean for it, every command in it runs as written (venv, `pip install -e`, `npm ci`, `contextos-server init-db/create-org/create-api-key/serve`) | a fresh clone reaches a working UI by following it |
| 21 | Limitations documented | `grep -rn -i "limitation" CONTEXT.md docs/` — enforcement gaps (what bypasses hooks/gateway), single-replica event bus, SQLite vs PostgreSQL, planned integrations | each known gap is written down where users will see it |
| 22 | No placeholder interfaces | `route_audit.py` "Route modules with no routes" = 0; `grep -rnE "\b(TODO|FIXME)\b|coming soon|lorem ipsum" backend/app sdk/contextos frontend/src`; click every nav item and primary button in the built UI | nothing empty, fake or dead |

## 3. Report (return this; update `CONTEXT.md` only if you own it or were asked)
```markdown
# Release readiness — <milestone> (<date>, <commit>)
Verdict: READY | NOT READY (<n> blockers)
| # | Item | Status (met/partial/not met) | Evidence | Gap → owner/next step |
|---|------|------------------------------|----------|-----------------------|
## Blockers
## Suite counts
backend <N> passed / SDK <N> / frontend <N>; ruff/tsc/eslint clean?
## Known limitations to publish
```
Blocker = any of items 1, 3, 5, 11, 12, 17, 18, 19, 22 not met, or any secret leak / cross-org
access found on the way.
