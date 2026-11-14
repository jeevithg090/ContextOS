# Repository audit

> Audit the whole ContextOS repository against its own rules (CONTRIBUTING.md, docs/engineering) and produce a ranked findings report. Use when asked to audit, health-check or assess the repo, before starting a new build wave or milestone, after a large merge, or when you need an evidence-based list of gaps (auth, org isolation, redaction, layering, placeholders, doc drift, failing suites).

Goal: an evidence-backed list of violations and gaps, ranked by severity, with a concrete fix for
each. Every finding cites `file:line` or a command output. Do not fix things during the audit
unless asked; report them.

## 0. Orient (read, do not skim)
1. `CONTRIBUTING.md` (non-negotiable rules), `CONTEXT.md` (claimed state — what you are checking against),
   `docs/ARCHITECTURE.md` (layers, pipeline, enforcement model, stable contracts).
2. `docs/engineering/*.md` for the areas in scope.
3. `git log --oneline -15` and `git status --short` so you know what is new and what others are editing.

## 1. Suites (record exact pass/fail counts)
Run what is in scope (machine may be slow: allow 10 min per command):
```bash
cd backend && .venv/bin/ruff check app tests
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider tests
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests
cd frontend && npx tsc -b --noEmit && npx eslint src && npx vitest run
```
A red suite is a finding (severity = highest rule the failing test protects). Interpretation guide:
`docs/engineering/checklists/test-and-verify.md` §4.

## 2. API surface: auth, permissions, isolation
```bash
backend/.venv/bin/python scripts/audit/route_audit.py --static   # seconds
backend/.venv/bin/python scripts/audit/route_audit.py            # + other_org test run (~1 min)
```
Interpretation:
- "Unauthenticated routes not in PUBLIC" → blocker unless it is a deliberate public endpoint
  (then add it to `PUBLIC` in the script with a reason).
- "Unsafe methods guarded only by read" → high: read the service; if it persists anything it needs
  `write`/`admin`/…; if it is a reviewed dry run, add it to `READ_ONLY_POSTS`.
- "Route modules with no routes" → placeholder interface (Definition of Done blocker).
- "Never requested in an other_org test" → high for routes that return or change org data; fine for
  org-agnostic catalogues (e.g. `/policies/fields`, `/workspace/ai/modes`) — say which you judged so.
- "Id routes that never answered 404" → high: no cross-org probe exists for that id route.

## 3. Rule greps (each hit is a lead; open the file and judge)
```bash
# Engines/workspace logic must be pure (no DB/FastAPI/services) — expect no output
grep -rnE "^\s*(from|import) (sqlalchemy|fastapi|app\.(services|models|api|database))" backend/app/engines backend/app/workspace
# SDK must not import server code — expect no output
grep -rnE "^\s*(from|import) app(\.|\s|$)" sdk/contextos
# Errors must use app.core.errors — expect no output
grep -rn "HTTPException" backend/app
# db.get in routes: only for ids taken from the principal (user_id/org_id), never a path/body id
grep -rn "db\.get(" backend/app/api/routes backend/app/services
# Naive timestamps — expect no output (use app.core.timeutil.utcnow)
grep -rnE "datetime\.(now|utcnow)\(" backend/app sdk/contextos | grep -v "datetime.now(UTC)"
# Silent excepts: a parse fallback that tries another strategy is fine; swallowing I/O, DB or
# security-check failures is a violation
grep -rnE -A1 "^\s*except\b.*:\s*$" backend/app sdk/contextos | grep -E "^\S+-[0-9]+-\s+pass\s*$"
# Notify types without a frontend invalidation entry — expect no output
comm -23 <(grep -rhoE 'notify\([^"]*"[a-z_]+\.[a-z_]+"' backend/app | grep -oE '"[a-z_]+\.[a-z_]+"' | tr -d '"' | sort -u) \
         <(grep -oE '^\s+"[a-z_]+\.[a-z_]+":' frontend/src/hooks/useLiveEvents.ts | grep -oE '[a-z_]+\.[a-z_]+' | sort -u)
# Raw colours in feature code (tokens only; rgb(var(--x)) is a token)
grep -rnE "\b(text|bg|border|ring|fill|stroke|from|to|via)-(red|green|blue|gray|slate|zinc|yellow|amber|orange|emerald|rose|pink|purple|indigo|sky|cyan|teal|lime|violet|fuchsia|neutral|stone|white|black)(-[0-9]{2,3})?\b|#[0-9a-fA-F]{6}\b" frontend/src/features --include='*.tsx' --include='*.ts' | grep -v __tests__
# fetch outside api.ts / lib/api.ts
grep -rnE "(^|[^A-Za-z_.])fetch\(" frontend/src --include='*.ts' --include='*.tsx' | grep -v -e "/api.ts:" -e __tests__
# Claude Code hook must never answer allow (only the guard's docstring/refusal should match)
grep -rn '"allow"' sdk/contextos/integrations/claude_code
# Placeholders and stubs
grep -rnE "\b(TODO|FIXME|XXX)\b|coming soon|lorem ipsum|raise NotImplementedError" backend/app sdk/contextos frontend/src --include='*.py' --include='*.ts' --include='*.tsx' | grep -v __tests__
# Files over ~500 lines (split by responsibility)
find backend/app sdk/contextos frontend/src \( -name '*.py' -o -name '*.ts' -o -name '*.tsx' \) -not -path '*/__pycache__/*' -exec wc -l {} + | awk '$2 != "total" && $1 > 500' | sort -rn
```

## 4. Schema vs migrations
```bash
cd backend && S=$(mktemp -d) && export CONTEXTOS_DATABASE_URL=sqlite:///$S/a.db \
  && .venv/bin/alembic upgrade head && .venv/bin/alembic check \
  && .venv/bin/alembic downgrade base && .venv/bin/alembic upgrade head; rm -rf "$S"; unset CONTEXTOS_DATABASE_URL
```
"No new upgrade operations detected" = models and migrations agree. Anything else is a high finding
(rule 10). No revisions at all is a Definition-of-Done blocker (“migrations run”).

## 5. Redaction and honest wording (sample, do not assume)
- Pick 3 writers of agent-derived text (`grep -rn "append_audit\|notify(\|log\.\(info\|warning\|exception\)" backend/app/services`) and confirm the value passed is redacted or an id.
- `grep -rniE "\bblocked\b|prevented|stopped" frontend/src/features backend/app/services --include='*.py' --include='*.tsx'` —
  each claim must be conditional on `enforcement == "enforced"`.
- `grep -rniE "caused|because of|led to" frontend/src/features/provenance frontend/src/features/context` —
  provenance copy must say "observed relationship".

## 6. Documentation drift
```bash
backend/.venv/bin/python scripts/audit/doc_paths.py
```
Every missing path/module is a finding (medium; high when it is a doc `CONTRIBUTING.md` tells contributors to read).
Then spot-check 3 claims in `CONTEXT.md` against the code.

## 7. Report (return this, in this shape)
```markdown
# Repo audit — <date>, <commit>
## Summary
Suites: backend N passed/M failed · SDK … · frontend tsc ok/fail, eslint …, vitest … · ruff …
Blockers: n · High: n · Medium: n · Low: n
## Findings
| # | Sev | Area | Evidence (file:line / command) | Rule | Fix |
|---|-----|------|--------------------------------|------|-----|
## Judgement calls
(things the scripts flagged that you accepted, and why)
## Not checked
(scope you skipped and why)
```
Severity: **blocker** = breaks a non-negotiable rule or the Definition of Done (secret persisted,
cross-org leak, fake data, false "blocked" claim, red suite); **high** = missing isolation/adversarial
test, missing migration, unauthenticated or under-permissioned route; **medium** = layering or doc
drift; **low** = style, size, naming.
