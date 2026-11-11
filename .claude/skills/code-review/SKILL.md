---
name: code-review
description: Review a ContextOS diff, branch or pull request against this repository's security rules and conventions — redaction, org isolation (404), server-side classification, honest enforcement wording, layering, migrations, frontend tokens and states, and test coverage — and report verified findings ranked by severity with a failure scenario and fix for each. Use when asked to review code, a PR or "my changes", before committing a feature, or as the last step of secure-feature / integration-builder work.
argument-hint: "[PR number | branch | paths]  (default: working tree vs main)"
---

# Code review (ContextOS)

Only report what you verified by reading the code (and, where cheap, by running a test). Each
finding needs a concrete failure scenario. Do not post to GitHub or edit files unless asked.

## 1. Get the change
```bash
git status --short && git diff --stat                 # working tree
git diff main...HEAD --stat && git diff main...HEAD    # branch
gh pr diff <number>                                    # pull request (read-only)
```
Read every changed file in full where it matters (not just hunks): the bug is often in the
unchanged caller.

## 2. Route each file to its checklist
| Paths | Load | Focus |
|---|---|---|
| `backend/app/**` | `.claude/rules/backend-architecture.md`, `security-engineering.md` | layers, errors, Page, audit+notify |
| `backend/app/models/**`, `backend/alembic/**` | `.claude/rules/database-migrations.md` | migration present and correct |
| `backend/app/services/ingestion*`, `events/**`, `sdk/**` | `.claude/rules/integration-adapters.md` | contract, enforcement, fail closed |
| `frontend/src/**` | `.claude/rules/frontend-architecture.md` | api.ts hooks, tokens, states |
| `**/tests/**` | `.claude/rules/testing.md` | isolation + adversarial coverage |
| `docs/**`, `*.md` | `.claude/rules/documentation.md` | claims match code |

## 3. Blockers — check every one
- [ ] Agent-derived text or a secret reaches a column, log, audit `details`, `notify`, SSE, export or
      AI prompt without `redact_text`/`redact_value` (trace the value from the request to each sink).
- [ ] An org-owned query without `organization_id` filtering (`scoped`/`get_scoped`), `db.get` on a
      client-supplied id, a foreign id in a body that is not checked, or a 403/other message that
      reveals another org's record exists.
- [ ] Trust level, risk, severity, decision or enforcement accepted from a client (schema field,
      query param, envelope extra) instead of computed server-side.
- [ ] "Blocked/denied/prevented" wording, a badge or a metric that does not depend on
      `enforcement == "enforced"`; provenance presented as causation; counterfactual presented as
      history or computed from anything but `PolicyDecision.input_snapshot`.
- [ ] Fake or hard-coded data in a product surface (sample rows, static metrics, placeholder
      copy, a button without a working handler); simulated rows not flagged/labelled.
- [ ] A Claude Code hook path that can emit `allow`; a RESTRICT path that runs unrestricted; an
      error path that turns into ALLOW (fail open without the user's explicit `open` fail mode).
- [ ] Schema change without an Alembic revision; a revision that does not round-trip.
- [ ] State change without `require(Permission…)` of the right strength, or guarded only by `read`.
- [ ] `except …: pass` (or log-and-continue) around I/O, DB or security checks.

## 4. Majors and minors
- Missing tests: happy, validation, permission, `other_org` isolation, adversarial/redaction.
- `append_audit`/`notify` missing on a state change; notify type absent from `useLiveEvents.ts`.
- Layer violations (DB/FastAPI in engines, logic in routes); stable contract signature changed.
- Lists not `Page[T]`, unbounded `limit`, N+1 queries, missing index on a new filter column.
- Frontend: raw palette colours/hex, hand-rolled badges, `fetch` outside `api.ts`, missing
  loading/error/empty state, retries on 404, query keys not feature-prefixed.
- Naive datetimes, ids not from `new_id`, files > ~500 lines, `HTTPException` instead of `AppError`.

## 5. Verify with tools (pick what the diff touches)
```bash
cd backend && .venv/bin/ruff check app tests
cd backend && .venv/bin/python -m pytest -q -p no:cacheprovider <test files for the changed area>
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests          # sdk/ or envelope changed
cd frontend && npx tsc -b --noEmit && npx eslint <changed paths> && npx vitest run <feature dir>
backend/.venv/bin/python .claude/skills/repo-audit/scripts/route_audit.py --tests <changed test files>   # routes changed
backend/.venv/bin/python .claude/skills/repo-audit/scripts/doc_paths.py <changed .md files>              # docs changed
```
When you suspect a leak or isolation bug, prove it with a throwaway test in the scratchpad (not in
the repo) using the `client`/`org`/`other_org` fixtures, and include the result.

## 6. Output (return exactly this shape)
```markdown
# Review — <target> (<n> files, +<a>/−<d>)
Verdict: approve | changes requested | blocked
## Findings
1. **[blocker|major|minor|nit] <short title>** — `path:line`
   Rule: <CLAUDE.md rule # or .claude/rules file>
   Scenario: <concrete input/state → wrong outcome>
   Fix: <specific change>
## Verified
- <command> → <result/count>
## Not reviewed
- <files/areas skipped and why>
```
Rank most severe first. No praise padding, no restating the diff.
