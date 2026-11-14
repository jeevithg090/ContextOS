# Architecture review

> Review a proposed design or an implemented change against ContextOS's architecture — layer boundaries (pure engines, services, thin routes), stable cross-module contracts, the ingestion pipeline, tenancy, the enforcement model, persistence and migrations, live notifications and frontend data flow — and return required changes with evidence. Use before building a new module or cross-cutting feature, when a change touches more than one layer or a stable contract, or when asked whether something "fits the architecture".

## 1. Gather
- The design or diff: `git diff --stat main...HEAD`, `git diff main...HEAD -- <paths>`, or the doc.
- `docs/ARCHITECTURE.md` (layers table, pipeline steps 1–12, enforcement model, stable contracts),
  `CONTRIBUTING.md`, `CONTEXT.md`, and the area docs listed there.
- The nearest existing implementation of the same kind (find it with
  `grep -rn "<similar concept>" backend/app frontend/src/features sdk/contextos`).

## 2. Layering (run, then read every hit)
```bash
grep -rnE "^\s*(from|import) (sqlalchemy|fastapi|app\.(services|models|api|database))" backend/app/engines backend/app/workspace   # must be empty
grep -rnE "^\s*from fastapi import .*Request|request: Request" backend/app/services                                         # services take db + org_id
grep -rnE "^\s*(from|import) app\.models" backend/app/schemas                                                                 # schemas don't import models
grep -rnE "^\s*(from|import) app(\.|\s|$)" sdk/contextos                                                                      # SDK speaks HTTP only
grep -rnE "select\(|db\.(add|execute|scalar)" backend/app/api/routes | grep -v "scoped("                                     # queries in routes = logic in the wrong layer
```
Questions: Is decision logic in an engine (pure, unit-testable, reusable by replay/simulation)?
Does the route only parse → call service → commit → return? Is a service > ~500 lines split by
responsibility (`*_query.py`, `*_present.py`)?

## 3. Contracts
List every symbol the change touches from "Cross-module contracts" in `docs/ARCHITECTURE.md`
(envelope v1.0, `loaders`, `record_finding`, incidents, approvals, `append_audit`/`verify_chain`,
`notify` types, engine `__init__` APIs, `/auth/me`, `/overview/nav-counts`). For each: signature
unchanged? If extended, are defaults backward compatible and callers (`grep -rn "<symbol>(" backend sdk frontend/src`)
still correct? A breaking change needs an explicit versioning plan (e.g. envelope `schema_version`).

## 4. Data flow and security architecture
- Integration data enters only via `ingest_event` / `decide_tool_request`; classifications are
  computed server-side; the pipeline order (validate → attribute → idempotency → redact → resolve →
  trust → detect → provenance → risk → policy → findings → persist/audit/notify) is preserved.
- Tenancy: every new table org-scoped; every lookup `scoped`/`get_scoped`; no cross-org joins.
- Enforcement: who returns the decision, at which boundary, and is the claimed mode
  (`enforced`/`advisory`/`observed`) true for that boundary? Fail mode defined?
- Honesty: provenance is observation, counterfactuals are simulations on `input_snapshot`,
  simulated data is flagged and filterable.
- Redaction happens before persistence and before anything leaves the process (SSE, export, AI prompt).

## 5. Persistence and operations
- Schema change → Alembic revision; SQLite and PostgreSQL both work (JSON variant, `UTCDateTime`,
  batch ALTER). Indexes for new filter/sort columns, always leading with `organization_id`.
- Query shape: no N+1 in list endpoints (check loops that query per row), bounded `limit`,
  pagination via `paginate`. Large payloads bounded (`max_event_bytes`, `str_max_length`).
- Live updates: `notify` after commit, ids only, type mirrored in `useLiveEvents.ts`; the
  in-process bus is single-replica — note it if the design assumes multiple workers.
- Config via `app.core.config.Settings` (`CONTEXTOS_*`), validated for production.

## 6. Frontend
Feature folder, `api.ts` hooks with feature-prefixed keys, types mirroring `*Out`, design-system
components, loading/error/empty states, no business rules duplicated client-side (the server
decides; the UI explains).

## 7. Output (return this)
```markdown
# Architecture review — <subject>
Verdict: approve | approve with required changes | rework
## Required changes (blocking)
1. <what> — <why, rule/contract> — evidence `file:line`
## Recommendations (non-blocking)
## Contract impact
| Contract | Change | Compatible? | Callers checked |
## Risks and open questions
## ADR needed?
yes/no — if yes: title, decision, alternatives considered, consequences (for the decisions doc
referenced in `docs/ARCHITECTURE.md` → "Why these choices")
```
