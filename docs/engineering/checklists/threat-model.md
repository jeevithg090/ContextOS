# Threat model

> Produce or update a threat model for a ContextOS feature, integration or the whole system — assets, actors, entry points, trust boundaries, STRIDE plus agent-specific threats (prompt injection, credential exfiltration, tool misuse, hook bypass, cross-tenant access), each mapped to the control in code, the test that proves it, and the residual risk. Use before building anything that handles agent data, auth, API keys, policy, approvals, exports or a new integration, and when a security review asks "what could go wrong here?".

Output is a table you can defend line by line: every "mitigated" claim names the code that does it
and the test that proves it. A control without a test is "unverified", not "mitigated".

## 1. Scope and context
1. State the scope in one sentence and list the files/routes in it (`grep -rn "router\." backend/app/api/routes/<area>.py`).
2. Read `docs/ARCHITECTURE.md` (pipeline + enforcement model), `backend/app/api/deps.py` (principals,
   CSRF), `backend/app/events/envelope.py` (what clients can send), and the security/threat docs
   listed in `CONTRIBUTING.md` — update them rather than contradict them.

## 2. Assets (pick those in scope)
Raw secrets and raw context content (must never be stored) · secret fingerprints and content hashes ·
API keys (`ctxk_…`, stored hashed) and session tokens (`ctxs_…`) · tenant data (agents, sessions,
context, findings, incidents, tasks) · policies and trust rules (they decide what agents may do) ·
approvals (a human's authorisation) · the audit hash chain (`backend/app/services/audit.py`) ·
`CONTEXTOS_SECRET_KEY` · exports (incident evidence, audit JSONL, AI fix-context prompts).

## 3. Actors
Author of malicious content an agent reads (README, web page, MCP tool description/result) ·
compromised or manipulated agent · holder of an integration API key (possibly agent-bound) · user of
another organisation · in-org user with a lower role (viewer/developer) · insider with DB read/write ·
network attacker against the hooks/gateway ↔ server channel · malicious MCP server.

## 4. Entry points and trust boundaries
`POST /api/v1/events`, `POST /api/v1/decide`, `GET /api/v1/decide/approvals/{id}`, `POST /api/v1/scan`
(API keys) · browser routes under `/api/v1/*` (session cookie + CSRF header) · `GET /api/v1/stream`
(SSE) · `contextos-server` CLI · Claude Code hooks (`contextos hook <Event>`) · MCP gateway
(`contextos mcp-gateway`) · SDK `guard()` · exports and AI prompt generation. Boundaries: agent ↔
host framework ↔ integration ↔ server ↔ database ↔ browser.

## 5. Enumerate threats
For each entry point apply STRIDE, then this ContextOS list (keep the ones in scope):

| Threat | Where the control lives (verify!) | Proving tests |
|---|---|---|
| Client supplies trust/risk/decision fields | `EventEnvelope` `extra="forbid"` (`backend/app/events/envelope.py`) | `tests/integration/test_events_api.py` |
| Key reports another agent / org | attribution check in `backend/app/services/ingestion.py`; org from key | `tests/integration/test_admin.py::test_api_key_bound_to_agent` |
| Replay / duplicate events | unique `(organization_id, client_event_id)` (`backend/app/models/platform.py`) | `test_events_api.py::test_duplicate_event_ids_are_idempotent` |
| Raw secret persisted, logged, streamed or exported | `app.engines.redaction` at every write; `notify` ids only | `tests/integration/test_ingestion_redaction.py`, `tests/unit/test_redaction*.py` |
| Redaction bypass by encoding/obfuscation | `backend/app/engines/redaction/`, `backend/app/engines/detection/normalize.py` | unit adversarial cases |
| Prompt injection in context steers tool use | detection + trust + session risk + policy (`backend/app/engines/`) | `tests/unit/test_detection.py`, `tests/integration/test_ingestion_usecases.py` |
| Credential exfiltration via tool arguments | fingerprints seen in context matched in arguments; built-in deny policy | `tests/integration/test_ingestion_pipeline.py`, `test_decide_api.py` |
| Cross-tenant read/write by id | `scoped`/`get_scoped` (`backend/app/services/scoping.py`) → 404 | `other_org` tests; `route_audit.py` |
| Privilege escalation inside an org | `require(Permission…)` (`backend/app/api/deps.py`), `ROLE_PERMISSIONS` | permission tests per area |
| CSRF on cookie sessions | `X-Requested-With: contextos` check in `get_principal` | `test_auth.py::test_cookie_session_requires_csrf_header_on_unsafe_requests` |
| Brute-force login | rate limiter (see `backend/app/services/auth_service.py`) | `test_auth.py::test_rate_limiter_window_and_key_isolation` |
| Oversized payload / DoS | 413 middleware (`backend/app/main.py`), `max_event_bytes` checks in `backend/app/api/routes/events.py` and `backend/app/services/ingestion.py` | none found for events (only `test_workspace_evidence.py` uploads) — add one |
| Audit tampering | keyed hash chain + `GET /audit/verify` | `tests/integration/test_audit_api.py` |
| Hook loosens permissions (`allow`) | `Verdict.to_output` refuses (`sdk/contextos/integrations/claude_code/enforce.py`) | `sdk/tests/test_claude_code_enforce.py` |
| Server unreachable → silently allowed | fail mode `closed` default (`sdk/contextos/config.py`) | `sdk/tests/test_claude_code_enforce.py`, `test_guard.py`, `test_mcp_gateway_enforcement.py` |
| RESTRICT not applicable → call runs unrestricted | deny when a restriction cannot be applied (`sdk/contextos/restrictions.py`) | `sdk/tests/test_guard_restrictions.py` |
| Approval spoofed or replayed | approvals scoped to org + invocation; a decided/expired approval answers 409 | `tests/integration/test_approvals_api.py` |
| Misleading claims ("blocked" when observed) | `enforcement` derivation (`backend/app/services/ingestion_state.py`) | `test_decide_api.py::test_enforcement_claim_depends_on_integration` |
| Provenance read as causation / counterfactual read as history | wording + `input_snapshot` replay (`backend/app/services/replay_service_counterfactual.py`) | `tests/integration/test_replay_api.py` |
| Exported AI prompt leaks secrets | redaction in workspace prompt generation (`backend/app/workspace/`) | `tests/integration/test_workspace_ai_prompts.py` |

Open each referenced file and test before you cite it — if it does not do what the row says, the
row becomes a finding.

## 6. Rate and decide
For each threat: likelihood (L/M/H) × impact (L/M/H) → risk; status = mitigated (code + test) /
partially mitigated / unverified (code, no test) / open. For open or partial items name the
smallest mitigation and the test that would prove it (adversarial case first).

## 7. Output (return this; save it into the threat-model doc only if asked or if you own it)
```markdown
# Threat model — <scope> (<date>, <commit>)
Scope: … · Assets: … · Actors: … · Entry points: …
| ID | Threat (STRIDE/agent) | Entry point | Control (file:line) | Test | L | I | Status | Mitigation needed |
|----|-----------------------|-------------|---------------------|------|---|---|--------|-------------------|
## Required tests
- [ ] <test name> in <file>: <adversarial input> → <expected>
## Accepted risks / out of scope (with reason)
## Assumptions (deployment, e.g. TLS terminates in front of the server; secret key managed externally)
```
