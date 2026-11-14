# Security engineering (ContextOS is a security product — these are release blockers)

Applies to: `backend/app/**/*.py`, `sdk/contextos/**/*.py`, `frontend/src/**/*.{ts,tsx}`, `examples/**`

Redaction
- Pass any agent-supplied text or structure (context content, tool arguments/results, prompts,
  notes, attachments, error messages that may echo input) through `app.engines.redaction`
  (`redact_text` / `redact_value`) BEFORE it reaches a DB column, log record, audit `details`,
  `notify` message, SSE frame, export or AI prompt. Store `sha256_hex` / `fingerprint_secret`
  values, never the raw secret. The SDK redacts client-side too (`sdk/contextos/redact.py`) — that
  is defence in depth, not a substitute for server-side redaction.
- Logs: `get_logger(__name__)` with ids in `extra`; never content, arguments or tokens.
- `notify(...)` fields are ids, types and enum values only. The frontend refetches details.

Tenant isolation
- Every org-owned query goes through `scoped(Model, principal.org_id)` / `get_scoped(...)` /
  `find_scoped(...)` (`app.services.scoping`). A client-supplied id is never passed to `db.get`.
- Another organisation's id is `NotFoundError` (404) — never 403, never a different message.
  Referencing a foreign id inside a body (incident_id, column_id, policy id …) is also 404.
- Derive the organisation from the principal (API key or session), never from a request body.
  API keys bound to an agent may only report that agent.

Server-side classification
- Never accept trust level, risk score, severity, policy decision or enforcement from a client.
  `EventEnvelope` (`app/events/envelope.py`) uses `extra="forbid"`; keep it that way. Hints (e.g.
  `category_hint`) are recorded for comparison only — the server classifies.

Honest claims
- Use `enforced` / `advisory` / `observed` (`EnforcementMode`) exactly as defined in
  `docs/ARCHITECTURE.md` → "Enforcement model". Say "blocked"/"denied" only when the decision was
  `enforced`; otherwise "would have been denied" / "violated policy (observed)".
- Provenance edges are observed relationships, not causation — say so in UI copy and docs.
- Counterfactual replay is a simulation evaluated against the recorded
  `PolicyDecision.input_snapshot`; it never reconstructs missing inputs and never persists results.
- Simulation Lab data is flagged `is_simulation` and labelled in the UI; never mix it into
  real metrics unless the caller opted in (`include_simulated`).

Credentials and auth
- Secrets come from settings (`CONTEXTOS_*` env vars, `app.core.config`); never hard-code keys.
  API keys and session tokens are stored hashed (`hash_token`); a raw API key is shown once.
- Cookie-authenticated unsafe requests need `X-Requested-With: contextos` (CSRF); keep the check.
- Fail closed: an error while deciding must not turn into ALLOW.
