# Integration builder

> Design, build and verify a ContextOS integration adapter for an agent framework or tool protocol (a new one, or changes to the Claude Code hooks, MCP gateway or Python SDK guard) with honest enforced/advisory/observed claims, fail-closed decision mapping, redaction, spooling, tests and docs. Use when asked to integrate a new framework (Codex, Cursor, LangGraph, …), to change how a hook or gateway maps events or decisions, or to verify an adapter against a real host.

Reference implementations: `sdk/contextos/integrations/claude_code/` (hooks) and
`sdk/contextos/integrations/mcp_gateway/` (protocol proxy); `sdk/contextos/guard.py` (in-process).
Rules: `docs/engineering/integration-adapters.md`. Docs to mirror: `docs/integrations/claude-code.md`.

## 1. Research the host (write the findings down with sources and dates)
- Which interception points exist, and does each run **before** the action and let you stop it?
  Quote the host's docs for: how to deny, how to ask a human, what happens on timeout, crash,
  non-zero exit, malformed output; whether a "permit" answer skips the host's own safety checks.
- Which payload fields are available at each point (tool name, arguments, result, session id,
  parent/child agent, cwd, model)? Capture real payloads into a fixture module like
  `sdk/tests/claude_code_payloads.py` — never invent field names.
- What bypasses the boundary (direct API calls, disabled hooks, sandboxes the hook cannot see into)?

## 2. Capability table (decides every claim you will make)
| Point | ContextOS call | Mode | Can prevent? | Bypasses |
|---|---|---|---|---|
| pre-tool | `POST /decide` | enforced (only if it honours DENY/approval before execution) | yes | … |
| post-tool | `POST /events` `tool.completed`/`tool.failed` | observed | no | … |
| context read | `POST /events` `context.ingested` | observed | no | … |
A point that returns a decision the host may ignore is **advisory**. Server side, a new
integration kind is reported `advisory` until it is added to `ENFORCING_INTEGRATIONS`
(`backend/app/services/ingestion_state.py`) and to the catalogue
(`backend/app/services/integrations_catalog.py`, `status`/`best_enforcement`) — both are backend
files; if you don't own them, file the change as a request with the test evidence.

## 3. Mapping (pure, `integrations/<name>/mapping.py`)
- Host payload → `contextos.models.EventEnvelope`: `event_type` ∈ `session.started`, `session.ended`,
  `prompt.submitted`, `context.ingested`, `tool.requested`, `tool.completed`, `tool.failed`,
  `agent.delegated`, `agent.message`, `mcp.server_connected` (`backend/app/domain/enums.py:EventType`).
- Stable `event_id` per host event (idempotency), `correlation_id` linking requested ↔ completed,
  `integration="<kind>"`, `agent`, `session_id`, `parent_session_id` for delegation, `source` refs
  for context (`SourceType`). Facts only — no trust/risk/decision fields (the server rejects them).
- Results the model reads → text as the model sees it (see `claude_code/results.py`), truncated.

## 4. Decision → host answer (enforcement module)
| ContextOS | Host answer |
|---|---|
| ALLOW, AUDIT | proceed through the host's normal flow (never a "skip safety checks" answer) |
| DENY | block with a reason citing the policy (`reason`, `policy_decision_id`) |
| REQUIRE_APPROVAL | poll `GET /decide/approvals/{id}` within the time budget; approved → proceed; rejected/expired/cancelled → block; still pending → ask the human or block |
| RESTRICT | `contextos.restrictions.apply_restrictions`; any restriction not applicable/checkable → block |
| anything else | block (fail closed) |
Fail mode (server unreachable, timeout, 5xx, input too large): `closed` (default) → block, `ask`
→ ask, `open` → proceed + visible warning. Rejected/under-scoped key → block. Spool every attempt
that was not decided (`contextos.spool`) so the server records it as `observed`. Stay inside the
host's timeout with your own budget (see `MAX_DECIDE_BYTES`, `POLL_S` in the Claude Code package).

## 5. Wiring
- Client: `contextos.client.ContextOSClient`, config via `contextos.config` (env/project file);
  redaction of anything spooled or logged via `contextos.redact`.
- CLI: lazy delegate in `sdk/contextos/_cli/delegates.py` (a broken install must fail closed at the
  enforcement point, as `CLAUDE_BLOCK_EXIT` does); install/uninstall that merges host config
  without destroying user settings and keeps a backup (`claude_code/install.py`).
- `contextos doctor` should detect the integration's config and key scopes (`decide` for
  enforcement, `ingest` for observation).

## 6. Tests (`sdk/tests/test_<name>_*.py`, server faked with `sdk/tests/sdk_fakes.py`)
- mapping for every host event type, using captured payloads;
- every decision row of §4, including unknown decision → block;
- every fail mode, rejected key, oversize input, time-budget exhaustion; spool written;
- RESTRICT with an inapplicable restriction → block; masked input when masking applies;
- the adapter never emits the host's "permit/skip checks" answer (assert on output);
- redaction: a canary secret in arguments never reaches logs or the spool unredacted;
- server side (if you own it): `backend/tests/integration/test_decide_api.py`-style test that the
  new `integration` kind gets the intended `enforcement` value.
Run: `cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests`.

## 7. Live verification (enforced claims require it)
Reproduce against the real host like `examples/claude_code/live_verify.py`: temp SQLite database,
backend on 127.0.0.1 with a port in 18000-18999, real CLI, real host process. Record host version,
date, the payloads seen and the answers honoured. Stop every process you started.

## 8. Docs and examples
`docs/integrations/<name>.md` with: capability table (§2), install/uninstall, configuration, fail
modes, decision mapping, what is NOT covered, live-verification record. `examples/<name>/` with a
runnable example using `ctxk_...` placeholders and reserved domains. Update `CONTEXT.md`.

## Output
Report: capability table, files changed, test commands with counts, live-verification evidence (or
"not live-verified" — then every claim stays advisory/observed), limitations, backend requests.
