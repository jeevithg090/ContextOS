---
paths:
  - "sdk/contextos/**/*.py"
  - "examples/**"
  - "docs/integrations/**"
  - "backend/app/events/**/*.py"
  - "backend/app/api/routes/events.py"
  - "backend/app/services/ingestion*.py"
---

# Integration adapters (Claude Code and Codex hooks, MCP gateway, Python SDK `guard()`)

- Adapters live in `sdk/contextos/integrations/<name>/` and speak HTTP only (`POST /events`,
  `POST /decide`, `GET /decide/approvals/{id}`) through `contextos.client.ContextOSClient`.
  Never import `app.*` from `sdk/`.
- Map host payloads to `EventEnvelope` in a pure `mapping.py` (unit-tested with captured payloads,
  e.g. `sdk/tests/claude_code_payloads.py`). The envelope carries facts only — no trust, risk,
  severity or decision fields; the server rejects them (`extra="forbid"`).
- Be explicit about what is enforced. `enforced` = the decision is returned at a boundary that
  runs before the action and honours DENY/approval (Claude Code and Codex `PreToolUse`, MCP
  gateway `tools/call`, SDK `guard()`); `advisory` = returned but the host may ignore it; `observed` =
  reported after the fact. A new integration kind is `advisory` until it is added to
  `ENFORCING_INTEGRATIONS` in `backend/app/services/ingestion_state.py` with tests proving the
  boundary. Document the uncovered paths (actions that bypass the boundary).
- Claude Code hooks never emit `permissionDecision: "allow"` (it skips Claude Code's own
  permission prompt). Allowed outcomes are "no decision"; DENY → `deny`; unresolved approval →
  `ask` or `deny`. The `Verdict` in `integrations/claude_code/enforce.py` refuses `allow` — keep that guard.
- Codex hooks block only with exit 2 and a non-empty stderr reason; anything else Codex cannot parse
  (`ask`, a bare `allow`, unknown fields, a crash or timeout) lets the tool run. Never answer `ask`;
  use `allow` only together with `updatedInput` (a RESTRICT rewrite). The `Verdict` in
  `integrations/codex/enforce.py` enforces both — keep it, and keep a fail-closed exit 2 for a hook
  module that cannot load (`_cli/delegates.py`).
- RESTRICT: apply every restriction with `contextos.restrictions.apply_restrictions`; if any
  restriction cannot be applied or checked (e.g. path restrictions on an opaque tool such as `Bash`),
  DENY. Never forward an unrestricted call under a RESTRICT decision.
- Unknown decision values → DENY (fail closed).
- Fail mode when ContextOS cannot decide (unreachable, timeout, 5xx, oversized input): `closed`
  (default) → deny, `ask` → ask the human, `open` → proceed with a visible warning. An invalid or
  under-scoped API key always denies. Spool the attempt (`contextos.spool`) so the server later
  records it as `observed`. Respect the host's time budget (hooks have a hard timeout).
- Post-execution reporting (`tool.completed` / `tool.failed`, `context.ingested`) is best-effort
  and must never change the tool's outcome or raise into the host.
- Redact client-side (`contextos.redact`) before spooling or sending; never log arguments,
  results or API keys. Read keys from config/env (`contextos.config`), never from code.
- Tests (in `sdk/tests/`): mapping per hook/message type, every decision → host answer, fail modes,
  restriction failure → deny, "never allow", spool on failure. Update `docs/integrations/<name>.md`
  and `examples/<name>/` with any behaviour change.
