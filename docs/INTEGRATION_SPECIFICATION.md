# Integration specification

How agent hosts talk to ContextOS: the event envelope, the decision and approval calls, what each
shipped adapter observes and enforces, how it fails, and its limits. The adapter-specific details
are in [integrations/claude-code.md](integrations/claude-code.md),
[integrations/codex.md](integrations/codex.md), [integrations/mcp.md](integrations/mcp.md) and
[../sdk/README.md](../sdk/README.md); this document
is the cross-adapter contract. Building a new adapter: `.claude/skills/integration-builder/SKILL.md`.

## Transport and authentication

- HTTPS (or `http://127.0.0.1` locally) to `/api/v1`, JSON bodies.
- `Authorization: Bearer ctxk_…` — an API key created in Settings → API keys or with
  `contextos-server create-api-key`. Scopes:

  | Scope | Allows |
  |---|---|
  | `ingest` | `POST /events`; starting Simulation Lab runs from the CLI (`POST /simulations/runs`, `/suites`) |
  | `decide` | `POST /decide`, `GET /decide/approvals/{id}`, `POST /decide/approvals/{id}/cancel` |
  | `read` | every read endpoint and `POST /scan` (the CLI data commands, the SDK's RESTRICT re-check) |

- The organisation comes from the key, never from the payload. A key bound to an agent
  (`--agent` / Settings) may only report events for that agent's name (`403 attribution_rejected`).
- Errors use the uniform envelope `{"error": {"code", "message", "details"}}`.

## Event envelope (`backend/app/events/envelope.py`, schema version `1.0`)

Every model is strict (`extra="forbid"`): unknown fields — including any attempt to send trust,
risk, severity, enforcement or a decision — are rejected with 422. ContextOS computes all
classifications server-side. Strings are capped at 200 000 characters.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `event_id` | id (`^[A-Za-z0-9_.:\-]{1,128}$`) | yes | client-generated idempotency key; unique per organisation |
| `event_type` | enum | yes | see the table below |
| `schema_version` | `"1.0"` | default | |
| `timestamp` | datetime | yes | client-observed time (display only; server time is authoritative) |
| `agent` | `AgentRef` {`name`, `framework`=`custom`, `version`, `environment`} | yes | auto-registers the agent by name |
| `session_id` | id | yes | the integration's own session id |
| `parent_session_id` | id | no | links a delegated session to its parent |
| `correlation_id` | ≤ 200 chars | no | pairs `tool.requested` with `tool.completed`/`tool.failed` |
| `integration` | ≤ 64 chars | no | `claude_code`, `openai_codex`, `mcp_gateway`, `python_sdk`, or anything else (default `custom`) — decides the enforcement claim |
| `collected_via` | ≤ 200 chars | no | which hook/callback observed it, e.g. `claude_code:PostToolUse:WebFetch` |
| `source` | `SourceRef` {`type` (`SourceType`), `identifier` ≤ 2048, `display_name`, `metadata`} | per type | where context came from |
| `tool` | `ToolRef` {`name`, `provider`=`unknown`, `server`, `category_hint`, `description`} | per type | `category_hint` is recorded for comparison only; the server classifies the tool |
| `destination` | `DestinationRef` {`kind` (`domain`/`ip`/`email`/`service`/`agent`/`unknown`), `identifier`} | no | explicit outbound destination (otherwise extracted from arguments) |
| `content`, `content_type` | text, ≤ 64 chars | per type | context text to inspect (redacted before persistence) |
| `arguments` | object | no | tool arguments (redacted and fingerprinted server-side) |
| `result`, `is_error` | text / object / list, bool | no | tool result as the model reads it |
| `delegation` | `DelegationRef` {`child_agent`, `child_session_id`, `task`} | per type | |
| `message` | `MessageRef` {`from_agent`, `from_session_id`, `to_agent`, `content`} | per type | |
| `metadata` | object | no | integration facts (e.g. `subagent_id`, `decision_unavailable`, `local_outcome`, `approved_at_host_prompt`) |

| `event_type` | Required fields | Typical sender |
|---|---|---|
| `session.started`, `session.ended` | — | all |
| `prompt.submitted` | `content` | Claude Code and Codex `UserPromptSubmit`, SDK `AgentSession.prompt` |
| `context.ingested` | `source`, `content` | SDK `ingest_context`, gateway resources/prompts |
| `tool.requested` | `tool` | `/decide` before the call (or `/events` when observed only / spooled) |
| `tool.completed`, `tool.failed` | `tool` | after the call |
| `agent.delegated` | `delegation` | Claude Code `Agent`/`Task`, Codex `spawn_agent`, SDK `child_session` |
| `agent.message` | `message` | subagent results, a Codex sub-agent's task, SDK `message` |
| `mcp.server_connected` | `source` (`mcp_server`) | gateway after `tools/list` (tool descriptions and schemas in `metadata`) |

Limits: `POST /events` takes 1–500 events per batch; each event's serialised size must fit
`CONTEXTOS_MAX_EVENT_BYTES` (default 512 000) — larger events get `status: "rejected"`, and on
`/decide` HTTP 413. A request body over 4× the limit is refused with 413 before authentication.
The SDK truncates content over 200 000 characters with a visible marker.

## Endpoints an integration uses

| Call | Returns | Notes |
|---|---|---|
| `POST /events` `{"events": [...]}` | `{"results": [EventResult]}` | per event: `accepted` / `duplicate` / `rejected` (+ `error`), `ingested_event_id`, `refs` (ids produced: `context_item_ids`, `source_ids`, `finding_ids`, `incident_ids`, `tool_invocation_id`, `policy_decision_id`, `approval_id`, `destination_id`, `child_session_id`, and for `mcp.server_connected` `source_trust_level` and `poisoned_tool_ids`). Always **observed**. |
| `POST /decide` (one `tool.requested` envelope) | `DecisionResponse` | `decision`, `enforcement`, `reason`, `policy_decision_id`, `tool_invocation_id`, `approval_id`, `approval_status`, `matched_policies`, `restrictions`, `risk`. A duplicate `event_id` returns the original decision (safe retry). Pipeline failure → 500 `decision_failed`: apply the fail mode. |
| `GET /decide/approvals/{id}` | `ApprovalPollOut` {`approval_id`, `status`, `decided_at`, `decision_note`, `expires_at`} | poll until not `pending` |
| `POST /decide/approvals/{id}/cancel` `{"reason"?}` | `ApprovalPollOut` | withdraw an approval the integration stopped waiting for; idempotent; 409 (with `details.status`) once a person decided it or it expired. The held call is recorded as cancelled. |
| `POST /scan` `{"content", "source_type"?, "content_type"?}` | `ScanOut` {`detection`, `hits`, `secrets` [{`type`, `start`, `end`, `confidence`}], `sensitivity`, `content_length`, `content_sha256`, `redacted_preview`} | nothing stored; secret values and fingerprints are never returned. Needs `read`. |
| `GET /health` | `{"status": "ok"}` | no auth |

## Decisions and the honest enforcement claim

`decision` is one of `ALLOW`, `AUDIT`, `RESTRICT`, `REQUIRE_APPROVAL`, `DENY`. `enforcement` is the
server's claim: `enforced` only for `/decide` calls from `claude_code`, `openai_codex`,
`mcp_gateway` or `python_sdk` (`ENFORCING_INTEGRATIONS`), `advisory` for `/decide` from any other integration name,
`observed` for everything sent to `/events`. A new adapter stays `advisory` until it is added to
that set with tests proving the boundary.

Every adapter must:

- run the tool only on `ALLOW`/`AUDIT`, an approved approval, or a RESTRICT whose every restriction
  it applied (`contextos.restrictions.apply_restrictions`); otherwise block;
- treat an unknown decision value as DENY;
- report the result afterwards (`tool.completed`/`tool.failed`, best effort — never changing the
  tool's outcome);
- spool what it could not send (`~/.contextos/spool`, redacted client-side) so the server records
  it later as observed.

RESTRICT keys: `redact_secrets` (mask, then re-check with `POST /scan`), `allowed_path_globs`,
`deny_path_globs`, `max_argument_bytes`. Path restrictions on tools whose paths are hidden in a
command (`shell`, `code_execution`, `infrastructure`, or a program-like argument) cannot be checked
and therefore deny.

## Capability matrix

The same data is served by `GET /api/v1/integrations` (catalogue in
`backend/app/services/integrations_catalog.py`) and shown on the Integrations page.

| Integration (`integration`) | Enforced (before the action) | Observed (after the fact) | Not covered |
|---|---|---|---|
| Claude Code hooks (`claude_code`) | `PreToolUse` → `/decide`: DENY → `deny`; REQUIRE_APPROVAL → wait, then no decision / `deny` / `ask`; RESTRICT `redact_secrets` → `ask` with masked input; other restrictions checked or `deny` | `SessionStart`, `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure`, `SubagentStop`, `SessionEnd` | disabled hooks (`disableAllHooks`, `--settings`, `--bare`, untrusted workspace); anything done without a tool call; files a shell command touches. The hook never answers `allow`, so it can only make Claude Code stricter. |
| OpenAI Codex hooks (`openai_codex`) | `PreToolUse` → `/decide` for `Bash`, `apply_patch`, `mcp__<server>__<tool>`, `spawn_agent` and other function tools: DENY → exit 2 (blocked); REQUIRE_APPROVAL → wait, then continue or block (Codex cannot ask); RESTRICT `redact_secrets` → `allow` + masked `updatedInput`; other restrictions checked or block | `SessionStart`, `UserPromptSubmit` (a sub-agent's task → `agent.message`), `PostToolUse` (successful calls only), `SubagentStop`, `SessionEnd` | hosted tools (web search); `write_stdin` into a running command; hooks Codex does not run (untrusted/modified in `/hooks`, `[features] hooks = false`); results of failed calls; another hook rewriting the input. The hook never grants approval, so Codex's own approval policy and sandbox still apply. |
| MCP gateway (`mcp_gateway`) | `tools/call` → `/decide` before the upstream server is contacted | `tools/list` (`mcp.server_connected`, poisoning scan), tool results, `resources/read`, `prompts/get` | other MCP servers the host talks to directly; sampling/elicitation/roots requests; subscriptions; remote (HTTP) upstreams |
| Python SDK `guard()` (`python_sdk`) | each guarded function call → `/decide` | `AgentSession` events (sessions, prompts, context, messages, delegation), tool results | code that calls the underlying API directly; tools the framework runs itself |
| Any other HTTP client | — (decisions are `advisory`) | whatever it sends to `/events` | everything it does not report |
| Planned: Cursor | — | — | no native adapter; interim path: wrap its MCP servers with the gateway |
| Planned: LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK | — | — | no native adapter; interim path: wrap Python tool functions with `guard()` (stdio MCP servers via the gateway) |

An integration counts as **connected** while ContextOS received an event from it in the last 24
hours (`stale_after_hours: 24` in `GET /integrations`); otherwise it is `stale`.

## Fail modes (ContextOS unreachable, timeout, 5xx, oversized input)

| Adapter | Setting | Default | `closed` | `ask` | `open` |
|---|---|---|---|---|---|
| Claude Code hook | `claude_code.fail_mode` / `CONTEXTOS_HOOK_FAIL_MODE` | `ask` | `deny` | `ask` (Claude Code's own prompt; headless `-p` treats it as a denial) | no decision + warning |
| Codex hook | `codex.fail_mode` / `CONTEXTOS_CODEX_FAIL_MODE` | `closed` | blocked (exit 2) | treated as `closed` (Codex hooks cannot ask) | continues without a decision, `systemMessage` warning |
| MCP gateway | `--fail-mode` / `CONTEXTOS_FAIL_MODE` | `closed` | error result, not forwarded | treated as `closed` | forwarded without a decision, warning on stderr |
| SDK `guard()` | `fail_mode` / `CONTEXTOS_FAIL_MODE` | `closed` | raises `ToolDenied` | raises `ApprovalRequired(approval_id=None)` | runs, logs a warning, raises a `RuntimeWarning` |

In every adapter an invalid, revoked or under-scoped key (401/403) always blocks, and the attempt is
spooled with `metadata.decision_unavailable=true` so the server records it as observed. The
organisation's `fail_mode` setting is used as the default in generated setup steps; each
integration applies its own setting locally (ContextOS cannot answer while unreachable).

## Approvals

`REQUIRE_APPROVAL` creates an `Approval` (expires after the organisation's `approval_timeout_s`,
default 600 s). The adapter polls `GET /decide/approvals/{id}` and proceeds only on `approved`.
When it stops waiting — hook budget (`approval_wait_s`, default 45 s, Claude Code and Codex), gateway
`--approval-timeout` (default 300 s), SDK `approval_timeout_s` (default 300 s), or the MCP host
cancelling the call — it withdraws the request with `POST /decide/approvals/{id}/cancel`, so a
reviewer cannot approve a call nothing is waiting for. If a person decided it a moment earlier,
the 409 carries that status and the adapter acts on it. If the server cannot be reached the
approval stays pending until it expires. An approval belongs to one call; a retry is a new request.

## Redaction and privacy on the client

The server redacts everything before persistence; adapters add defence in depth: the SDK masks
secrets before spooling (`contextos/redact.py`), hooks and the gateway never log arguments,
results or keys, the gateway strips every `CONTEXTOS_*` variable from the upstream server's
environment, and keys are read from `~/.contextos/config.json` (mode 600), the project
`.contextos/config.json` or environment variables.

## Verification

- `make test-sdk` — mapping per hook/message type, every decision → host answer, fail modes,
  restriction failure → deny, "never allow", spool on failure, envelope contract against the server
  model (`sdk/tests/test_client_contract.py`).
- `backend/tests/e2e/test_live_hooks.py`, `test_live_codex.py`, `test_live_mcp_gateway.py`,
  `test_live_sdk_guard.py`, `test_live_cli.py` — a real `contextos-server` process and the real
  adapters as subprocesses (part of `make test-backend`). `test_live_codex.py` also drives the real
  Codex binary with a scripted offline model when one is installed (skipped otherwise).
- Live records: [integrations/claude-code.md](integrations/claude-code.md#live-verification),
  [integrations/codex.md](integrations/codex.md#live-verification).
