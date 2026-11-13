# ContextOS Python SDK and CLI

`contextos` lets Python agents report what they consume to ContextOS and enforce ContextOS
policy decisions on their tools. It talks to the server over HTTP only (`/api/v1`) and never
imports server code.

- `ContextOSClient`: events, synchronous decisions, approvals, scan, read helpers
- `AgentSession`: report sessions, prompts, context, inter-agent messages, delegation
- `guard()` / `ToolGuard`: ask for a decision before a tool runs and enforce it
- `contextos` CLI: `init`, `status`, `doctor`, `flush`, `agents`, `events`, `policies`,
  `incidents`, `replay`, `simulate`, `scan`, plus `hook` (Claude Code), `codex-hook` (OpenAI Codex)
  and `mcp-gateway`

```bash
pip install -e sdk            # or: pip install -e 'sdk[mcp]' for the MCP gateway
contextos init --url http://localhost:8000 --api-key ctxk_...
contextos doctor
```

## Configuration

Each setting is resolved in this order, and the first match wins:

1. Environment: `CONTEXTOS_URL`, `CONTEXTOS_API_KEY`, `CONTEXTOS_AGENT_NAME`,
   `CONTEXTOS_FAIL_MODE` (`closed` | `open` | `ask`), `CONTEXTOS_TIMEOUT_S`,
   `CONTEXTOS_APPROVAL_TIMEOUT_S`, `CONTEXTOS_ENVIRONMENT`
2. The project file `.contextos/config.json`, searched upward from the working directory
3. The user file `~/.contextos/config.json` (set `CONTEXTOS_HOME` to use a different directory than `~/.contextos`)

`contextos init` checks the server and the key before it writes anything. It stores the API key in
the user file (mode 600) by default. Pass `--key-location project` to store the key in the
project file instead; that file is also mode 600 and `init` adds it to `.gitignore`. The key is
never printed or logged. Output shows only its prefix, for example `ctxk_abc…`.

API key scopes: `ingest` (report events; also needed to run `contextos simulate <scenario>`),
`decide` (enforcement, approval polling and withdrawal), `read` (CLI data commands and `scan`).

## Reporting a session

```python
from contextos import AgentSession, ContextOSClient

client = ContextOSClient.from_config()
with AgentSession(client) as session:            # session.started / session.ended
    session.prompt(user_request)
    session.ingest_context("web", url, page_text)  # trust + injection detection happen server-side
    session.message(text, from_agent="planner")
    child = session.child_session("researcher", task="find sources")
```

Session events are **observed**. They are reported, and nothing is blocked. The server computes
every classification: the envelope has no fields for trust, risk or decisions, and the server
rejects them if they are sent. Content longer than 200,000 characters is truncated with a marker.

## Enforcing tool calls with `guard()`

```python
from contextos import guard, ToolDenied

@guard("send_email", category_hint="email", destination="to")
def send_email(to: str, subject: str, body: str) -> str: ...

@guard("read_file", category_hint="file_read", path_args=["path"])
async def read_file(path: str) -> str: ...      # async functions work too
```

Before each call the guard sends `tool.requested` to `POST /decide` and acts on the decision:

| Decision | What the guard does |
|---|---|
| `ALLOW`, `AUDIT` | Runs the function |
| `DENY` | Raises `ToolDenied(reason, decision)`. The function is never entered |
| `REQUIRE_APPROVAL` | Polls the approval until it is decided or `approval_timeout_s` passes (default 300). Runs only if approved, otherwise raises `ToolDenied`; on a timeout the request is withdrawn (`POST /decide/approvals/{id}/cancel`) so nobody approves a call that is no longer waiting. `approval_timeout_s=0` raises `ApprovalRequired(approval_id=…)` at once and leaves the request pending for the host to wait on |
| `RESTRICT` | Applies every restriction and runs the function with the restricted arguments. If any restriction cannot be applied, raises `ToolDenied` (fail closed) |
| anything else | Raises `ToolDenied` (fail closed) |

After the call, the guard sends `tool.completed` or `tool.failed` with the result, truncated to
16,000 characters by default. Problems with this report are logged. They never change the
tool's outcome.

**What this enforcement covers:** it is real for the tools you call through the guard. A denied
function never runs. Code that calls the underlying API directly is not covered, and neither are
tools that the agent framework runs itself.

### Restrictions (`RESTRICT`)

- `redact_secrets`: the SDK masks secrets in the arguments (known token formats, private keys,
  credentials in URLs, values under credential-named keys). It then asks the server (`POST /scan`)
  to re-check the masked arguments. The call is denied if the server still finds a secret or
  cannot do the re-check. Masking applies to str, bytes, dict, list and tuple values.
- `allowed_path_globs` / `deny_path_globs`: these are checked against the call's path arguments.
  Those are the arguments named in `path_args`. Without `path_args`, the guard uses arguments with
  path-like names, `os.PathLike` values, and strings that look like paths.
  - An allowed path must match both after `..` is collapsed and after symlinks are resolved.
  - A denied path is refused if any way of writing it matches, ignoring case.
  - Tools with category `shell`, `code_execution` or `infrastructure` hide their paths inside
    commands, so path restrictions on them are always denied.
- `max_argument_bytes`: the serialised arguments must fit the limit.
- Any key the SDK does not know turns the decision into a denial.

### Fail modes (server unreachable or returning 5xx)

| `fail_mode` | Behaviour |
|---|---|
| `closed` (default) | Raises `ToolDenied` |
| `open` | Runs the tool, logs a warning and raises a `RuntimeWarning`. The event is marked `ran_without_decision` |
| `ask` | Raises `ApprovalRequired` (with `approval_id=None`), so the host can ask its user |

If the user approves after an `ask`, the host can call the original function through
`tool.__wrapped__`. That call is unguarded and is not reported.

A rejected or under-scoped key (401/403) always fails closed. In every case the attempt is saved
to the spool, so the server records it later. It is recorded as observed, not as enforced.

## Offline spool

Non-blocking events are appended to `~/.contextos/spool/<agent>.jsonl` when the server is
unreachable. They are re-sent after the next successful send, or when you run `contextos flush`.
Event ids are idempotency keys, so re-sending never creates duplicates.

- Secrets are masked before an event is written to disk.
- The spool directory is mode 700 and the files are mode 600.
- The spool holds at most 5 MiB per agent by default (`spool_max_bytes`). When it is full, new
  events are dropped and a warning is logged.
- Decisions are never spooled.

## Errors

`ContextOSError` is the base class. It has these subclasses:

- `Unreachable`: network error, timeout, or HTTP 502/503/504
- `APIError`, with two subclasses: `AuthError` (401/403) and `ServerError` (5xx)
- `ApprovalTimeout`
- `ToolDenied`, with the subclass `ApprovalRequired`

Retry rules:

- Event sends and GET requests retry with exponential backoff.
- `POST /decide` retries only when the connection never opened, so a decision is never
  requested twice.

## CLI

| Command | Purpose |
|---|---|
| `contextos init [--claude-code] [--codex]` | Write the project config after checking `/health` and the key's scopes. With `--claude-code` / `--codex`, also install the Claude Code hooks (`.claude/settings.json`) or the Codex hooks (`.codex/hooks.json`; `--scope user` for `~/.codex/hooks.json`) |
| `contextos status` | Show the active config (key masked), where each value came from, the spool, and whether the server is reachable |
| `contextos doctor` | Check the config, connectivity, key, scopes, spool size, and the Claude Code and Codex hooks (for Codex also the trust Codex recorded, `[features] hooks`, project trust and login-shell stdout) |
| `contextos flush` | Re-send spooled events now |
| `contextos agents` / `events [--session ID]` / `policies` / `incidents [--status S]` | Read commands (`--json` prints the raw response). Simulation Lab data is labelled; `agents` and `incidents` leave it out unless `--include-simulated` |
| `contextos replay <session_id>` | Print a session's recorded timeline. Takes the ContextOS id (`asn_…`) or the integration's own session id (e.g. the SDK's `ses_…`) |
| `contextos simulate --list` / `simulate <scenario_id>` | Run a Simulation Lab scenario through the real pipeline (needs `ingest` as well as `read`). Results are flagged as simulation |
| `contextos scan <path…\|->` | Run detection without storing anything. Files at sensitive paths (`.env`, keys, credentials) are not uploaded unless you pass `--force` |
| `contextos hook <Event>` | Claude Code hook entry point (Claude Code integration package) |
| `contextos codex-hook <Event>` | OpenAI Codex hook entry point; PreToolUse blocks with exit 2 ([docs/integrations/codex.md](../docs/integrations/codex.md)) |
| `contextos mcp-gateway …` | MCP gateway (MCP gateway package). Arguments are passed through |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error, or a failed check or simulation |
| 2 | Usage error |
| 3 | `scan` detected something (turn off with `--no-fail`) |

If the Claude Code or Codex hook module cannot be loaded, `contextos hook PreToolUse` /
`contextos codex-hook PreToolUse` exits with 2 and a reason on stderr, which tells the host to block
the tool call. A broken install therefore fails closed.

## Example

[`examples/python_sdk/guarded_agent.py`](../examples/python_sdk/guarded_agent.py) is a support
agent that receives an e-mail carrying a prompt-injection payload. The injection then tries to
mail out a `.env` file, and the guard enforces the server's decision on each step.

## Tests

```bash
make test-sdk                                                     # the whole SDK suite, from the repository root
cd sdk && ../backend/.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_client*.py tests/test_guard*.py tests/test_cli*.py
```

Run the SDK suite as its own pytest process, never together with `backend/tests` (both packages are
named `tests`; see `docs/DEVELOPMENT_GUIDE.md`). The Claude Code and MCP gateway adapters are
documented in `docs/integrations/claude-code.md` and `docs/integrations/mcp.md`; the cross-adapter
contract in `docs/INTEGRATION_SPECIFICATION.md`.

The tests use `httpx.MockTransport` and make no network calls. `test_client_contract.py` checks
the SDK's copy of the envelope against `backend/app/events/envelope.py` whenever the server
package can be imported.
