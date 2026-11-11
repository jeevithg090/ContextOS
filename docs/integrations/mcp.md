# MCP security gateway

`contextos mcp-gateway` runs an MCP server behind ContextOS. The host (Claude Code, Claude
Desktop, Cursor, any MCP client) starts the gateway instead of the server. The gateway starts the
real ("upstream") server as a child process and serves the same tools, resources and prompts on
its own stdin/stdout. Every `tools/call` is decided by ContextOS **before** the upstream server is
contacted.

```
host ──stdio──▶ contextos mcp-gateway ──stdio──▶ upstream MCP server
                      │
                      └──HTTP──▶ ContextOS  POST /decide (before each call)
                                            POST /events (listings, results, resources, prompts)
```

## What is enforced and what is observed

| MCP traffic | What the gateway does | Mode |
|---|---|---|
| `tools/call` | Sends `tool.requested` to `POST /decide` and applies the answer (table below). A blocked call gets an error result and **never reaches the upstream server**. | **enforced** |
| tool result | Sends `tool.completed` (or `tool.failed`) before the result goes back to the host. ContextOS records the result as context from an `mcp_tool` source (`<server>/<tool>`), caps its trust at the server's trust level and scans it for prompt injection. | observed |
| `tools/list` | Sends `mcp.server_connected` with every tool's name, description and input schema. The server instructions and the text inside input schemas (parameter descriptions, defaults, enums) are sent as listing content. ContextOS scans all of it for tool poisoning. Tools are re-exposed unchanged. If the listing changes later (a description swapped after you started trusting the server), it is reported again. | observed |
| `resources/read`, `prompts/get` | Passed through unchanged. The returned text is reported as `context.ingested` from an `mcp_server` source (`<server>/resource:<uri>`, `<server>/prompt:<name>`) and scanned. | observed |
| `resources/list`, `resources/templates/list`, `prompts/list`, `completion/complete` | Passed through unchanged (only if the upstream advertises the capability). | — |

Detection findings on listings, results and resources are evidence of manipulative content. They
do not prove the agent acted on it. The provenance edges ContextOS draws (server → listing,
invocation → returned item) are observed relationships, not causation.

### Decisions

| ContextOS answer | Gateway behaviour |
|---|---|
| `ALLOW`, `AUDIT` | Forward the call. |
| `DENY` | Do not forward. The host gets `isError: true` with `Blocked by ContextOS policy '<name>': <reason> (decision <id>). The tool was not run.` |
| `REQUIRE_APPROVAL` | Poll `GET /decide/approvals/{id}` for up to `--approval-timeout` seconds (default 300). The host gets MCP progress notifications while it waits (if it asked for them). Forward only when the approval is `approved`. Rejected, expired, cancelled or still pending means blocked. The reviewer's note is included in the message. |
| `RESTRICT` | Apply every restriction, then forward the restricted arguments. Any restriction the gateway cannot apply blocks the call (fail closed): <br>• `redact_secrets`: secrets are masked, then the masked arguments are re-checked with `POST /scan`. That needs the `read` scope; without it the call is blocked. <br>• `allowed_path_globs` / `deny_path_globs`: checked against path-like arguments. A call with a program-like argument (`command`, `cmd`, `script`, `code`, `shell`, …) is blocked, because the gateway cannot see which files it touches. <br>• `max_argument_bytes`: checked. <br>• Unknown restriction keys: blocked. |
| anything else | Blocked (fail closed). |

### When ContextOS cannot decide

| Situation | `--fail-mode closed` (default) | `--fail-mode open` |
|---|---|---|
| ContextOS unreachable, timeout, HTTP 5xx | Blocked: `Blocked by the ContextOS MCP gateway: ContextOS is unreachable (…) and the gateway fails closed.` | Forwarded **without a decision**, with a warning on stderr. |
| API key rejected or missing a scope (401/403), other 4xx | Blocked | Blocked |
| The request cannot be built (e.g. a tool name over 200 characters) | Blocked | Blocked |

In both fail modes the attempt goes to the offline spool. The spooled request has
`metadata.decision_unavailable=true` and `local_outcome` set to `not_run` or
`forwarded_without_decision`. ContextOS records it, as observed, after the next successful send.
`CONTEXTOS_FAIL_MODE=ask` (used by the SDK) means `closed` here: the gateway has nobody to ask.

## Setup

Requirements:

- The `contextos` package with the MCP extra: `pip install -e 'sdk[mcp]'`. The gateway needs the
  MCP Python SDK **2.x**; it refuses to start on 1.x and says so. The example servers run on both.
- A ContextOS API key with the scopes `ingest` and `decide`. Add `read` if you want
  `--hide-blocked-tools` or `RESTRICT` with `redact_secrets`.

Configure ContextOS once per machine or project. The key is stored with mode 0600:

```bash
contextos init            # writes ~/.contextos/config.json (url + api key), or use the variables below
export CONTEXTOS_URL=http://localhost:8000 CONTEXTOS_API_KEY=ctxk_...
```

Try it with the example servers:

```bash
contextos mcp-gateway --name toolbox -- python examples/mcp/benign_server.py
contextos mcp-gateway --name notes   -- python examples/mcp/malicious_server.py
```

`examples/mcp/malicious_server.py` is deliberately hostile but harmless:

- `add_note` has a poisoned description: an `<IMPORTANT>` block telling the model to pass
  `~/.ssh/id_rsa` as `notes`. The tool reads no files and sends nothing.
- `get_forecast` returns a weather report followed by an injected instruction to exfiltrate
  `~/.aws/credentials` to `collector.attacker.example`.
- `delete_all_notes` lets you try a DENY policy.
- The resource `notes://index` hides an instruction in an HTML comment.

### Claude Code (`.mcp.json` in the project)

```json
{
  "mcpServers": {
    "notes": {
      "command": "contextos",
      "args": ["mcp-gateway", "--name", "notes", "--agent", "claude-code", "--",
               "python", "examples/mcp/malicious_server.py"],
      "env": { "CONTEXTOS_URL": "http://localhost:8000", "CONTEXTOS_API_KEY": "${CONTEXTOS_API_KEY}" }
    }
  }
}
```

Use the same value for `--name` and the key in `mcpServers`. Claude Code then calls the tools
`mcp__notes__<tool>`, and ContextOS attributes them to the same server whether they come from the
gateway or from the Claude Code hooks.

If you also run the ContextOS `PreToolUse` hook for MCP tools, each call is decided twice: once
by the hook and once by the gateway. Both decisions are enforced and both are recorded.

### Claude Desktop (`claude_desktop_config.json`) and Cursor (`.cursor/mcp.json`)

Both use the same `mcpServers` shape. Hosts often start servers with a minimal `PATH`, so use the
absolute path from `which contextos`. Prefer `contextos init` over putting the key in the host's
config file.

```json
{
  "mcpServers": {
    "github": {
      "command": "/Users/me/.venvs/contextos/bin/contextos",
      "args": ["mcp-gateway", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }
    }
  }
}
```

Any other stdio MCP host works the same way: replace the server command with
`contextos mcp-gateway --name <name> -- <server command>`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--name NAME` | required | Server name. 1–100 letters, digits, `.`, `_`, `-`, with no `/`, `:` or `__` (those separate server and tool names, so they would attribute calls to a different server). |
| `--agent NAME` | `CONTEXTOS_AGENT_NAME`, else the host's MCP `clientInfo.name` (e.g. `claude-code`), else `mcp-client` | Agent reported to ContextOS. A key bound to an agent only accepts that agent's name. |
| `--fail-mode closed\|open` | `CONTEXTOS_FAIL_MODE`, else `closed` | See above. |
| `--approval-timeout SECONDS` | `CONTEXTOS_APPROVAL_TIMEOUT_S`, else 300 | Wait for approvals. `0` blocks immediately. Check that the host's own tool timeout is at least this long. |
| `--poll-interval SECONDS` | 2 | Approval polling interval. |
| `--session-id ID` | a new id per process | One gateway process is one ContextOS session. |
| `--hide-blocked-tools` | off | List no tools when ContextOS classifies this server's `mcp_server` source as `BLOCKED`. The gateway reads `GET /context/sources/{id}`, which needs the `read` scope. If that read fails, the tools stay listed. This only filters the listing. Every call is decided by ContextOS either way. |
| `--no-context-reports` | off | Do not report resource reads and prompts. |
| `--max-result-chars N` | 100000 | Characters of each result, resource or prompt that are reported. Longer text is cut with a visible marker, the number of omitted characters is recorded, and the cut-off part is not scanned. |
| `--startup-timeout SECONDS` | 60 | Time the upstream server has to finish MCP initialization. |
| `--cwd DIR` | the gateway's | Working directory of the upstream server. |
| `--log-level` | info | stderr only. Tool names and outcomes are logged. Arguments, results and keys never are. |

Gateway options must come before the upstream command. The upstream command starts at `--` or at
the first argument that is not a gateway option.

## Security properties

- **The upstream never sees ContextOS credentials.** The upstream server inherits the gateway's
  environment minus every `CONTEXTOS_*` variable. Other variables, such as the upstream's own
  tokens, are passed through.
- **Decide before contact.** The upstream connection is used for a `tools/call` only after a
  decision allows it. A blocked call sends nothing upstream.
- **Report before return.** Result reports go to ContextOS before the host receives the result.
  The decision on the agent's next call therefore already reflects, for example, an injection
  found in this result. Reporting failures are logged; they never change the result.
- **No secrets at rest in the gateway.** Arguments and results go only to ContextOS, which redacts
  them before persisting anything. The spool holds unsent events locally, under
  `~/.contextos/spool` with mode 0700.
- **stdout is the MCP channel.** The gateway writes only to stderr, which hosts usually log.

## Verified behaviour

Run from `backend/`:

```bash
.venv/bin/python -m pytest -q ../sdk/tests/test_mcp_gateway_mapping.py ../sdk/tests/test_mcp_gateway_enforcement.py \
  ../sdk/tests/test_mcp_gateway_proxy.py ../sdk/tests/test_mcp_gateway_cli.py ../sdk/tests/test_mcp_gateway_integration.py
```

- **Mapping (pure):** server-name rules; truncation markers and byte budgets; text of every MCP
  content block; schema-text extraction; listings split across events without losing any
  description; request/result pairing by correlation id. Every event validates against the
  server's `EventEnvelope`.
- **Enforcement:** every decision outcome; both fail modes; 401/403/422 always blocked; approvals
  (approved, rejected with note, timeout, `0`, already approved, revoked key while polling);
  RESTRICT (redaction with re-check, missing `read` scope, path globs, command arguments, unknown
  keys).
- **Proxy:** host ↔ gateway ↔ example server over the real MCP stack, in memory. Covers:
  - tools re-exposed unchanged, and changed descriptions reported again;
  - allowed calls decided first, forwarded and reported;
  - denied calls never executed upstream (checked against the example server's call log);
  - fail-closed and fail-open behaviour;
  - upstream errors reported as `tool.failed`;
  - resources and prompts reported as context;
  - `--hide-blocked-tools`, agent naming and `list_changed` relay.
- **Integration:** the real backend (uvicorn on a free port in 18000–18999, temp SQLite, seeded
  policy pack plus a DENY policy for `delete_all_notes`), the real `python -m contextos mcp-gateway`
  process and `malicious_server.py`. The test asserts against the database:
  - the `mcp_server` source `notes` exists;
  - an `MCP-POISON-001` finding exists on that source, and `add_note`'s tool record carries the
    poisoning metadata;
  - `get_forecast` was forwarded with enforcement `enforced`, completed, and its `mcp_tool` result
    has injection findings;
  - `delete_all_notes` returned `Blocked by ContextOS policy 'Deny deleting notes'`, has status
    `denied`, and never ran upstream;
  - the resource read was recorded with findings;
  - the upstream never saw a `CONTEXTOS_*` variable;
  - the gateway's stderr holds no key, arguments or results.

## Limitations

- **Server-to-client requests are not proxied.** Sampling, elicitation and roots requests from
  the upstream server get the MCP client's default "not supported" answer. So do tool calls that
  return the 2026-07-28 `input_required` result: the host receives an MCP error.
- **Subscriptions are not proxied.** That covers `resources/subscribe` and the 2026-07-28
  `subscriptions/listen` stream. `list_changed` notifications are relayed only on handshake-era
  connections.
- **Pagination is flattened.** `tools/list` is served unpaginated: the gateway reads up to 100
  upstream pages so the whole listing can be scanned. Resource and prompt lists keep the
  upstream's pagination.
- **Text-only scanning.** Images, audio and binary resources are labelled
  "not inspected by ContextOS". Tool error text (`tool.failed`) is stored redacted but is not
  scanned as context by the server.
- **Approvals stay open after a timeout.** When the gateway stops waiting, the approval stays
  pending in ContextOS. Approving it later does not run the old call; the agent must call again,
  which creates a new approval.
- **Fail open is not enforcement.** Calls forwarded under `--fail-mode open` ran without a
  decision. ContextOS shows them as observed once the spool is delivered.
- **Path restrictions are only as good as the arguments.** They can be enforced only where the
  paths are visible in the arguments. A tool that reads files it is not given cannot be checked.
- **Long text is truncated.** A tool description over 50 000 characters, and results, resources
  or prompts over `--max-result-chars`, are cut. The omitted part is not scanned.
- **Transport.** The gateway serves the host over stdio. Upstream servers must also speak stdio;
  remote HTTP MCP servers are not wrapped.
