# OpenAI Codex + ContextOS

Monitor what the Codex CLI does and enforce ContextOS policy *before* a tool runs, using Codex's
hooks. The hooks talk to ContextOS over HTTP only (the `contextos` SDK); nothing in your code
changes.

## Install

```bash
pip install -e sdk                          # installs the `contextos` CLI
contextos init --url http://localhost:8000 --api-key ctxk_... --codex
codex                                       # in the project: open /hooks and trust the ContextOS hooks
contextos doctor                            # server, key scopes, and whether Codex will run the hooks
```

`--codex` merges the hooks into `.codex/hooks.json` without moving any hooks you already have, and
keeps the original as `.codex/hooks.json.contextos-backup`. Use `--scope user` for
`~/.codex/hooks.json` (every project; `CODEX_HOME` is honoured). `hooks.example.json` here shows
the result.

Codex runs a hook only after you have reviewed and trusted it (`/hooks`); trust is pinned to the
hook's definition, so trust them again after re-running the installer. Project hooks also need
Codex to trust the project. The API key needs the `decide` scope for enforcement and `ingest` for
observation (`read` lets RESTRICT re-check masked secrets).

## What each hook does

| Hook | ContextOS | Blocks? |
|------|-----------|---------|
| `PreToolUse` | `POST /decide` → exit 2 with the reason on stderr, or nothing | **Enforced** |
| `PostToolUse` | `tool.completed` (Codex has no hook for failed calls) | No |
| `UserPromptSubmit` | `prompt.submitted` (a sub-agent's task → `agent.message`) | No |
| `SessionStart` / `SessionEnd` / `SubagentStop` | `session.started` / `session.ended` | No |

On `ALLOW`/`AUDIT` the hook prints nothing, so Codex's own approval policy and sandbox still apply.
It never answers `ask` (Codex does not support it in PreToolUse) and uses `allow` only to hand back
a RESTRICT-masked input. `REQUIRE_APPROVAL` waits for the ContextOS Approval Centre; still undecided
at the timeout, the call is blocked. When ContextOS is unreachable the fail mode decides (`closed`
by default; `open` continues with a warning). Full contract and limitations:
[`../../docs/integrations/codex.md`](../../docs/integrations/codex.md).

## MCP servers

The hook already decides every MCP tool call (`mcp__<server>__<tool>`). To add the gateway's
protocol-level checks for a stdio server, start it through `contextos mcp-gateway` in
`~/.codex/config.toml`:

```toml
[mcp_servers.toolbox]
command = "/path/to/contextos"
args = ["mcp-gateway", "--name", "toolbox", "--", "python", "examples/mcp/benign_server.py"]
env = { CONTEXTOS_URL = "http://localhost:8000" }
```

## Live verification (offline)

`live_verify.py` runs a real `contextos-server` and the **real Codex binary** against a demo project
with a prompt-injection fixture and a synthetic token. The model is `fake_model_server.py`, a
scripted Responses API on 127.0.0.1, so no OpenAI account is used and every step is fixed: read the
README, try to read `.env`, try to send the token out with `curl`, write a file with `apply_patch`,
call an MCP tool through the gateway, start a sub-agent and wait for it.

```bash
backend/.venv/bin/python examples/codex/live_verify.py [--codex /path/to/codex] [--keep]
```

It prints what the model received for each call, every ContextOS decision with its enforcement and
the findings, and exits 0 when Codex blocked the `.env` read and the exfiltration (the command's
`touch exfil-ran.txt` never ran), ran the allowed calls, and every decision was `enforced`. Your own
`~/.codex` is never touched (a throw-away `CODEX_HOME` is used).
