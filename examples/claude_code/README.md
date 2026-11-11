# Claude Code + ContextOS

Monitor what Claude Code does and enforce ContextOS policy *before* a tool runs, using Claude
Code's hooks. The hooks talk to ContextOS over HTTP only (the `contextos` SDK); nothing in your
code changes.

## Install

```bash
pip install -e sdk                          # installs the `contextos` CLI
contextos init --url http://localhost:8000 --api-key ctxk_... --claude-code
contextos doctor                            # confirms the server, the key scopes and the hooks
```

`--claude-code` merges the hooks into `.claude/settings.json` without disturbing any hooks you
already have, and keeps the original as `.claude/settings.json.contextos-backup`. Use
`--scope local` for `.claude/settings.local.json` (this machine only) or `--scope user` for
`~/.claude/settings.json` (every project). `settings.example.json` here shows the result.

The decide API key needs the `decide` scope for enforcement and `ingest` for observation.

## What each hook does

| Hook | ContextOS | Blocks? |
|------|-----------|---------|
| `PreToolUse` | `POST /decide` → `deny` / `ask`, or nothing (**never `allow`**) | **Enforced** |
| `PostToolUse` / `PostToolUseFailure` | `tool.completed` / `tool.failed` | No |
| `UserPromptSubmit` | `prompt.submitted` (or a subagent result → `agent.message`) | No |
| `SessionStart` / `SessionEnd` / `SubagentStop` | `session.started` / `session.ended` | No |

The hook only ever makes Claude Code **stricter**. On `ALLOW`/`AUDIT` it prints nothing, so Claude
Code's own permission prompt still applies; it never returns `permissionDecision: "allow"`.
`REQUIRE_APPROVAL` waits for the ContextOS Approval Centre, then allows, denies, or asks you here.
When ContextOS is unreachable the fail mode decides (`ask` by default; `closed` denies; `open`
continues with a warning). See `../../docs/integrations/claude-code.md` for the full contract.

## Live verification

`live_verify.py` runs the real backend and the real Claude Code CLI against a demo project that
contains a prompt-injection fixture (synthetic credentials, a request-capture host) and prints
what ContextOS caught. It is self-contained and cleans up after itself.

```bash
backend/.venv/bin/python examples/claude_code/live_verify.py --model haiku
```

It exits 0 when ContextOS denied an outbound call or raised an exfiltration finding. Pass `--keep`
to inspect the temp directory (database, server log, transcript, the written settings file).
