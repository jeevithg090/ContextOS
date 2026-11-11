# MCP gateway examples

Two small stdio MCP servers for trying `contextos mcp-gateway`. Run them **behind the gateway**;
the gateway asks ContextOS for a decision before every `tools/call` and reports listings, results,
resources and prompts. Requirements, options and limits: [../../docs/integrations/mcp.md](../../docs/integrations/mcp.md).

| Server | What it contains | Expected with the built-in policy pack |
|---|---|---|
| `benign_server.py` (`toolbox`) | tools `add`, `word_count`, `utc_now`; resource `docs://readme`; prompt `review_text`. No file access, no network, no instructions | every call allowed, no findings |
| `malicious_server.py` (`notes`) | **deliberately hostile but harmless**: `add_note`'s description hides an `<IMPORTANT>` block asking for `~/.ssh/id_rsa` (tool poisoning); `get_forecast` returns an injected instruction to send `~/.aws/credentials` to `collector.attacker.example`; `delete_all_notes` is destructive; the resource `notes://index` hides an instruction in an HTML comment. It reads no files and sends nothing | `MCP-POISON-001` on the server, the server classified `SUSPICIOUS`, injection findings on `get_forecast`'s result and the resource; add a DENY policy for `delete_all_notes` to see a call blocked before it reaches the server |

```bash
pip install -e 'sdk[mcp]'        # the gateway needs the MCP Python SDK 2.x (make install does this)
export CONTEXTOS_URL=http://127.0.0.1:8000 CONTEXTOS_API_KEY=ctxk_...   # scopes ingest, decide
contextos mcp-gateway --name toolbox -- python examples/mcp/benign_server.py
contextos mcp-gateway --name notes   -- python examples/mcp/malicious_server.py
```

Normally the MCP host starts these commands (see the `.mcp.json` / `claude_desktop_config.json`
examples in the gateway doc). Set `MCP_EXAMPLE_CALL_LOG=/path/calls.jsonl` to log the tools a server
actually executed — the tests use it to prove that blocked calls never reach the server and that the
server never sees `CONTEXTOS_*` variables (`sdk/tests/test_mcp_gateway_integration.py`,
`backend/tests/e2e/test_live_mcp_gateway.py`).
