# Product improvements

Known limitations and opportunities, each traced to the code or doc that reports it. Priority:
**P1** next milestone, **P2** soon, **P3** when demand appears. Complexity: S (days), M (1–2
weeks), L (more). Status: `open`, `decided`, `deferred`, `done`.

## Open and deferred

| # | Opportunity | Problem today | Impact | Complexity | Priority | Decision | Status |
|---|---|---|---|---|---|---|---|
| 1 | Verify the Docker image and compose stack | `Dockerfile` and `docker-compose.yml` exist but were never built or run (no Docker on the build machine) | Deployment path unproven | S | P1 | Build and run on a machine with Docker; record the result in `CONTEXT.md` | open |
| 2 | Default destination for MCP tool calls | MCP tool calls have no default `mcp:<server>` destination; credential flows into an MCP tool are not "outbound" for destination policies | A poisoned server could receive data without a destination check | M | P2 | Deferred: a default destination would make every local MCP server count as outbound and trip trifecta/approval policies. Mitigation shipped: built-in "Deny credentials in tool arguments after prompt injection" | deferred |
| 3 | Shared live-update bus | `app/events/bus.py` is in-process; SSE reaches only browsers on the same process | Blocks horizontal scaling of the API | M | P2 | Introduce Redis/NATS when more than one replica is needed (ADR-004) | open |
| 4 | Shared sign-in rate limiter | Failure counters in `services/auth_service.py` live in process memory | Limits reset on restart and are per replica | S | P2 | Move to the database or the shared bus together with #3 | open |
| 5 | Semantic detection | Lexical rules miss paraphrased instructions without trigger vocabulary (23 of 25 test false negatives, `coer-02`); `register_classifier` hook exists but no classifier ships | Missed injections | L | P2 | Keep rules as the primary, explainable control; evaluate an optional classifier on the same corpus before enabling it | open |
| 6 | Tool-request precision | 0.850 on the test split (target 0.90); `echo $VAR` is flagged high for ordinary variables (`echo $PATH`) | False positives on harmless shell commands | S | P2 | Distinguish secret-like variable names from ordinary ones; re-measure | open |
| 7 | GET-based exfiltration | Data in a fetched URL's query string (`tr-exf-04`) has no tool rule; only destination checks apply | Exfiltration to a non-suspicious host via GET is not flagged | M | P2 | Add a tool rule for secret fingerprints / high-entropy values in query strings | open |
| 8 | Category accuracy across sentence boundaries | Regex windows stop at a period, so "send the contents of the `.env` file to <url>" is `credential_access` but not `exfiltration` | Weaker categorisation (all 23 test category errors) | S | P3 | Allow file-name periods inside rule windows | open |
| 9 | Remote (HTTP) MCP upstreams | The gateway wraps stdio servers only | Remote MCP servers cannot be enforced | M | P2 | Add a streamable-HTTP upstream transport to the gateway | open |
| 10 | Server-to-client MCP requests | Sampling, elicitation, roots and subscriptions are not proxied; `input_required` results become errors | Some MCP servers lose features behind the gateway | M | P3 | Proxy them with the same reporting rules | open |
| 11 | Claude Code `ToolSearch` classification | Classified as a generic `search` tool (name heuristic); it only loads deferred tool definitions | Its results appear as search context | S | P3 | Add `ToolSearch` to `engines/risk/tool_names.py` | open |
| 12 | Native adapters for planned integrations | Cursor, LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK are `planned` in the catalogue; only interim paths (gateway, `guard()`) exist (OpenAI Codex shipped as hooks, 2026-11-13) | Their own tool calls are not covered | L | P2 | Build through `.claude/skills/integration-builder`; each stays `advisory` until its boundary is proven | open |
| 13 | Automated audit-head anchoring | Exporting `audit_head_hash` to write-once storage is a manual step | An attacker with DB and secret can rewrite the chain undetected | S | P2 | Scheduled export command or webhook | open |
| 14 | Secret key rotation | `CONTEXTOS_SECRET_KEY` keys fingerprints, receipts and the audit chain; rotating it invalidates all three | Rotation is effectively impossible without losing verifiability | M | P2 | Key ids on fingerprints/receipts/chain entries and a keyring | open |
| 15 | Built-in retention scheduling | `contextos-server purge` must be scheduled externally | Data may outlive the retention setting if nobody schedules it | S | P3 | Document (done); optional in-process daily job for single-node installs | open |
| 16 | SSO and MFA | Local email/password accounts only | Enterprise adoption | M | P2 | OIDC sign-in, then MFA for local accounts | open |
| 17 | Approvals when the server is unreachable | If an adapter cannot reach ContextOS to withdraw an approval, the request stays pending until it expires | A reviewer may approve a call that no longer waits (approving it runs nothing) | S | P3 | Accept; the approval timeout bounds it | decided |
| 18 | Opaque tool coverage | Files a shell command or opaque MCP tool touches are not visible in its arguments; path RESTRICTs on such tools deny | Coarse control for shell tools | L | P3 | Keep fail-closed behaviour; consider sandbox telemetry integrations | decided |
| 19 | Non-text content | Images, audio and binary resources are labelled "not inspected"; text over the size caps is truncated and the remainder not scanned | Injections in images or very long text are missed | M | P3 | Document; consider OCR/extraction as an opt-in | open |
| 20 | Detection outside 13 languages | Multilingual rules cover override, credential and exfiltration families in 13 languages only | Attacks in other languages are missed unless decoding exposes English | M | P3 | Extend `_ML` families with evaluation samples | open |
| 21 | Page-level render tests and a signed-in click-through | 17 of 29 pages (`AgentsPage`, `PolicyStudioPage`, `ApprovalCentrePage`, `ReplayLabPage`, `SettingsPage`, the workspace boards/tasks pages, …) have no Vitest test that renders the page (their components are tested); for 0.1.0 the signed-in UI was walked by hand in a browser (every nav page, 1280 px and 375 px), which is not repeatable | A wiring error between a page and its components would reach users unnoticed | S | P2 | Add one render test per page (loading, error, empty, data) and a scripted browser walk over every nav item before each release | open |
| 22 | Route-audit noise | `route_audit.py` reports `GET /stream` (isolation tested in process, not over HTTP) and two global catalogue routes (`/simulations/scenarios/{id}`, `/integrations/{kind}/setup`) as gaps | Real gaps are harder to spot in the report | S | P3 | Add an HTTP-level cross-org `/stream` test and an allowlist of non-org catalogue routes to the audit script | open |

## Done in this release

| Item | Change | Evidence |
|---|---|---|
| Credentials passed to a tool after prompt injection | New built-in DENY policy "Deny credentials in tool arguments after prompt injection" (`builtin.deny-secrets-to-tools-after-injection`) | Found by Simulation Lab `poisoned-mcp-server` / `malicious-web-page`; scenario checks pass |
| Outbound calls after prompt injection | New built-in REQUIRE_APPROVAL policy "Require approval for outbound calls after prompt injection" (`builtin.approve-outbound-after-injection`) | Same scenarios; checks pass |
| Approvals left pending after an adapter stopped waiting | `POST /decide/approvals/{id}/cancel`; the Claude Code hook, MCP gateway and `guard()` withdraw requests | SDK tests; [INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md#approvals) |
| Approved at Claude Code's own prompt reported as "decision not honoured" | Server recognises `approved_at_host_prompt` for held approvals and raises the low-severity `CTX-APPROVED-AT-HOST-PROMPT` instead | `services/ingestion_results.py` |
| `--hide-blocked-tools` needed the `read` scope | Gateway reads `refs.source_trust_level` from the `mcp.server_connected` result | `mcp_gateway/proxy.py` |
| Simulated traffic inflated real counters | `Tool.invocation_count` and destination transfer counters ignore simulated calls | `ingestion_entities.py`, `ingestion_tools.py` |
| SSH public keys treated as secrets | `~/.ssh/*.pub` is no longer a sensitive path | `engines/redaction/paths.py` |
| Tool error text not scanned | Failed tool output is recorded and scanned as context | `services/ingestion_results.py` |
| Exfiltration remediation overstated | The advice for `exfiltration` findings said "treat the credential as compromised" even when only an instruction was found in content; it now asks the reader to check whether data left first | `services/ingestion_findings.py`; `test_findings_api.py::test_exfiltration_remediation_does_not_assume_data_left` |

Related: [ROADMAP.md](ROADMAP.md), [../CONTEXT.md](../CONTEXT.md).
