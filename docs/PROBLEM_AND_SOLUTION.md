# Problem and solution

## The problem

Agents combine three things that are each fine alone and dangerous together — the **lethal
trifecta**: exposure to untrusted content, access to private data, and a channel that can send data
out. A coding agent that reads a repository, has the developer's credentials on disk and can run
`curl` has all three.

Concretely, teams running agents cannot answer:

| Question | Why it is hard today |
|---|---|
| What did the agent read, and where did it come from? | Context arrives through dozens of tools (file reads, web fetches, MCP results, sub-agent replies) and is gone after the session. |
| Was any of it trying to instruct the agent? | Injections hide in HTML comments, `display:none` text, base64, zero-width characters, other languages, and MCP tool descriptions. |
| Did a secret leave? | The secret was in a `.env` the agent read three steps earlier; logging the secret to find out would create a second leak. |
| Could we have stopped it? | Many guardrails only observe. Claims of "blocked" are often not backed by an execution boundary. |
| What exactly happened, in order, and what would a different policy have done? | No replayable record; policy changes are tested in production. |
| Who fixes it, and is it fixed? | Findings live in a security tool; fixes live in an issue tracker with none of the evidence. |

## The solution

| Need | ContextOS feature | How it works (implemented) |
|---|---|---|
| Account for context | Context Explorer, Context Receipts | Every `context.ingested`, prompt and tool result becomes a `context_items` row: source, trust at ingest, sensitivity, detections, SHA-256 of the raw text, redacted preview, HMAC-signed receipt. |
| Know whom to trust | Trust Centre | Rules (globs on identifier/domain) plus recorded evidence classify sources and destinations; injection evidence downgrades a source to `SUSPICIOUS` even if it was trusted manually. |
| Detect manipulation | Security Intelligence | Deterministic detection over normalised views (decoded, de-obfuscated, hidden text extracted) of content and tool requests; MCP listings scanned for tool poisoning; sub-agent replies checked for cross-agent contamination; findings deduplicated and escalated to incidents. |
| Track secrets without storing them | Redaction engine | Secrets replaced by `[REDACTED:<type>:<fp8>]`; keyed fingerprints match a secret seen in context with the same secret in a later outbound call (`matched_session_fingerprints`). |
| Stop the dangerous step | Policy Studio, Approval Centre, integrations | `POST /decide` evaluates each tool call against enforce-mode policies before it runs; Claude Code hooks, the MCP gateway and `guard()` honour DENY, approvals and restrictions and fail closed on unknown answers. 13 built-in policies cover credential exfiltration, sensitive access after injection, destructive shell, agent config tampering, the trifecta and suspicious destinations. |
| See flows | Provenance Graph | Observed relationships from source to action with risky paths and whether each was prevented. |
| Investigate | Incidents, Replay Lab, Audit Log | Timelines from recorded events, evidence bundles with a SHA-256 written to the keyed audit chain, step-by-step replay, counterfactual replay as a labelled simulation over recorded inputs. |
| Test controls | Simulation Lab | Nine attack and baseline scenarios run through the real pipeline (flagged `is_simulation`), with checks and suite comparison. |
| Fix | Engineering Workspace | Tasks created from findings/incidents, deterministic fix-context prompts and context packs for coding agents, fix attempts, verification (including re-running a scenario). |

## What ContextOS does not solve

- It cannot enforce where the host offers no boundary (disabled hooks, servers not behind the
  gateway, code not wrapped by `guard()`); those paths are observed at best.
- Detection is lexical and measured, not perfect: see the blind spots in
  [DETECTION_EVALUATION.md](DETECTION_EVALUATION.md).
- Destination checks look at names and addresses; they do not verify who owns a destination.

Related: [PRODUCT_VISION.md](PRODUCT_VISION.md), [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md),
[INTEGRATION_SPECIFICATION.md](INTEGRATION_SPECIFICATION.md).
