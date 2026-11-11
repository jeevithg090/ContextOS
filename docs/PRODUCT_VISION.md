# Product vision

## Vision

Autonomous agents read the world and act on it. ContextOS makes that safe to operate: every piece
of context an agent consumes is accounted for, every sensitive action is decided by policy at a
boundary the agent cannot talk its way past, and every incident can be reconstructed from
records — stated with exactly as much certainty as the evidence supports.

## Who it is for

- **Security teams** who must answer "what did our agents read, what did they try to do, and what
  stopped them?" — and prove it with an audit trail.
- **Platform and engineering teams** who run coding and operations agents (Claude Code, MCP-based
  tools, custom Python agents) and need guardrails that do not depend on the model behaving.
- **Engineers fixing what was found**, who need the evidence and context handed to them (or to a
  coding agent) in one place.

## Principles

1. **Context is the attack surface.** Prompt injection arrives in files, web pages, tool results,
   MCP tool descriptions and other agents' replies. ContextOS records each as a receipt with its
   source and trust level, and treats untrusted content as data, never as instructions.
2. **Decide before the action, where the host allows it.** Enforcement happens at real execution
   boundaries (Claude Code `PreToolUse`, the MCP gateway's `tools/call`, the SDK's `guard()`).
   Everything else is labelled `advisory` or `observed`; the product never claims to have blocked
   what it only saw.
3. **The server classifies.** Integrations report facts; trust, risk, severity and decisions are
   computed server-side and cannot be supplied by a client.
4. **Never keep the secret.** Raw content and credentials are redacted before anything is stored;
   keyed fingerprints let ContextOS recognise the same secret leaving later without holding it.
5. **Honest evidence.** Provenance edges are observed relationships, not causation. Counterfactual
   replay is a simulation over recorded inputs. Simulation Lab data is flagged and kept out of real
   metrics. Detection quality is measured on a published corpus, including its blind spots.
6. **From finding to fix.** A finding is not done when it is triaged; the Engineering Workspace
   tracks the fix, generates the context a coding agent needs and verifies the result.

## What success looks like

- A team installs the Claude Code hooks in minutes and sees sessions, context and decisions live.
- A malicious README, web page or poisoned MCP server is flagged on arrival, and the follow-up
  credential read or outbound call is denied or held for a human before it runs.
- An investigator opens an incident and gets a timeline, the evidence, a verifiable export and a
  replay — without anyone having stored the leaked secret.
- Policy changes are tested against recorded decisions and Simulation Lab suites before they ship.

## Non-goals (today)

- Being the model's alignment layer: ContextOS does not rewrite prompts or judge model reasoning.
- Network-level data-loss prevention: destinations are assessed by name/address, without DNS or
  connections, and only for calls that pass through an integration.
- Hosting or calling AI models: the fix-context generator is deterministic and makes no external
  AI calls.

Related: [PROBLEM_AND_SOLUTION.md](PROBLEM_AND_SOLUTION.md), [PRODUCT_SPECIFICATION.md](PRODUCT_SPECIFICATION.md),
[ROADMAP.md](ROADMAP.md).
