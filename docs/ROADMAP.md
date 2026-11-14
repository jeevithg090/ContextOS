# Roadmap

Where ContextOS goes after 0.1.0. Items are planned, not shipped; the current state is in
[../CONTEXT.md](../CONTEXT.md) and the detailed backlog with impact and decisions in
[PRODUCT_IMPROVEMENTS.md](PRODUCT_IMPROVEMENTS.md) (numbers in brackets refer to it).

## Now — finish 0.1.0

- Close the wave-2 security review and the release-readiness report
  (`docs/engineering/checklists/release-readiness.md`).
- Build and run the Docker image and compose stack; fix whatever that finds [1].
- Commit the verified state and tag the release.

## Next — 0.2: coverage and scale

- **Integrations**: OpenAI Codex shipped (hooks; [integrations/codex.md](integrations/codex.md)).
  Next a native adapter for Cursor (today: wrap its MCP servers with the gateway), then LangGraph /
  OpenAI Agents SDK / Claude Agent SDK callbacks beyond `guard()` [12].
  Each ships `advisory` until tests prove an enforcing boundary.
- **MCP gateway**: remote (streamable HTTP) upstreams [9]; proxy sampling, elicitation and
  subscriptions [10]; decide the default `mcp:<server>` destination question [2].
- **Multi-replica**: shared bus for live updates and a shared sign-in limiter [3, 4].
- **Detection**: GET-query exfiltration rule [7], `echo $VAR` precision [6], sentence-window fix
  [8]; evaluate an optional classifier against the published corpus [5].
- **Operations**: automated audit-head anchoring [13], optional in-process retention schedule [15].

## Later

- Key rotation with key ids for fingerprints, receipts and the audit chain [14].
- OIDC single sign-on and MFA [16].
- Broader language coverage for multilingual rules [20]; opt-in extraction for non-text content [19].
- Sandbox or host telemetry integrations that can see which files a shell command touches [18].

## Principles that do not change

Server-side classification only; redaction before persistence; honest `enforced` / `advisory` /
`observed` claims; provenance as observed relationships; counterfactuals and Simulation Lab
results labelled as simulations; no fake data in product surfaces.
