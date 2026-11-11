# Python SDK example: a guarded agent

`guarded_agent.py` is a support-triage "agent" with a fixed plan (no LLM, so every run is the
same). It receives a customer e-mail that carries a hidden prompt-injection payload, reads its
refund policy, replies to the customer, and then attempts what the injection asked for: mailing its
workspace's `.env` (a fake credential generated at runtime) to an outside address.

Both tools are wrapped with `@guard` (`contextos.guard`), so ContextOS decides each call **before**
it runs and the SDK enforces the decision (`enforced`): a denied tool is never entered. The tools
are harmless — files come from a temporary workspace and e-mails are written as `.eml` files to a
local outbox instead of being sent.

## Run

The server must be running and the key needs the `ingest` and `decide` scopes:

```bash
export CONTEXTOS_URL=http://127.0.0.1:8000 CONTEXTOS_API_KEY=ctxk_...
backend/.venv/bin/python examples/python_sdk/guarded_agent.py
```

With the built-in policy pack, an outbound e-mail after injected content needs approval: open the
Approval Centre and approve the reply, reject the leak. The guard polls (`approval_timeout_s`,
default 300 s) and runs only what was approved — the outbox gets the reply and never the `.env`.
If the server is unreachable, the default fail mode `closed` denies every call; the attempts are
spooled and reported later as observed.

`backend/tests/e2e/test_live_sdk_guard.py` runs this example as a subprocess against a real
`contextos-server` and checks exactly that outcome. SDK reference: [../../sdk/README.md](../../sdk/README.md).
