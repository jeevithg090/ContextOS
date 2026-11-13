"""``contextos codex-hook <EventName>``: the command Codex runs for each hook event.

Codex starts the command through ``$SHELL -lc`` in the turn's working directory, writes the hook
payload as JSON on stdin and reads stdout, stderr and the exit code (see docs/integrations/codex.md
for the verified contract):

- ``PreToolUse`` is the enforcement point. To block, the hook exits 2 with the reason on stderr.
  To continue it exits 0 and prints nothing, or — to hand back a RESTRICT-masked input, or a
  fail-open warning — prints one JSON object. It never answers ``ask`` (unsupported by Codex) and
  uses ``allow`` only together with ``updatedInput``. It always answers within its own budget (hook
  timeout minus a margin): a hook Codex has to kill counts as failed and the tool would run.
- Every other event is observation only: the hook reports the event, never blocks, prints nothing
  (plain stdout on SessionStart and UserPromptSubmit would be added to the model's context) and
  exits 0. Events that cannot be delivered go to the offline spool and are re-sent later.
  ``SessionEnd`` has at most 3 s in Codex, so its event is spooled first and then flushed.

Diagnostics go to stderr only when ``CONTEXTOS_DEBUG=1``; tool input and secrets are never printed.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from collections.abc import Callable, Mapping
from typing import IO

from contextos.client import ContextOSClient
from contextos.config import ConfigError
from contextos.errors import ContextOSError
from contextos.integrations.hookkit import (
    configure_logging,
    is_debug,
    read_stdin,
    run_with_budget,
)

from . import mapping, observe
from .config import (
    EVENT_BUDGET_S,
    MAX_STDIN_BYTES,
    SESSION_END_BUDGET_S,
    CodexHookConfig,
    fail_mode_from_env,
    load_hook_config,
    project_dir_for,
)
from .enforce import BLOCK_EXIT, PreToolUseEnforcer, Verdict, fail_mode_verdict
from .mapping import HookInput, PayloadError

log = logging.getLogger("contextos.codex")

ClientFactory = Callable[[CodexHookConfig, float], ContextOSClient]


def default_client(cfg: CodexHookConfig, budget_s: float) -> ContextOSClient:
    """Client for one hook process: short timeouts that fit the budget, one retry, per-agent spool."""
    timeout = max(1.0, min(cfg.base.timeout_s, budget_s / 2))
    return ContextOSClient(
        cfg.base.url, cfg.base.api_key, timeout=timeout,
        agent=mapping.agent_ref(cfg.agent_name, cfg.base.environment),
        integration=mapping.INTEGRATION, spool_max_bytes=cfg.base.spool_max_bytes, max_retries=1,
    )


def _debug(enabled: bool, message: str) -> None:
    if enabled:
        print(f"contextos-codex-hook: {message}", file=sys.stderr)


def handle_pre_tool_use(h: HookInput, cfg: CodexHookConfig, client_factory: ClientFactory, started: float) -> Verdict:
    deadline = started + cfg.decide_budget_s
    client = client_factory(cfg, cfg.decide_budget_s)
    try:
        return PreToolUseEnforcer(client, cfg, deadline=deadline).run(h)
    finally:
        client.close()


def handle_observation(h: HookInput, cfg: CodexHookConfig, client_factory: ClientFactory) -> int:
    """Report a non-blocking event. Returns how many events were accepted or spooled."""
    events = observe.observation_events(h, mapping.agent_ref(cfg.agent_name, cfg.base.environment),
                                        max_result_chars=cfg.max_result_chars)
    if not events:
        return 0
    budget = SESSION_END_BUDGET_S if h.event == "SessionEnd" else EVENT_BUDGET_S
    client = client_factory(cfg, budget)
    try:
        if h.event == "SessionEnd":
            # Codex kills SessionEnd hooks after at most 3 s: keep the event on disk first, so a
            # kill mid-request loses nothing (event ids make the later re-send idempotent).
            stored = client.spool_events(events)
            client.flush_spool()
            return stored
        outcome = client.send_events(events)
        for rejected in outcome.rejected:
            log.debug("ContextOS rejected %s: %s", rejected.event_id, rejected.error)
        return outcome.accepted + len(outcome.spooled)
    finally:
        client.close()


def _emit(verdict: Verdict, stdout: IO[str], stderr: IO[str], tool: str) -> int:
    """Write the answer; a block that cannot be written still exits 2, a write that fails blocks."""
    try:
        code, out, err = verdict.answer()
    except ValueError:
        code, out, err = BLOCK_EXIT, None, f"ContextOS produced an invalid answer for this {tool} call; blocked.\n"
    try:
        if out:
            stdout.write(out)
            stdout.flush()
        if err:
            stderr.write(err)
            stderr.flush()
    except (OSError, ValueError) as exc:
        try:
            stderr.write(f"ContextOS could not answer for this {tool} call ({type(exc).__name__}); blocked.\n")
            stderr.flush()
        except (OSError, ValueError):
            pass  # nothing left to write to; exit 2 still blocks only with a reason, nothing more to do
        return BLOCK_EXIT
    return code


def main(event_name: str, *, stdin: IO[bytes] | None = None, stdout: IO[str] | None = None,
         stderr: IO[str] | None = None, env: Mapping[str, str] | None = None,
         client_factory: ClientFactory | None = None) -> int:
    """Hook entry point. Returns the process exit code: 2 blocks a PreToolUse call, otherwise 0."""
    started = time.monotonic()
    environ = os.environ if env is None else env
    debug = is_debug(environ)
    configure_logging(debug, "contextos-codex-hook")
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    event = (event_name or "").strip()
    blocking = event == "PreToolUse"
    factory = client_factory or default_client

    h: HookInput | None = None
    problem: str | None = None
    try:
        h = mapping.parse_payload(read_stdin(stdin or sys.stdin.buffer, MAX_STDIN_BYTES, PayloadError), event)
        event = h.event
        blocking = event == "PreToolUse"
    except (PayloadError, OSError) as exc:
        problem = str(exc) if isinstance(exc, PayloadError) else f"the hook input could not be read ({exc.strerror})"

    if not blocking and event not in mapping.SUPPORTED_EVENTS:
        _debug(debug, f"{event or 'unknown event'}: not handled by ContextOS")
        return 0
    cfg: CodexHookConfig | None = None
    try:  # loaded even when the payload is unusable: PreToolUse needs the configured fail mode
        cfg = load_hook_config(project_dir_for(h.cwd if h else None, environ), env=environ)
    except (ConfigError, OSError, ValueError) as exc:
        problem = problem or f"the ContextOS configuration is invalid: {exc}"

    if not blocking:
        if problem is not None:
            _debug(debug, f"{event or 'unknown event'}: nothing reported ({problem})")
            return 0
        assert h is not None and cfg is not None
        budget = SESSION_END_BUDGET_S if event == "SessionEnd" else EVENT_BUDGET_S
        try:
            finished, count = run_with_budget(lambda: handle_observation(h, cfg, factory), budget,
                                              name="contextos-codex-hook")
        except (ContextOSError, OSError, ValueError) as exc:
            _debug(debug, f"{event}: not reported ({type(exc).__name__}: {exc})")
            return 0
        except Exception as exc:  # noqa: BLE001 - observation hooks must never break the session
            _debug(debug, f"{event}: internal error {type(exc).__name__}")
            return 0
        _debug(debug, f"{event}: {'reported ' + str(count) + ' event(s)' if finished else 'gave up after the time budget'}")
        return 0

    # -- PreToolUse: always answer ---------------------------------------------------------------
    tool = h.tool_name if h else "tool"
    if problem is not None or cfg is None or h is None:
        mode = cfg.fail_mode if cfg is not None else fail_mode_from_env(environ)
        verdict = fail_mode_verdict(mode, tool, problem or "the hook could not start")
    else:
        try:
            finished, result = run_with_budget(lambda: handle_pre_tool_use(h, cfg, factory, started),
                                               cfg.decide_budget_s - (time.monotonic() - started),
                                               name="contextos-codex-hook")
            verdict = result if finished else fail_mode_verdict(
                cfg.fail_mode, tool, f"no answer within the hook's {cfg.decide_budget_s:.0f}s budget")
        except Exception as exc:  # noqa: BLE001 - a crash must not let the tool run unchecked
            verdict = fail_mode_verdict(cfg.fail_mode, tool, f"the ContextOS hook failed ({type(exc).__name__})")
    code = _emit(verdict, out, err, tool)
    decided = verdict.decision.decision if verdict.decision else "-"
    _debug(debug, f"PreToolUse {tool}: decision={decided} answer={verdict.kind} outcome={verdict.outcome} "
           f"in {(time.monotonic() - started) * 1000:.0f} ms")
    return code


__all__ = ["ClientFactory", "default_client", "handle_observation", "handle_pre_tool_use", "main"]
