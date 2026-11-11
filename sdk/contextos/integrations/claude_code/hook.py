"""``contextos hook <EventName>``: the command Claude Code runs for each hook event.

Claude Code writes the hook payload as JSON on stdin and reads the answer from stdout and the exit
code (see docs/integrations/claude-code.md for the verified contract):

- ``PreToolUse`` is the enforcement point. The hook prints a ``hookSpecificOutput`` JSON object
  with ``permissionDecision`` ``deny`` or ``ask`` — or nothing at all, which lets the call continue
  through Claude Code's normal permission flow. It never prints ``allow``. It always answers within
  its own budget (hook timeout minus a margin): a hook that Claude Code has to kill is a
  non-blocking error and the tool would run.
- Every other event is observation only. The hook reports the event, never blocks, prints nothing
  (on SessionStart and UserPromptSubmit plain stdout would be added to Claude's context) and exits
  0. Events that cannot be delivered go to the offline spool and are re-sent later.

Diagnostics go to stderr only when ``CONTEXTOS_DEBUG=1``; tool input and secrets are never
printed.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import IO, Any

from contextos.client import ContextOSClient
from contextos.config import ConfigError
from contextos.errors import ContextOSError

from . import mapping, observe
from .approval import take_host_prompt
from .enforce import PreToolUseEnforcer, Verdict, fail_mode_verdict
from .hook_config import (
    EVENT_BUDGET_S,
    MAX_STDIN_BYTES,
    HookConfig,
    hook_fail_mode_from_env,
    load_hook_config,
)
from .mapping import HookInput, PayloadError

log = logging.getLogger("contextos.claude_code")

ClientFactory = Callable[[HookConfig, float], ContextOSClient]
_LOGGING_READY = False


def _configure_logging(debug: bool) -> None:
    """Silence SDK logging unless CONTEXTOS_DEBUG=1 (stray stderr shows up as hook errors)."""
    global _LOGGING_READY
    if _LOGGING_READY:
        return
    _LOGGING_READY = True
    root = logging.getLogger("contextos")
    if debug:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("contextos-hook %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
    else:
        root.addHandler(logging.NullHandler())
    root.propagate = False


def _is_debug(env: Mapping[str, str]) -> bool:
    return env.get("CONTEXTOS_DEBUG", "").strip().lower() in ("1", "true", "yes")


def default_client(cfg: HookConfig, budget_s: float) -> ContextOSClient:
    """Client for one hook process: short timeouts that fit the budget, one retry, per-agent spool."""
    timeout = max(1.0, min(cfg.base.timeout_s, budget_s / 2))
    return ContextOSClient(
        cfg.base.url, cfg.base.api_key, timeout=timeout,
        agent=mapping.agent_ref(cfg.agent_name, cfg.base.environment),
        integration=mapping.INTEGRATION, spool_max_bytes=cfg.base.spool_max_bytes, max_retries=1,
    )


def read_stdin(stream: IO[bytes], limit: int = MAX_STDIN_BYTES) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise PayloadError(f"the hook input is larger than {limit:,} bytes")
    return data


def _project_dir(env: Mapping[str, str], h: HookInput | None) -> Path:
    for candidate in (env.get("CLAUDE_PROJECT_DIR"), h.cwd if h else None):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return Path.cwd()


def _run_with_budget(fn: Callable[[], Any], budget_s: float) -> tuple[bool, Any]:
    """Run ``fn`` in a daemon thread; ``(finished, result)``. Exceptions propagate to the caller."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the calling thread
            box["error"] = exc

    worker = threading.Thread(target=target, name="contextos-hook", daemon=True)
    worker.start()
    worker.join(max(0.1, budget_s))
    if worker.is_alive():
        return False, None
    if "error" in box:
        raise box["error"]
    return True, box.get("value")


def _write(stdout: IO[str], output: dict[str, Any] | None) -> None:
    if output is None:
        return
    stdout.write(json.dumps(output, ensure_ascii=False) + "\n")
    stdout.flush()


def _debug(enabled: bool, message: str) -> None:
    if enabled:
        print(f"contextos-hook: {message}", file=sys.stderr)


def handle_pre_tool_use(h: HookInput, cfg: HookConfig, client_factory: ClientFactory, started: float) -> Verdict:
    deadline = started + cfg.decide_budget_s
    client = client_factory(cfg, cfg.decide_budget_s)
    try:
        return PreToolUseEnforcer(client, cfg, deadline=deadline).run(h)
    finally:
        client.close()


def handle_observation(h: HookInput, cfg: HookConfig, client_factory: ClientFactory) -> int:
    """Report a non-blocking event. Returns how many events were accepted or spooled."""
    extra: dict[str, Any] = {}
    if h.event in ("PostToolUse", "PostToolUseFailure"):
        prompt = take_host_prompt(h.correlation_id)
        if prompt:
            # The call ran after the hook answered "ask": a person approved it at Claude Code's prompt.
            extra = {"approved_at_host_prompt": True, "host_prompt": prompt}
    events = observe.observation_events(h, mapping.agent_ref(cfg.agent_name, cfg.base.environment),
                                        max_result_chars=cfg.max_result_chars, extra_metadata=extra)
    if not events:
        return 0
    client = client_factory(cfg, EVENT_BUDGET_S)
    try:
        outcome = client.send_events(events)
        for rejected in outcome.rejected:
            log.debug("ContextOS rejected %s: %s", rejected.event_id, rejected.error)
        return outcome.accepted + len(outcome.spooled)
    finally:
        client.close()


def main(event_name: str, *, stdin: IO[bytes] | None = None, stdout: IO[str] | None = None,
         env: Mapping[str, str] | None = None, client_factory: ClientFactory | None = None) -> int:
    """Hook entry point. Returns the process exit code (always 0 unless no answer could be written)."""
    started = time.monotonic()
    environ = os.environ if env is None else env
    debug = _is_debug(environ)
    _configure_logging(debug)
    out = stdout or sys.stdout
    event = (event_name or "").strip()
    blocking = event == "PreToolUse"
    factory = client_factory or default_client

    h: HookInput | None = None
    problem: str | None = None
    try:
        h = mapping.parse_payload(read_stdin(stdin or sys.stdin.buffer), event)
        event = h.event
        blocking = event == "PreToolUse"
    except (PayloadError, OSError) as exc:
        problem = str(exc) if isinstance(exc, PayloadError) else f"the hook input could not be read ({exc.strerror})"

    if not blocking and event not in mapping.SUPPORTED_EVENTS:
        _debug(debug, f"{event or 'unknown event'}: not handled by ContextOS")
        return 0
    cfg: HookConfig | None = None
    try:  # loaded even when the payload is unusable: PreToolUse needs the configured fail mode
        cfg = load_hook_config(_project_dir(environ, h), env=environ)
    except (ConfigError, OSError, ValueError) as exc:
        problem = problem or f"the ContextOS configuration is invalid: {exc}"

    if not blocking:
        if problem is not None:
            _debug(debug, f"{event or 'unknown event'}: nothing reported ({problem or 'event not handled'})")
            return 0
        assert h is not None and cfg is not None
        try:
            finished, count = _run_with_budget(lambda: handle_observation(h, cfg, factory), EVENT_BUDGET_S)
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
        mode = cfg.fail_mode if cfg is not None else hook_fail_mode_from_env(environ)
        verdict = fail_mode_verdict(mode, tool, problem or "the hook could not start")
    else:
        try:
            finished, result = _run_with_budget(lambda: handle_pre_tool_use(h, cfg, factory, started),
                                                cfg.decide_budget_s - (time.monotonic() - started))
            verdict = result if finished else fail_mode_verdict(
                cfg.fail_mode, tool, f"no answer within the hook's {cfg.decide_budget_s:.0f}s budget")
        except Exception as exc:  # noqa: BLE001 - a crash must not let the tool run unchecked
            verdict = fail_mode_verdict(cfg.fail_mode, tool, f"the ContextOS hook failed ({type(exc).__name__})")
    try:
        _write(out, verdict.to_output())
    except (OSError, ValueError) as exc:
        # Exit 2 is Claude Code's "block this tool call" signal; stderr becomes the reason.
        print(f"ContextOS could not answer for this {tool} call ({type(exc).__name__}); blocked.", file=sys.stderr)
        return 2
    decided = verdict.decision.decision if verdict.decision else "-"
    _debug(debug, f"PreToolUse {tool}: decision={decided} answer={verdict.permission or 'none'} "
           f"outcome={verdict.outcome} in {(time.monotonic() - started) * 1000:.0f} ms")
    return 0


__all__ = ["default_client", "handle_observation", "handle_pre_tool_use", "main", "read_stdin"]
