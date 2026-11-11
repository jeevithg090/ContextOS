"""``contextos mcp-gateway``: run an MCP server behind the ContextOS gateway.

    contextos mcp-gateway --name <server-name> [options] -- <upstream command> [args...]

Gateway options come first; the upstream command starts at ``--`` or at the first argument that is
not a gateway option (``contextos``'s own CLI drops the ``--``, so both forms are accepted).

ContextOS settings come from the usual SDK configuration (``CONTEXTOS_URL``, ``CONTEXTOS_API_KEY``,
``CONTEXTOS_AGENT_NAME``, ``CONTEXTOS_FAIL_MODE``, ``CONTEXTOS_APPROVAL_TIMEOUT_S`` or
``.contextos/config.json``). The upstream server inherits this process's environment EXCEPT every
``CONTEXTOS_*`` variable, so a third-party MCP server never sees the ContextOS API key.

stdout is the MCP channel: everything the gateway says goes to stderr (which MCP hosts log).
Exit codes: 0 the host disconnected normally, 1 configuration or upstream failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import logging
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from contextos.config import Config, ConfigError, load_config

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
LOG_FORMAT = "[contextos mcp-gateway] %(levelname)s %(message)s"
log = logging.getLogger("contextos.mcp_gateway")

# (option strings, takes a value, argparse keyword arguments)
_OPTIONS: list[tuple[tuple[str, ...], bool, dict[str, object]]] = [
    (("--name",), True, {"required": True, "metavar": "NAME",
                         "help": "MCP server name as the host knows it (e.g. the .mcp.json key); ContextOS keys the "
                                 "server and its tools by this name"}),
    (("--agent",), True, {"metavar": "NAME", "help": "agent name reported to ContextOS (default: CONTEXTOS_AGENT_NAME, "
                                                     "else the host's MCP client name)"}),
    (("--fail-mode",), True, {"choices": ("closed", "open"),
                              "help": "when ContextOS cannot be reached: 'closed' blocks tool calls (default), 'open' "
                                      "forwards them without a decision"}),
    (("--approval-timeout",), True, {"type": float, "metavar": "SECONDS",
                                     "help": "how long a REQUIRE_APPROVAL call waits for a reviewer (default: "
                                             "CONTEXTOS_APPROVAL_TIMEOUT_S or 300; 0 = do not wait, block); a "
                                             "request nobody decided in time is withdrawn"}),
    (("--poll-interval",), True, {"type": float, "default": 2.0, "metavar": "SECONDS",
                                  "help": "approval polling interval (default 2)"}),
    (("--session-id",), True, {"metavar": "ID", "help": "session id to report (default: a new id per process)"}),
    (("--hide-blocked-tools",), False, {"action": "store_true",
                                        "help": "list no tools when ContextOS classifies this MCP server as BLOCKED "
                                                "(calls are decided either way)"}),
    (("--no-context-reports",), False, {"action": "store_true",
                                        "help": "do not report resource reads and prompts to ContextOS"}),
    (("--max-result-chars",), True, {"type": int, "default": 100_000, "metavar": "N",
                                     "help": "characters of each result/resource reported for scanning (default 100000)"}),
    (("--startup-timeout",), True, {"type": float, "default": 60.0, "metavar": "SECONDS",
                                    "help": "how long the upstream server may take to initialize (default 60)"}),
    (("--cwd",), True, {"metavar": "DIR", "help": "working directory of the upstream server"}),
    (("--log-level",), True, {"default": "info", "choices": ("debug", "info", "warning", "error"),
                              "help": "stderr log level (default info); tool arguments and results are never logged"}),
    (("-h", "--help"), False, {"action": "help", "help": "show this help and exit"}),
]
_TAKES_VALUE = {opt: takes for opts, takes, _ in _OPTIONS for opt in opts}


@dataclass
class Invocation:
    options: argparse.Namespace
    command: list[str]


class UsageError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contextos mcp-gateway", add_help=False,
        usage="contextos mcp-gateway --name NAME [options] -- COMMAND [ARGS...]",
        description="Run an MCP server behind ContextOS: every tools/call is decided by ContextOS before the "
                    "server is contacted; listings, results, resources and prompts are reported for scanning.",
        epilog="Example: contextos mcp-gateway --name github --agent claude-code -- npx -y "
               "@modelcontextprotocol/server-github",
    )
    for opts, _takes, kwargs in _OPTIONS:
        parser.add_argument(*opts, **kwargs)  # type: ignore[arg-type]
    return parser


def split_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """``(gateway_args, upstream_command)``; the command starts at ``--`` or the first non-option."""
    args = list(argv)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return args[:i], args[i + 1:]
        if not arg.startswith("-") or arg == "-":
            return args[:i], args[i:]
        name = arg.split("=", 1)[0]
        if name not in _TAKES_VALUE:
            raise UsageError(f"unknown gateway option {arg!r} (gateway options must come before the upstream command)")
        i += 2 if _TAKES_VALUE[name] and "=" not in arg else 1
    return args, []


def parse(argv: Sequence[str]) -> Invocation:
    gateway_args, command = split_argv(argv)
    options = build_parser().parse_args(gateway_args)
    if not command:
        raise UsageError("no upstream MCP server command given (add it after '--')")
    return Invocation(options, command)


def upstream_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """This process's environment without ``CONTEXTOS_*`` (never hand the API key to the upstream)."""
    source = os.environ if environ is None else environ
    return {k: v for k, v in source.items() if not k.upper().startswith("CONTEXTOS_")}


def _configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root = logging.getLogger("contextos")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    root.propagate = False
    logging.getLogger().setLevel(logging.WARNING)  # quiet third-party INFO logs on the host's stderr


def _mcp_problem() -> str | None:
    try:
        version = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        return "the MCP Python SDK is not installed; install it with: pip install 'contextos[mcp]'"
    major = version.split(".", 1)[0]
    if not major.isdigit() or int(major) < 2:
        return f"the MCP gateway needs the MCP Python SDK 2.x (found mcp {version}); upgrade with: pip install -U 'mcp>=2'"
    return None


def _root_cause(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def main(argv: Sequence[str] | None = None) -> int:
    try:
        invocation = parse(list(sys.argv[1:] if argv is None else argv))
    except UsageError as exc:
        print(f"contextos mcp-gateway: {exc}\n{build_parser().format_usage().strip()}", file=sys.stderr)
        return EXIT_USAGE
    except SystemExit as exc:  # argparse: --help (0) or invalid options (2, message already printed)
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    opts = invocation.options
    _configure_logging(opts.log_level)

    from contextos.integrations.mcp_gateway.mapping import server_name_problem

    problem = server_name_problem(opts.name)
    if problem:
        log.error("Invalid --name %r: %s", opts.name, problem)
        return EXIT_USAGE
    problem = _mcp_problem()
    if problem:
        log.error("Cannot start: %s", problem)
        return EXIT_ERROR
    try:
        config = load_config()
    except ConfigError as exc:
        log.error("Invalid ContextOS configuration: %s", exc)
        return EXIT_ERROR
    if not config.api_key:
        log.error("No ContextOS API key: set CONTEXTOS_API_KEY (scopes ingest + decide) or run `contextos init`. "
                  "The gateway refuses to start rather than block every tool call.")
        return EXIT_ERROR
    fail_mode = opts.fail_mode or config.fail_mode
    if fail_mode not in ("closed", "open"):
        log.info("Fail mode %r is not available in the MCP gateway (it has no one to ask); using 'closed'", fail_mode)
        fail_mode = "closed"
    return _run(invocation, config, fail_mode)


def _run(invocation: Invocation, config: Config, fail_mode: str) -> int:
    import anyio
    from mcp import StdioServerParameters

    from contextos.client import ContextOSClient
    from contextos.integrations.mcp_gateway.proxy import GatewaySettings, serve_stdio
    from contextos.models import AgentRef, new_session_id

    opts = invocation.options
    agent_name = opts.agent or config.agent_name
    settings = GatewaySettings(
        server_name=opts.name, agent_name=agent_name, session_id=opts.session_id or new_session_id(),
        fail_mode=fail_mode,
        approval_timeout_s=opts.approval_timeout if opts.approval_timeout is not None
        else config.approval_timeout_s,
        poll_s=opts.poll_interval, hide_blocked_tools=opts.hide_blocked_tools,
        report_context=not opts.no_context_reports, max_result_chars=max(1_000, opts.max_result_chars),
    )
    client = ContextOSClient.from_config(
        config, agent=AgentRef(name=agent_name or f"mcp-gateway-{opts.name}", framework="mcp"),
        integration="mcp_gateway",
    )
    upstream = StdioServerParameters(command=invocation.command[0], args=invocation.command[1:],
                                     env=upstream_environment(), cwd=opts.cwd)
    try:
        anyio.run(lambda: serve_stdio(settings, upstream, client, startup_timeout_s=opts.startup_timeout))
    except KeyboardInterrupt:
        return EXIT_OK
    except BaseException as exc:  # noqa: BLE001 - report the root cause, never a traceback of event content
        cause = _root_cause(exc)
        if isinstance(cause, KeyboardInterrupt):
            return EXIT_OK
        if isinstance(cause, FileNotFoundError | PermissionError):
            log.error("Cannot start the upstream MCP server %r: %s", invocation.command[0], cause.strerror or cause)
        elif isinstance(cause, TimeoutError):
            log.error("The upstream MCP server did not finish initializing within %.0fs (--startup-timeout)",
                      opts.startup_timeout)
        else:
            log.error("The MCP gateway stopped: %s: %s", type(cause).__name__, cause)
            log.debug("Gateway failure", exc_info=cause)
        return EXIT_ERROR
    finally:
        client.close()
    return EXIT_OK


__all__ = ["main", "parse", "split_argv", "upstream_environment"]
