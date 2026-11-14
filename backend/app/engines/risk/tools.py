"""Server-side tool classification (pure).

The category, risk level and outbound/sensitive flags are always computed here from the tool's
name, server and (redacted) arguments. A client-supplied ``category_hint`` is only a fallback when
the name carries no signal, and it is labelled as such in the reason.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from app.domain.enums import OUTBOUND_CATEGORIES, RiskLevel, ToolCategory
from app.engines.risk.resources import command_text, extract_resources
from app.engines.risk.shell import analyze_command
from app.engines.risk.tool_names import (
    READ_VERBS,
    SEND_VERBS,
    WEB_SEARCH_TOKENS,
    ParsedName,
    builtin_for,
    infer_category,
    name_tokens,
    parse_tool_name,
)

C = ToolCategory
_RANK: dict[str, int] = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}

BASE_RISK: dict[str, str] = {
    C.SHELL: RiskLevel.HIGH,
    C.CODE_EXECUTION: RiskLevel.HIGH,
    C.INFRASTRUCTURE: RiskLevel.HIGH,
    C.EMAIL: RiskLevel.HIGH,
    C.MESSAGING: RiskLevel.HIGH,
    C.HTTP: RiskLevel.MEDIUM,
    C.BROWSER: RiskLevel.MEDIUM,
    C.FILE_WRITE: RiskLevel.MEDIUM,
    C.DATABASE: RiskLevel.MEDIUM,
    C.AGENT_DELEGATION: RiskLevel.MEDIUM,
    C.MCP: RiskLevel.MEDIUM,
    C.FILE_READ: RiskLevel.LOW,
    C.SEARCH: RiskLevel.LOW,
    C.OTHER: RiskLevel.LOW,
}

_CATEGORY_TEXT: dict[str, str] = {
    C.SHELL: "runs shell commands",
    C.CODE_EXECUTION: "executes code",
    C.INFRASTRUCTURE: "changes cloud or cluster infrastructure",
    C.EMAIL: "sends or reads email",
    C.MESSAGING: "sends or reads chat messages",
    C.HTTP: "makes network requests",
    C.BROWSER: "drives a web browser",
    C.FILE_WRITE: "writes or deletes files",
    C.DATABASE: "queries a database",
    C.AGENT_DELEGATION: "delegates work to another agent",
    C.MCP: "calls an MCP server tool whose capability is not recognisable from its name",
    C.FILE_READ: "reads local files",
    C.SEARCH: "searches",
    C.OTHER: "has no recognised capability",
}

_SENDING_KEYS = ("body", "data", "json", "form", "payload", "files", "content")
_DESTRUCTIVE_SQL = re.compile(r"\b(drop|truncate|alter|grant|revoke)\b|\bdelete\s+from\b", re.IGNORECASE)
_DESTRUCTIVE_INFRA = re.compile(r"\b(destroy|delete|terminate|teardown|purge)\b", re.IGNORECASE)
_SQL_START = re.compile(r"^\s*(select|insert|update|delete|with|create|drop|alter)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ToolClassification:
    category: str  # ToolCategory
    risk_level: str  # RiskLevel
    outbound: bool  # can transmit data outside the environment
    reads_sensitive: bool  # typically reads private data (files, DB, env)
    reason: str


def _raise(level: str, floor: str) -> str:
    return floor if _RANK[floor] > _RANK[level] else level


def _valid_category(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return ToolCategory(str(value)).value
    except ValueError:
        return None


def _shape_category(args: dict[str, Any]) -> tuple[str, str] | None:
    """Last-resort inference from the argument object's keys."""
    keys = {str(k).lower() for k in args}
    if command_text(args, include_script=False):
        return C.SHELL, "a 'command' argument"
    for key in ("sql", "query", "statement"):
        value = args.get(key)
        if isinstance(value, str) and _SQL_START.match(value):
            return C.DATABASE, f"an SQL '{key}' argument"
    if keys & {"to", "recipient", "recipients"} and keys & {"subject", "body", "html"}:
        return C.EMAIL, "recipient and message arguments"
    if keys & {"url", "uri", "endpoint", "webhook_url"}:
        return C.HTTP, "a URL argument"
    if keys & {"file_path", "path", "filename"}:
        return (
            (C.FILE_WRITE, "a path with content") if keys & {"content", "text"} else (C.FILE_READ, "a path")
        )
    return None


def _resolve_category(
    parsed: ParsedName, hint: str | None, args: dict[str, Any], provider: str | None = None
) -> tuple[str, str, bool]:
    """(category, reason, came_from_hint)."""
    builtin, host = builtin_for(parsed.tool, provider) if not parsed.is_mcp else (None, "")
    if builtin:
        return builtin[0], f"{host} built-in '{parsed.tool}' {builtin[1]}.", False
    origin = (
        f"MCP tool '{parsed.tool}' on server '{parsed.server}'"
        if parsed.is_mcp and parsed.server
        else (f"MCP tool '{parsed.tool}'" if parsed.is_mcp else f"Tool '{parsed.tool}'")
    )
    found = infer_category(name_tokens(parsed.tool))
    if found is None and parsed.server:
        server_found = infer_category(name_tokens(parsed.server))
        if server_found:
            found = (server_found[0], f"server name contains '{server_found[1]}'")
    elif found:
        found = (found[0], f"name contains '{found[1]}'")
    if found:
        category, why = found
        return category, f"{origin} {_CATEGORY_TEXT[category]} ({why}).", False
    hinted = _valid_category(hint)
    if hinted and hinted != C.OTHER:
        return (
            hinted,
            (
                f"{origin}: name gave no signal, so the integration's category hint '{hinted}' was used "
                "(not verified)."
            ),
            True,
        )
    shape = _shape_category(args) if args else None
    if shape:
        return shape[0], f"{origin} {_CATEGORY_TEXT[shape[0]]} (inferred from {shape[1]}).", False
    if parsed.is_mcp:
        return C.MCP, f"{origin} {_CATEGORY_TEXT[C.MCP]}; treated as able to send data to that server.", False
    return C.OTHER, f"{origin} {_CATEGORY_TEXT[C.OTHER]}.", False


def _sends_body(args: dict[str, Any]) -> bool:
    method = str(args.get("method", "")).upper()
    return method in {"POST", "PUT", "PATCH", "DELETE"} or any(args.get(k) for k in _SENDING_KEYS)


def _contains_redacted_secret(args: dict[str, Any]) -> bool:
    try:
        return "[REDACTED:" in json.dumps(args, default=str)
    except (TypeError, ValueError):
        return False


def classify_tool(
    name: str,
    provider: str,
    *,
    category_hint: str | None = None,
    server: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> ToolClassification:
    args = arguments if isinstance(arguments, dict) else {}
    parsed = parse_tool_name(name, provider, server)
    category, reason, from_hint = _resolve_category(parsed, category_hint, args, provider)
    reasons = [reason]
    risk = BASE_RISK.get(category, RiskLevel.LOW)
    tokens = name_tokens(parsed.tool) | (name_tokens(parsed.server) if parsed.server else set())

    builtin = builtin_for(parsed.tool, provider)[0] if not parsed.is_mcp else None
    if builtin and builtin[2]:
        risk = builtin[2]
    if from_hint and parsed.is_mcp:
        risk = _raise(risk, RiskLevel.MEDIUM)

    outbound = category in OUTBOUND_CATEGORIES
    reads_sensitive = False
    shell = None
    if category == C.SHELL:
        cmd = command_text(args)
        shell = analyze_command(cmd) if cmd else None
        if shell is None:
            outbound = False
            reasons.append(
                "No command to inspect: shell counts as outbound only when its command uses network tools."
            )
        elif shell.outbound:
            reasons.append(f"Outbound: {shell.outbound_reasons[0]}.")
        else:
            outbound = False
            reasons.append(
                "Command uses no network tools that reach another host, so it is treated as local "
                "(not outbound)."
                if not shell.network_programs
                else "Network tools only contact this machine (loopback), so it is not outbound."
            )
    elif category in {C.EMAIL, C.MESSAGING}:
        if tokens & READ_VERBS and not tokens & SEND_VERBS:
            outbound, reads_sensitive, risk = False, True, RiskLevel.MEDIUM
            reasons.append(
                "Its name only reads messages, so it is not an outbound channel; message content is "
                "private and comes from outside."
            )
    elif category == C.SEARCH:
        if builtin or tokens & WEB_SEARCH_TOKENS:
            outbound, risk = True, RiskLevel.MEDIUM
            reasons.append("Search queries leave the machine, so query text is an outbound channel.")
    elif category == C.DATABASE:
        reads_sensitive = True
        reasons.append("Databases typically hold private records.")

    resources = extract_resources(category, args) if args else []
    sensitive = [r for r in resources if r.get("sensitive")]
    if sensitive:
        risk = _raise(risk, RiskLevel.HIGH)
        listed = ", ".join(
            f"{r['id']}" + (f" ({r['reason']})" if r.get("reason") else "") for r in sensitive[:3]
        )
        reasons.append(f"Touches sensitive resource(s): {listed}.")
        if category in {C.FILE_READ, C.SHELL, C.CODE_EXECUTION, C.DATABASE}:
            reads_sensitive = True
        if outbound:
            risk = RiskLevel.CRITICAL
            reasons.append("A sensitive resource and an outbound channel appear in the same call.")

    if shell is not None:
        if shell.env_dumps:
            reads_sensitive = True
            risk = _raise(risk, RiskLevel.CRITICAL if outbound else RiskLevel.HIGH)
        if shell.exec_on_connect:
            risk = RiskLevel.CRITICAL
            reasons.append("Hands a program to a network connection (reverse/bind shell pattern).")
        if shell.destructive:
            risk = RiskLevel.CRITICAL
            reasons.append(f"Destructive command: {shell.destructive[0]}.")
    if category in {C.HTTP, C.BROWSER} and args and _sends_body(args):
        risk = _raise(risk, RiskLevel.HIGH)
        reasons.append("Sends a request body or uses a state-changing HTTP method.")
    if category == C.DATABASE:
        sql = " ".join(str(args.get(k, "")) for k in ("query", "sql", "statement"))
        if _DESTRUCTIVE_SQL.search(sql):
            risk = _raise(risk, RiskLevel.HIGH)
            reasons.append("SQL modifies schema/permissions or deletes data.")
    if category == C.INFRASTRUCTURE:
        cmd = command_text(args) or ""
        if tokens & {"destroy", "delete", "terminate", "teardown"} or _DESTRUCTIVE_INFRA.search(cmd):
            risk = RiskLevel.CRITICAL
            reasons.append("Destroys or deletes infrastructure.")
    if outbound and args and _contains_redacted_secret(args):
        risk = RiskLevel.CRITICAL
        reasons.append("Arguments contained a credential (now redacted) and the call can transmit data.")

    return ToolClassification(
        category=str(category),
        risk_level=str(risk),
        outbound=outbound,
        reads_sensitive=reads_sensitive,
        reason=" ".join(reasons),
    )
