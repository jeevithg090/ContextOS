"""Field catalog and operator vocabulary of the policy condition DSL.

``FIELD_CATALOG`` lists every path a condition may reference, derived from
:class:`~app.engines.policy.spec.EvaluationInput` (the module checks at import time that every
catalog root is a real EvaluationInput field and that every field is covered). Served verbatim by
``GET /api/v1/policies/fields`` so the policy editor and the validator agree.

Entry keys:
    path         dotted path; ``[*]`` = "any element of this list"; ``arguments.*`` = any argument key
    type         string | number | boolean | list | enum | any  (``any``: free-form tool arguments)
    description  plain-language meaning
    example      a representative value
    values       allowed values (enums, and lists whose items are enum values), lowest rank first
    ordered      enums only: values have a rank, so gt/gte/lt/lte compare by rank
    item_type    lists only: string | enum | object
    ops          operators valid for this field
"""

from __future__ import annotations

import re
from dataclasses import fields as dataclass_fields
from typing import Any

from app.domain.enums import (
    SEVERITY_RANK,
    TRUST_RANK,
    FindingCategory,
    RiskLevel,
    ToolCategory,
)
from app.engines.policy.spec import EvaluationInput

OPERATORS: list[dict[str, Any]] = [
    {"op": "eq", "label": "equals", "value": "scalar"},
    {"op": "neq", "label": "does not equal", "value": "scalar"},
    {"op": "in", "label": "is one of", "value": "list"},
    {"op": "not_in", "label": "is not one of", "value": "list"},
    {"op": "contains", "label": "contains", "value": "scalar"},
    {"op": "not_contains", "label": "does not contain", "value": "scalar"},
    {"op": "glob", "label": "matches glob", "value": "glob"},
    {"op": "any_glob", "label": "has an element matching glob", "value": "glob"},
    {"op": "exists", "label": "is present", "value": "none"},
    {"op": "empty", "label": "is empty", "value": "none"},
    {"op": "not_empty", "label": "is not empty", "value": "none"},
    {"op": "gt", "label": "is greater than", "value": "comparable"},
    {"op": "gte", "label": "is at least", "value": "comparable"},
    {"op": "lt", "label": "is less than", "value": "comparable"},
    {"op": "lte", "label": "is at most", "value": "comparable"},
    {"op": "is_true", "label": "is true", "value": "none"},
    {"op": "is_false", "label": "is false", "value": "none"},
]
OPS: frozenset[str] = frozenset(o["op"] for o in OPERATORS)
VALUELESS_OPS: frozenset[str] = frozenset(o["op"] for o in OPERATORS if o["value"] == "none")
COMPARISON_OPS: frozenset[str] = frozenset({"gt", "gte", "lt", "lte"})

SEVERITIES = sorted(SEVERITY_RANK, key=SEVERITY_RANK.__getitem__)  # info .. critical
RISK_LEVELS = [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
TRUST_LEVELS = sorted(TRUST_RANK, key=TRUST_RANK.__getitem__)  # BLOCKED .. TRUSTED
TOOL_CATEGORIES = [c.value for c in ToolCategory]
FINDING_CATEGORIES = [c.value for c in FindingCategory]
ENVIRONMENTS = ["development", "staging", "production"]
DESTINATION_KINDS = ["domain", "ip", "email", "service", "agent", "unknown"]

_STRING_OPS = [
    "eq",
    "neq",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "glob",
    "exists",
    "empty",
    "not_empty",
]
_ENUM_OPS = ["eq", "neq", "in", "not_in", "glob", "exists"]
_NUMBER_OPS = ["eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte", "exists"]
_BOOLEAN_OPS = ["is_true", "is_false", "eq", "neq", "exists"]
_SCALAR_LIST_OPS = ["contains", "not_contains", "in", "not_in", "any_glob", "empty", "not_empty", "exists"]
_OBJECT_LIST_OPS = ["empty", "not_empty", "exists"]


def _ops_for(type_: str, *, ordered: bool = False, item_type: str | None = None) -> list[str]:
    if type_ == "string":
        return list(_STRING_OPS)
    if type_ == "enum":
        return _ENUM_OPS + (sorted(COMPARISON_OPS) if ordered else [])
    if type_ == "number":
        return list(_NUMBER_OPS)
    if type_ == "boolean":
        return list(_BOOLEAN_OPS)
    if type_ == "list":
        return list(_OBJECT_LIST_OPS if item_type == "object" else _SCALAR_LIST_OPS)
    return [o["op"] for o in OPERATORS]  # "any"


def _f(
    path: str,
    type_: str,
    description: str,
    example: Any,
    *,
    values: list[str] | None = None,
    ordered: bool = False,
    item_type: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"path": path, "type": type_, "description": description, "example": example}
    if values is not None:
        entry["values"] = list(values)
    if type_ == "enum":
        entry["ordered"] = ordered
    if item_type is not None:
        entry["item_type"] = item_type
    entry["ops"] = _ops_for(type_, ordered=ordered, item_type=item_type)
    return entry


FIELD_CATALOG: list[dict[str, Any]] = [
    # agent
    _f("agent.id", "string", "ContextOS id of the agent making the call.", "agt_01J9Z8…"),
    _f("agent.name", "string", "Agent name as registered (case-insensitive comparison).", "release-bot"),
    _f(
        "agent.environment",
        "enum",
        "Deployment environment the agent runs in.",
        "production",
        values=ENVIRONMENTS,
    ),
    _f(
        "agent.labels", "list", "Labels assigned to the agent in ContextOS.", ["payments"], item_type="string"
    ),
    _f("agent.framework", "string", "Agent framework reported by the integration.", "claude_code"),
    # tool
    _f("tool.name", "string", "Name of the tool being called.", "Bash"),
    _f(
        "tool.category",
        "enum",
        "Server-side classification of what the tool does.",
        "http",
        values=TOOL_CATEGORIES,
    ),
    _f("tool.provider", "string", "Who provides the tool (built-in, MCP, SDK...).", "claude_code"),
    _f("tool.server", "string", "MCP server that exposes the tool, when applicable.", "github"),
    _f(
        "tool.risk_level",
        "enum",
        "Server-side inherent risk of the tool.",
        "high",
        values=RISK_LEVELS,
        ordered=True,
    ),
    # arguments
    _f("arguments", "any", "All tool arguments (redacted before evaluation).", {"command": "ls -la"}),
    _f(
        "arguments.*",
        "any",
        "Any tool argument by key, after redaction; nested keys use dots "
        "(e.g. arguments.command, arguments.url, arguments.headers.host).",
        "arguments.command",
    ),
    # resources
    _f(
        "resources",
        "list",
        "Resources the call touches (files, URLs, hosts, commands).",
        [{"kind": "file", "id": "/app/.env", "sensitive": True}],
        item_type="object",
    ),
    _f("resources[*].kind", "string", "Kind of a touched resource: file, url, host, command, ...", "file"),
    _f("resources[*].id", "string", "Identifier of a touched resource (path, URL, host...).", "/app/.env"),
    _f(
        "resources[*].sensitive",
        "boolean",
        "Whether a touched resource is sensitive (credentials, keys, env files...).",
        True,
    ),
    _f("resources[*].reason", "string", "Why the resource was flagged sensitive.", "environment file"),
    _f(
        "sensitive_resources",
        "list",
        "Identifiers of the sensitive resources the call touches.",
        ["/home/dev/.aws/credentials"],
        item_type="string",
    ),
    # destination
    _f(
        "destination.kind",
        "enum",
        "Kind of outbound destination the call can send data to.",
        "domain",
        values=DESTINATION_KINDS,
    ),
    _f(
        "destination.identifier",
        "string",
        "Canonical outbound destination (host, address, service).",
        "api.example.com",
    ),
    _f(
        "destination.classification",
        "enum",
        "Trust classification of the destination.",
        "UNKNOWN",
        values=TRUST_LEVELS,
        ordered=True,
    ),
    _f(
        "destination.checks",
        "list",
        "Checks performed when classifying the destination.",
        [{"check": "allowlist", "result": "no_match"}],
        item_type="object",
    ),
    _f("destination.checks[*].check", "string", "Name of a destination check that was performed.", "raw_ip"),
    _f("destination.checks[*].result", "string", "Result of a destination check.", "match"),
    # secrets
    _f(
        "secrets_in_arguments",
        "list",
        "Secrets detected in the tool arguments (type and fingerprint only).",
        [{"type": "aws_access_key"}],
        item_type="object",
    ),
    _f(
        "secrets_in_arguments[*].type",
        "string",
        "Type of a secret detected in the arguments.",
        "aws_access_key",
    ),
    _f(
        "session_secret_matches",
        "list",
        "Secrets in the arguments that this session previously read from "
        "its context (a credential flowing towards a tool call).",
        [{"type": "github_token"}],
        item_type="object",
    ),
    _f(
        "session_secret_matches[*].type",
        "string",
        "Type of a secret that flowed from context into the call.",
        "github_token",
    ),
    # session risk
    _f("session.score", "number", "Session risk score, 0-100.", 72),
    _f("session.level", "enum", "Session risk level.", "high", values=RISK_LEVELS, ordered=True),
    _f(
        "session.untrusted_exposure",
        "boolean",
        "The session has consumed content from untrusted sources.",
        True,
    ),
    _f("session.sensitive_access", "boolean", "The session has accessed sensitive data.", True),
    _f(
        "session.outbound_channel", "boolean", "The session has used a channel that can send data out.", False
    ),
    _f(
        "session.trifecta",
        "boolean",
        "Lethal trifecta: sensitive access, untrusted exposure and an outbound "
        "channel all observed in the session (a risk condition, not proof of an attack).",
        True,
    ),
    # context
    _f(
        "context.lowest_trust",
        "enum",
        "Lowest trust level among the context items in the session.",
        "UNKNOWN",
        values=TRUST_LEVELS,
        ordered=True,
    ),
    _f("context.untrusted_item_count", "number", "Number of untrusted context items in the session.", 3),
    _f(
        "context.suspicious_source_ids",
        "list",
        "Ids of sources classified SUSPICIOUS that fed the session.",
        ["src_01J9…"],
        item_type="string",
    ),
    _f(
        "context.injection_detected",
        "boolean",
        "Prompt injection was detected in the session's context.",
        True,
    ),
    _f(
        "context.max_detection_severity",
        "enum",
        "Highest detection severity in the session's context.",
        "high",
        values=SEVERITIES,
        ordered=True,
    ),
    # detection over the request
    _f(
        "detection.rule_ids",
        "list",
        "Detection rules that fired on this tool request.",
        ["TOOL-DESTRUCTIVE-RM-RF"],
        item_type="string",
    ),
    _f(
        "detection.max_severity",
        "enum",
        "Highest severity among detections on this tool request.",
        "high",
        values=SEVERITIES,
        ordered=True,
    ),
    _f(
        "detection.categories",
        "list",
        "Finding categories of detections on this tool request.",
        ["credential_access"],
        values=FINDING_CATEGORIES,
        item_type="enum",
    ),
    # integration
    _f("integration.kind", "string", "Integration that reported the call.", "claude_code"),
    _f(
        "integration.supports_enforcement",
        "boolean",
        "The integration can enforce decisions before the tool runs.",
        True,
    ),
]

_BY_PATH: dict[str, dict[str, Any]] = {e["path"]: e for e in FIELD_CATALOG}
FIELD_PATHS: list[str] = [e["path"] for e in FIELD_CATALOG]


# ---- path syntax ---------------------------------------------------------------------------

WILDCARD = "*"
_SEGMENT = re.compile(r"^([^\[\]]+)((?:\[(?:\*|\d+)\])*)$")
_INDEX = re.compile(r"\[(\*|\d+)\]")


def parse_path(path: str) -> list[str | int] | None:
    """``"resources[*].sensitive"`` -> ``["resources", "*", "sensitive"]``; ``None`` if malformed."""
    if not isinstance(path, str) or not path or path != path.strip():
        return None
    out: list[str | int] = []
    for part in path.split("."):
        m = _SEGMENT.match(part)
        if not m:
            return None
        out.append(m.group(1))
        for idx in _INDEX.findall(m.group(2)):
            out.append(WILDCARD if idx == "*" else int(idx))
    return out


def canonical_path(path: str) -> str | None:
    """Catalog form of a path: numeric indexes become ``[*]``; unknown argument keys -> ``arguments.*``."""
    segs = parse_path(path)
    if segs is None:
        return None
    text = ""
    for seg in segs:
        if isinstance(seg, int) or seg == WILDCARD:
            text += "[*]"
        else:
            text += f".{seg}" if text else seg
    if text.startswith("arguments.") or text.startswith("arguments["):
        return "arguments.*"
    return text


def lookup_field(path: str) -> dict[str, Any] | None:
    canon = canonical_path(path)
    return _BY_PATH.get(canon) if canon else None


def rank_of(spec: dict[str, Any] | None, value: Any) -> int | None:
    """Rank of an ordered enum value (case-insensitive), else None."""
    if not spec or not spec.get("ordered") or not isinstance(value, str):
        return None
    folded = [v.casefold() for v in spec.get("values", [])]
    v = value.casefold()
    return folded.index(v) if v in folded else None


def _check_catalog_against_input() -> None:
    roots = {f.name for f in dataclass_fields(EvaluationInput)}
    covered = set()
    for entry in FIELD_CATALOG:
        root = parse_path(entry["path"])
        if root is None or root[0] not in roots:
            raise RuntimeError(f"policy field catalog path {entry['path']!r} is not an EvaluationInput field")
        covered.add(root[0])
    if covered != roots:
        raise RuntimeError(f"policy field catalog misses EvaluationInput fields: {sorted(roots - covered)}")


_check_catalog_against_input()
