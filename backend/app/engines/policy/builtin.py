"""Built-in policy pack seeded into every new organisation (``app.services.seed``).

Each entry is a dict with keys ``builtin_key, name, description, outcome, mode, priority,
severity, conditions, restrictions, tags``. Seeding is idempotent by ``builtin_key``; organisations
may edit or disable the seeded copies. Built-in policies cannot be deleted (the policies API answers
409 Conflict); disabling one turns it off and it can be re-enabled later.

Each policy matches its own intent, so disabling one changes behaviour instead of being masked by
another. In particular destructive commands and privilege escalation are separate detection
semantics: ``TOOL-DESTRUCTIVE-*`` rules report ``suspicious_tool_use`` (matched by rule-id prefix in
"Deny destructive shell commands"), while ``permission_escalation`` is reserved for agent-config
writes, persistence and reverse shells ("Deny agent config tampering and privilege escalation").

A decision only stops a tool call where the integration enforces it at an execution boundary
(Claude Code and Codex PreToolUse hooks, MCP gateway, SDK ``guard()``). Elsewhere the same decision is
advisory or observed, and the UI labels it that way.

Every ``conditions`` object here must pass ``validate_conditions`` (asserted by the unit tests).
"""

from __future__ import annotations

import copy
from typing import Any

from app.engines.policy.spec import PolicySpec

# A call that can move data out: a destination was extracted, or the tool itself is a network /
# messaging channel (so a missing destination is not a loophole).
_OUTBOUND_CALL: dict[str, Any] = {
    "any": [
        {"field": "destination.identifier", "op": "exists"},
        {"field": "tool.category", "op": "in", "value": ["http", "browser", "email", "messaging"]},
    ]
}

_TOUCHES_SENSITIVE: dict[str, Any] = {
    "any": [
        {"field": "sensitive_resources", "op": "not_empty"},
        {"field": "resources[*].sensitive", "op": "is_true"},
    ]
}

# Unclassified destinations are treated as untrusted: NOT(in [...]) is true when the field is missing.
_NOT_TRUSTED_DESTINATION: dict[str, Any] = {
    "not": {"field": "destination.classification", "op": "in", "value": ["TRUSTED", "APPROVED"]}
}

_PACK: list[dict[str, Any]] = [
    {
        "builtin_key": "builtin.block-credential-exfiltration",
        "name": "Block credential exfiltration",
        "description": (
            "Threat: an agent sends a credential out of the environment, typically after reading it from a "
            "file or environment variable, often because injected content told it to. "
            "Decision: DENY any outbound call (a destination is present, or the tool is HTTP, browser, email "
            "or messaging) whose arguments contain a detected secret or a secret this session previously "
            "read from its context, unless the destination is classified TRUSTED or APPROVED. A destination "
            "that could not be classified counts as untrusted."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 1000,
        "severity": "critical",
        "conditions": {
            "all": [
                {
                    "any": [
                        {"field": "secrets_in_arguments", "op": "not_empty"},
                        {"field": "session_secret_matches", "op": "not_empty"},
                    ]
                },
                _OUTBOUND_CALL,
                _NOT_TRUSTED_DESTINATION,
            ]
        },
        "restrictions": {},
        "tags": ["exfiltration", "credentials", "secrets"],
    },
    {
        "builtin_key": "builtin.block-blocked-destinations",
        "name": "Block blocked destinations",
        "description": (
            "Threat: data sent to, or content fetched from, a destination your organisation has explicitly "
            "blocked (known exfiltration endpoints, paste sites, tunnels). "
            "Decision: DENY any tool call whose destination a trust rule classifies as BLOCKED."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 950,
        "severity": "high",
        "conditions": {"field": "destination.classification", "op": "eq", "value": "BLOCKED"},
        "restrictions": {},
        "tags": ["destinations", "exfiltration"],
    },
    {
        "builtin_key": "builtin.deny-sensitive-access-after-injection",
        "name": "Deny sensitive access after prompt injection",
        "description": (
            "Threat: a prompt injection in content the session consumed steers the agent towards credentials "
            "or private files. Detection is evidence of manipulative content, not proof the agent obeyed it. "
            "Decision: DENY tool calls that touch a sensitive resource (.env files, SSH keys, cloud "
            "credentials...) once prompt injection has been detected in the session's context."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 900,
        "severity": "high",
        "conditions": {
            "all": [
                {"field": "context.injection_detected", "op": "is_true"},
                _TOUCHES_SENSITIVE,
            ]
        },
        "restrictions": {},
        "tags": ["prompt-injection", "sensitive-data"],
    },
    {
        "builtin_key": "builtin.deny-secrets-to-tools-after-injection",
        "name": "Deny credentials in tool arguments after prompt injection",
        "description": (
            "Threat: injected instructions (for example a poisoned MCP tool description) tell the agent to "
            "put a credential into a tool's arguments, so the tool's provider receives it even when no "
            "outbound destination is visible to ContextOS. "
            "Decision: DENY tool calls whose arguments contain a detected secret once prompt injection has "
            "been detected in the session's context."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 880,
        "severity": "critical",
        "conditions": {
            "all": [
                {"field": "context.injection_detected", "op": "is_true"},
                {"field": "secrets_in_arguments", "op": "not_empty"},
            ]
        },
        "restrictions": {},
        "tags": ["prompt-injection", "credential-exfiltration", "mcp"],
    },
    {
        "builtin_key": "builtin.approve-outbound-after-injection",
        "name": "Require approval for outbound calls after prompt injection",
        "description": (
            "Threat: after a prompt injection in the session's context, an outbound request to a destination "
            "that is not approved or trusted may be the injected instruction being carried out (sending data "
            "out), even when no secret is visible in the arguments. "
            "Decision: REQUIRE_APPROVAL for outbound calls to destinations that are not TRUSTED or APPROVED once "
            "prompt injection has been detected in the session's context."
        ),
        "outcome": "REQUIRE_APPROVAL",
        "mode": "enforce",
        "priority": 680,
        "severity": "high",
        "conditions": {
            "all": [
                {"field": "context.injection_detected", "op": "is_true"},
                _OUTBOUND_CALL,
                _NOT_TRUSTED_DESTINATION,
            ]
        },
        "restrictions": {},
        "tags": ["prompt-injection", "destinations"],
    },
    {
        "builtin_key": "builtin.deny-destructive-shell",
        "name": "Deny destructive shell commands",
        "description": (
            "Threat: irreversible damage such as recursive deletes of the filesystem or repository, disk "
            "wipes, history-rewriting force pushes or dropped databases, whether triggered by an injected "
            "instruction or by an agent mistake. "
            "Decision: DENY tool requests on which a TOOL-DESTRUCTIVE-* detection rule fired (detection reports "
            "them as suspicious_tool_use). This is the only built-in policy that denies destructive commands, so "
            "disabling it lets them through to the shell audit policy."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 850,
        "severity": "high",
        "conditions": {"field": "detection.rule_ids", "op": "any_glob", "value": ["TOOL-DESTRUCTIVE-*"]},
        "restrictions": {},
        "tags": ["shell", "destructive"],
    },
    {
        "builtin_key": "builtin.deny-agent-config-tampering",
        "name": "Deny agent config tampering and privilege escalation",
        "description": (
            "Threat: an agent widens what it can do or who controls it: rewriting its own guardrails (hook "
            "or permission settings, MCP server configuration, instruction files), installing persistence "
            "(cron jobs, shell rc edits, launch agents) or opening a reverse shell. "
            "Decision: DENY tool requests that detection flags in the permission_escalation category (agent "
            "configuration writes, persistence, reverse shells). Destructive commands are not in this category; "
            "they are covered by 'Deny destructive shell commands'."
        ),
        "outcome": "DENY",
        "mode": "enforce",
        "priority": 840,
        "severity": "high",
        "conditions": {"field": "detection.categories", "op": "contains", "value": "permission_escalation"},
        "restrictions": {},
        "tags": ["permissions", "configuration"],
    },
    {
        "builtin_key": "builtin.approve-outbound-under-trifecta",
        "name": "Require approval for outbound calls under the lethal trifecta",
        "description": (
            "Threat: a session that has accessed sensitive data, consumed untrusted content and has an "
            "outbound channel can be manipulated into leaking that data (the lethal trifecta). The trifecta "
            "is a risk condition, not proof of an attack. "
            "Decision: REQUIRE_APPROVAL for every outbound call (a destination is present, or the tool is "
            "HTTP, browser, email or messaging) while all three conditions are active in the session."
        ),
        "outcome": "REQUIRE_APPROVAL",
        "mode": "enforce",
        "priority": 700,
        "severity": "high",
        "conditions": {"all": [{"field": "session.trifecta", "op": "is_true"}, _OUTBOUND_CALL]},
        "restrictions": {},
        "tags": ["lethal-trifecta", "exfiltration"],
    },
    {
        "builtin_key": "builtin.approve-suspicious-destinations",
        "name": "Require approval for suspicious destinations",
        "description": (
            "Threat: data sent to a destination with signs of risk, such as a raw IP address, a paste or "
            "webhook service, a tunnel, a lookalike or punycode domain, or a history of findings. "
            "Decision: REQUIRE_APPROVAL for tool calls whose destination is classified SUSPICIOUS."
        ),
        "outcome": "REQUIRE_APPROVAL",
        "mode": "enforce",
        "priority": 650,
        "severity": "high",
        "conditions": {"field": "destination.classification", "op": "eq", "value": "SUSPICIOUS"},
        "restrictions": {},
        "tags": ["destinations"],
    },
    {
        "builtin_key": "builtin.approve-production-infrastructure",
        "name": "Require approval for infrastructure changes in production",
        "description": (
            "Threat: an agent running in production changes infrastructure (deployments, cloud resources, "
            "DNS, IAM, Kubernetes, Terraform) on the strength of context that may not be trustworthy. "
            "Decision: REQUIRE_APPROVAL for infrastructure tool calls made by agents whose environment is "
            "production."
        ),
        "outcome": "REQUIRE_APPROVAL",
        "mode": "enforce",
        "priority": 600,
        "severity": "high",
        "conditions": {
            "all": [
                {"field": "agent.environment", "op": "eq", "value": "production"},
                {"field": "tool.category", "op": "eq", "value": "infrastructure"},
            ]
        },
        "restrictions": {},
        "tags": ["infrastructure", "production"],
    },
    {
        "builtin_key": "builtin.monitor-http-unknown-destinations",
        "name": "Dry run: approval for HTTP to unknown destinations",
        "description": (
            "Threat: data leaving for destinations nobody has classified yet. "
            "Runs in monitor mode: each match is recorded as a dry-run result (it would have required "
            "approval) and never changes the decision returned to the agent, so you can measure how often "
            "it would fire before switching it to enforce."
        ),
        "outcome": "REQUIRE_APPROVAL",
        "mode": "monitor",
        "priority": 400,
        "severity": "medium",
        "conditions": {
            "all": [
                {"field": "tool.category", "op": "in", "value": ["http", "browser"]},
                {"field": "destination.classification", "op": "eq", "value": "UNKNOWN"},
            ]
        },
        "restrictions": {},
        "tags": ["destinations", "dry-run"],
    },
    {
        "builtin_key": "builtin.audit-sensitive-file-reads",
        "name": "Audit sensitive file reads",
        "description": (
            "Threat: credential and private-data harvesting starts with reads. "
            "Decision: AUDIT whenever an agent reads a sensitive file (credentials, keys, env files), so the "
            "access stands out in investigations. The read itself is not blocked by this policy."
        ),
        "outcome": "AUDIT",
        "mode": "enforce",
        "priority": 300,
        "severity": "medium",
        "conditions": {
            "all": [{"field": "tool.category", "op": "eq", "value": "file_read"}, _TOUCHES_SENSITIVE]
        },
        "restrictions": {},
        "tags": ["sensitive-data", "audit"],
    },
    {
        "builtin_key": "builtin.audit-shell-commands",
        "name": "Audit shell commands",
        "description": (
            "Threat: shell access is the broadest capability an agent has. "
            "Decision: AUDIT every shell command so command history can be reviewed next to the context that "
            "preceded it. Commands are not blocked by this policy."
        ),
        "outcome": "AUDIT",
        "mode": "enforce",
        "priority": 200,
        "severity": "low",
        "conditions": {"field": "tool.category", "op": "eq", "value": "shell"},
        "restrictions": {},
        "tags": ["shell", "audit"],
    },
]

# Deep-copied per entry so no two policies share a condition object (the shared fragments above
# must never be mutated through one policy and silently change another).
BUILTIN_POLICIES: list[dict[str, Any]] = [copy.deepcopy(p) for p in _PACK]


def builtin_policy_specs() -> list[PolicySpec]:
    """The pack as engine specs (id = builtin_key); used by tests, simulations and docs."""
    return [
        PolicySpec(
            id=p["builtin_key"],
            name=p["name"],
            outcome=p["outcome"],
            conditions=p["conditions"],
            mode=p["mode"],
            priority=p["priority"],
            severity=p["severity"],
            restrictions=p["restrictions"],
            description=p["description"],
        )
        for p in BUILTIN_POLICIES
    ]
