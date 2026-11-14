"""Seed trust rules for new organisations (consumed by ``app.services.seed``).

Deliberately modest: each rule encodes a widely shared judgement and explains it. Priorities are
chosen so an organisation's own rules (default priority 100) override the broad defaults, while
the exfiltration-service rules (150) need an explicit higher-priority rule to be relaxed.

Keys: name, description, applies_to, source_type, match_field, pattern, trust_level,
capabilities, priority.
"""

from __future__ import annotations

from typing import Any

_DOCS_DESCRIPTION = (
    "Official documentation is a well-known third party: useful reference material, but its content is "
    "data and may not instruct the agent. Pages can still contain user-contributed or compromised text."
)
_REGISTRY_DESCRIPTION = (
    "Package registries publish READMEs and metadata written by package authors, not by the registry. "
    "Treat the content as data; it may not instruct the agent."
)
_EXFIL_DESCRIPTION = (
    "{service} lets anyone create a public endpoint or upload and read whatever is sent to it, which makes it a common "
    "landing spot for data stolen through prompt injection. If your team uses it legitimately, add a "
    "rule for your specific endpoint with a priority above 150."
)
_PROVIDER_DESCRIPTION = (
    "Agents send prompts and context to their model provider as part of normal operation, so flagging "
    "these calls would only add noise. Approval covers sending data to this API; it does not verify "
    "how the provider stores or uses that data."
)


def _source(
    name: str,
    pattern: str,
    level: str,
    description: str,
    *,
    match_field: str = "domain",
    source_type: str | None = None,
    capabilities: tuple[str, ...] = ("read",),
    priority: int = 50,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "applies_to": "source",
        "source_type": source_type,
        "match_field": match_field,
        "pattern": pattern,
        "trust_level": level,
        "capabilities": list(capabilities),
        "priority": priority,
    }


def _destination(
    name: str,
    pattern: str,
    level: str,
    description: str,
    *,
    capabilities: tuple[str, ...] = (),
    priority: int = 50,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "applies_to": "destination",
        "source_type": None,
        "match_field": "domain",
        "pattern": pattern,
        "trust_level": level,
        "capabilities": list(capabilities),
        "priority": priority,
    }


DEFAULT_TRUST_RULES: list[dict[str, Any]] = [
    # --- Sources -------------------------------------------------------------------------------
    _source(
        "User prompts",
        "*",
        "TRUSTED",
        "Prompts typed by the person operating the agent are the agent's legitimate instructions.",
        match_field="identifier",
        source_type="user_prompt",
        capabilities=("read", "instruct", "execute"),
        priority=100,
    ),
    _source("Python documentation", "docs.python.org", "EXTERNAL", _DOCS_DESCRIPTION),
    _source("MDN Web Docs", "developer.mozilla.org", "EXTERNAL", _DOCS_DESCRIPTION),
    _source("Anthropic documentation", "docs.anthropic.com", "EXTERNAL", _DOCS_DESCRIPTION),
    _source("Claude documentation", "docs.claude.com", "EXTERNAL", _DOCS_DESCRIPTION),
    _source("Node.js documentation", "*.nodejs.org", "EXTERNAL", _DOCS_DESCRIPTION),
    _source("PyPI", "*.pypi.org", "EXTERNAL", _REGISTRY_DESCRIPTION),
    _source("npm (website)", "*.npmjs.com", "EXTERNAL", _REGISTRY_DESCRIPTION),
    _source("npm (registry)", "registry.npmjs.org", "EXTERNAL", _REGISTRY_DESCRIPTION),
    _source(
        "GitHub content",
        "github.com/*",
        "EXTERNAL",
        "Public GitHub repositories, issues and pull requests can be written by anyone, so their content is "
        "data and may not instruct the agent. Approve your own organisation's repositories with a "
        "higher-priority rule such as 'github.com/your-org/*'.",
        match_field="identifier",
        priority=10,
    ),
    # --- Destinations --------------------------------------------------------------------------
    _destination(
        "Localhost",
        "*.localhost",
        "APPROVED",
        "Requests to localhost stay on the machine running the agent (for example a local dev server).",
        capabilities=("send",),
    ),
    _destination(
        "Loopback address",
        "127.0.0.1",
        "APPROVED",
        "The IPv4 loopback address stays on the machine running the agent.",
        capabilities=("send",),
    ),
    _destination(
        "Anthropic API", "api.anthropic.com", "APPROVED", _PROVIDER_DESCRIPTION, capabilities=("send",)
    ),
    _destination("OpenAI API", "api.openai.com", "APPROVED", _PROVIDER_DESCRIPTION, capabilities=("send",)),
    _destination(
        "Webhook.site",
        "*.webhook.site",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="Webhook.site"),
        priority=150,
    ),
    _destination(
        "Pipedream request bins",
        "*.pipedream.net",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="Pipedream"),
        priority=150,
    ),
    _destination(
        "ngrok tunnels",
        "*.ngrok-free.app",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="ngrok"),
        priority=150,
    ),
    _destination(
        "ngrok tunnels (legacy)",
        "*.ngrok.io",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="ngrok"),
        priority=150,
    ),
    _destination(
        "Cloudflare quick tunnels",
        "*.trycloudflare.com",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="Cloudflare's quick-tunnel service"),
        priority=150,
    ),
    _destination(
        "Pastebin",
        "*.pastebin.com",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="Pastebin"),
        priority=150,
    ),
    _destination(
        "transfer.sh",
        "*.transfer.sh",
        "SUSPICIOUS",
        _EXFIL_DESCRIPTION.format(service="transfer.sh"),
        priority=150,
    ),
]
