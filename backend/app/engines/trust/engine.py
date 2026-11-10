"""Trust engine public functions (contract in ``app.engines.trust.__init__``).

Implementation is split by responsibility:
- ``canonical``    identifier canonicalisation (URLs, repositories, paths, emails, MCP names)
- ``domains``      host canonicalisation, IP parsing, registrable domains
- ``matching``     trust-rule glob semantics and rule precedence
- ``sources``      ``assess_source``
- ``destinations`` ``assess_destination`` and its checks
- ``lookalike`` / ``services``  lookalike-domain and exfiltration-service knowledge
"""

from __future__ import annotations

from app.engines.trust.canonical import canonicalize
from app.engines.trust.destinations import assess_destination
from app.engines.trust.sources import assess_source
from app.engines.trust.specs import (
    DestinationAssessment,
    DestinationHistory,
    SourceHistory,
    TrustAssessment,
    TrustRuleSpec,
)


def canonicalize_source(source_type: str, identifier: str) -> tuple[str, str | None]:
    """Canonical identifier and registrable domain (None when the identifier names no host).

    Examples::

        ("web", "HTTPS://Docs.Example.com:443/a/./b/?utm_source=x#top") -> ("https://docs.example.com/a/b", "example.com")
        ("repository", "git@github.com:Acme/API.git")                    -> ("github.com/acme/api", "github.com")
        ("file", "/srv/app/../app/./config.yaml")                        -> ("/srv/app/config.yaml", None)
        ("mcp_tool", "mcp__GitHub__create_issue")                         -> ("github/create_issue", None)
    """

    canonical = canonicalize(source_type, identifier)
    return canonical.identifier, canonical.domain


__all__ = [
    "DestinationAssessment",
    "DestinationHistory",
    "SourceHistory",
    "TrustAssessment",
    "TrustRuleSpec",
    "assess_destination",
    "assess_source",
    "canonicalize_source",
]
