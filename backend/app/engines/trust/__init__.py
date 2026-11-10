"""Trust engine (pure; no database access).

CONTRACT:

    canonicalize_source(source_type, identifier) -> tuple[str, str | None]
        Canonical identifier (lower-cased host, stripped fragments/tracking params, normalised
        paths) and the registrable domain when applicable.

    assess_source(source_type, identifier, *, rules, history=None) -> TrustAssessment
        Contextual classification. Rules (TrustRuleSpec, highest priority first) set the level and
        capabilities; evidence in ``history`` (e.g. prior high-severity injection findings) can
        downgrade to SUSPICIOUS even for manually trusted sources, and says so in ``reasons``.
        Defaults with no rule: user_prompt/system → TRUSTED; tool_output/agent_output → inherit
        (caller passes ``inherited_level``); everything else → UNKNOWN (web/email/mcp → EXTERNAL
        only when a rule says so).

    assess_destination(kind, identifier, *, rules, history=None) -> DestinationAssessment
        Classification + the list of checks actually performed (allowlist match, blocklist match,
        raw IP, paste/webhook/tunnel service patterns, punycode/lookalike, first-seen). Never claims
        recipient identity verification. ``history`` (DestinationHistory, optional) lets the
        first-seen check report pass/warn instead of "unknown".

    DEFAULT_TRUST_RULES (in app.engines.trust.defaults): seed rules for new organisations.

    Helpers: glob_match(pattern, value) applies trust-rule glob semantics (see
    ``app.engines.trust.matching``); registrable_domain(host) returns the eTLD+1.
"""

from app.engines.trust.domains import registrable_domain
from app.engines.trust.engine import (
    DestinationAssessment,
    DestinationHistory,
    SourceHistory,
    TrustAssessment,
    TrustRuleSpec,
    assess_destination,
    assess_source,
    canonicalize_source,
)
from app.engines.trust.matching import glob_match

__all__ = [
    "DestinationAssessment",
    "DestinationHistory",
    "SourceHistory",
    "TrustAssessment",
    "TrustRuleSpec",
    "assess_destination",
    "assess_source",
    "canonicalize_source",
    "glob_match",
    "registrable_domain",
]
