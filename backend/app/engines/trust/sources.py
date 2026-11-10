"""Source assessment: how much an agent may rely on content from a given source.

Order of decisions (each step explains itself in ``reasons``):
1. Manual classification by an administrator, if any (wins over rules).
2. Otherwise the highest-priority enabled matching trust rule.
3. Otherwise a default for the source type.
4. Tool/agent output is capped at the trust of what it read ("inherited" level).
5. Evidence: high/critical findings observed in content from the source downgrade it to
   SUSPICIOUS (unless BLOCKED) and remove instruct/execute, even for manually trusted sources.
6. Invariants: BLOCKED has no capabilities; EXTERNAL/UNKNOWN/SUSPICIOUS content is data only.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.domain.enums import SEVERITY_RANK, TRUST_RANK, Severity, TrustCapability, TrustLevel
from app.engines.trust.canonical import canonicalize
from app.engines.trust.matching import describe_rule, domain_candidates, identifier_candidates, matching_rules
from app.engines.trust.specs import SourceHistory, TrustAssessment, TrustRuleSpec

T = TrustLevel
C = TrustCapability

DEFAULT_CAPABILITIES: dict[str, tuple[str, ...]] = {
    T.TRUSTED: (C.READ, C.INSTRUCT, C.EXECUTE),
    T.APPROVED: (C.READ,),
    T.EXTERNAL: (C.READ,),
    T.UNKNOWN: (C.READ,),
    T.SUSPICIOUS: (C.READ,),
    T.BLOCKED: (),
}
SOURCE_CAPABILITIES = frozenset({C.READ, C.INSTRUCT, C.EXECUTE, C.CREDENTIAL_ACCESS})
DATA_ONLY_LEVELS = frozenset({T.EXTERNAL, T.UNKNOWN, T.SUSPICIOUS})
_VALID_LEVELS = frozenset(level.value for level in TrustLevel)

_TYPE_LABELS = {
    "web": "web page", "repository": "repository", "file": "file", "document": "document", "email": "email",
    "api": "API response", "mcp_server": "MCP server", "mcp_tool": "MCP tool", "browser": "browser page",
    "database": "database", "user_upload": "uploaded file", "user_prompt": "user prompt", "tool_output": "tool output",
    "agent_output": "sub-agent output", "system": "system prompt", "other": "source",
}
_PRODUCED_TYPES = frozenset({"tool_output", "agent_output"})


def _producer(source_type: str) -> str:
    return "a sub-agent" if source_type == "agent_output" else "a tool"


def _capabilities(level: str, requested: Sequence[str]) -> tuple[list[str], list[str]]:
    """(applied, dropped) capabilities for ``level`` given what a rule or admin asked for."""

    wanted = [str(c) for c in requested if c in SOURCE_CAPABILITIES] if requested else list(DEFAULT_CAPABILITIES[level])
    if level == T.BLOCKED:
        return [], wanted
    if level in DATA_ONLY_LEVELS:
        applied = [c for c in wanted if c == C.READ]
        return applied, [c for c in wanted if c != C.READ]
    return list(dict.fromkeys(wanted)), []


def _default(source_type: str, history: SourceHistory) -> tuple[str, str]:
    label = _TYPE_LABELS.get(source_type, "source")
    if source_type == "user_prompt":
        return T.TRUSTED, "User prompts come from the person operating the agent, so they are trusted to give instructions."
    if source_type == "system":
        return T.TRUSTED, "System prompts are set by whoever configured the agent, so they are trusted to give instructions."
    if source_type in _PRODUCED_TYPES:
        inherited = history.inherited_level
        if inherited in _VALID_LEVELS:
            return inherited, (
                f"This is output from {_producer(source_type)}, so it inherits the trust of what it read: the least "
                f"trusted input was {inherited}. Output is never treated as more trusted than what it read."
            )
        return T.UNKNOWN, (
            f"This is output from {_producer(source_type)} and nothing was recorded about what it read, so it is "
            "treated as UNKNOWN: its content is data, not instructions."
        )
    if source_type in ("file", "repository"):
        return T.UNKNOWN, (
            f"No trust rule classifies this {label}, so it is UNKNOWN: its content is treated as data, not instructions."
        )
    return T.UNKNOWN, (
        f"No trust rule matches this {label}, so it is UNKNOWN: its content is treated as data, not instructions. "
        "Add a trust rule to classify it."
    )


def _evidence_reason(prefix: str, history: SourceHistory, outcome: str) -> str:
    count = history.finding_count
    noun = "finding was" if count == 1 else "findings were"
    return (
        f"{prefix}, but {count} {noun} observed in content from this source (highest severity: "
        f"{history.max_finding_severity}); {outcome}"
    )


def assess_source(
    source_type: str, identifier: str, *, rules: Sequence[TrustRuleSpec], history: SourceHistory | None = None
) -> TrustAssessment:
    history = history or SourceHistory()
    st = (source_type or "other").strip().lower()
    canonical = canonicalize(st, identifier)
    host = canonical.host.host if canonical.host else None
    matches = matching_rules(
        rules,
        scope="source",
        source_type=st,
        identifiers=identifier_candidates(canonical.identifier) if canonical.identifier else [],
        domains=domain_candidates(host, canonical.domain),
    )
    rule = matches[0] if matches else None
    reasons: list[str] = []
    matched_rule_id: str | None = None
    requested: Sequence[str]

    manual = history.manually_classified and history.current_level in _VALID_LEVELS
    if manual:
        level = str(history.current_level)
        requested = history.current_capabilities
        basis = f"It was manually classified as {level}"
        reasons.append(
            f"An administrator manually classified this source as {level}; manual classification takes "
            "precedence over trust rules."
        )
        if rule is not None and rule.trust_level != level:
            reasons.append(f"Without it, {describe_rule(rule)} would classify it as {rule.trust_level}.")
    elif rule is not None:
        level, requested, matched_rule_id = rule.trust_level, rule.capabilities, rule.id
        basis = f"Trust rule '{rule.name}' classifies it as {level}"
        reasons.append(f"Matches {describe_rule(rule)}, which classifies it as {level}.")
    else:
        level, reason = _default(st, history)
        requested = ()
        basis = f"By default it would be {level}"
        reasons.append(reason)

    capabilities, dropped = _capabilities(level, requested)
    if dropped and level != T.BLOCKED:
        listed = ", ".join(f"'{c}'" for c in dropped)
        reasons.append(
            f"{level} content is always treated as data, so the requested {listed} "
            f"{'capability was' if len(dropped) == 1 else 'capabilities were'} not applied."
        )

    # A tool's or sub-agent's output is never more trusted than what it read.
    inherited = history.inherited_level
    if st in _PRODUCED_TYPES and (manual or rule is not None) and inherited in _VALID_LEVELS:
        if TRUST_RANK[inherited] < TRUST_RANK[level]:
            level = str(inherited)
            capabilities = [c for c in capabilities if c in DEFAULT_CAPABILITIES[level]]
            basis = f"Capped at {level} by what it read"
            reasons.append(
                f"It was produced by {_producer(st)} that read {level} content, and output is never treated as "
                f"more trusted than what it read, so it is capped at {level}."
            )

    severity = history.max_finding_severity
    high = SEVERITY_RANK[Severity.HIGH]
    if history.finding_count > 0 and severity in SEVERITY_RANK:
        if SEVERITY_RANK[severity] >= high:
            if level == T.BLOCKED:
                reasons.append(_evidence_reason(basis, history, "it remains BLOCKED."))
            elif level == T.SUSPICIOUS:
                reasons.append(_evidence_reason(basis, history, "it stays SUSPICIOUS until they are reviewed."))
                capabilities = [c for c in capabilities if c == C.READ]
            else:
                reasons.append(_evidence_reason(
                    basis, history, "it is treated as SUSPICIOUS until the findings are reviewed, and may not "
                    "give instructions or trigger tools.",
                ))
                level = T.SUSPICIOUS.value
                capabilities = [c for c in capabilities if c == C.READ]
        else:
            noun = "finding was" if history.finding_count == 1 else "findings were"
            reasons.append(
                f"{history.finding_count} lower-severity {noun} observed in content from this source (highest "
                f"severity: {severity}); this does not change the classification."
            )

    return TrustAssessment(
        level=str(level),
        capabilities=[str(c) for c in capabilities],
        reasons=reasons,
        matched_rule_id=matched_rule_id,
        canonical_identifier=canonical.identifier,
        domain=canonical.domain,
    )
