"""Policy engine (pure; no database access).

CONTRACT:

    evaluate(inp: EvaluationInput, policies: Sequence[PolicySpec]) -> EvaluationResult
        Deterministic. Enabled ENFORCE-mode matches decide the outcome by precedence
        DENY > REQUIRE_APPROVAL > RESTRICT > AUDIT > ALLOW (ties → higher priority, then name).
        MONITOR-mode matches are reported in ``monitor_matches`` and never change the decision.
        No match → ``default_decision`` (ALLOW unless the org configures AUDIT).

    validate_conditions(conditions) -> list[str]       # human-readable errors; [] = valid
    explain_conditions(conditions) -> str              # "tool.category is one of [http, email] AND ..."

Condition DSL (JSON):
    {"all": [cond, ...]} | {"any": [cond, ...]} | {"not": cond} |
    {"field": "<dotted path into EvaluationInput.to_dict()>", "op": <op>, "value": <json>}
    ops: eq, neq, in, not_in, contains, not_contains, glob, any_glob, exists, empty, not_empty,
         gt, gte, lt, lte, is_true, is_false
    An empty condition object matches nothing (never everything).

BUILTIN_POLICIES (app.engines.policy.builtin): the seed policy pack for new organisations.
"""

from app.engines.policy.engine import (
    EvaluationInput,
    EvaluationResult,
    PolicyMatch,
    PolicySpec,
    evaluate,
    explain_conditions,
    validate_conditions,
)

__all__ = [
    "EvaluationInput",
    "EvaluationResult",
    "PolicyMatch",
    "PolicySpec",
    "evaluate",
    "explain_conditions",
    "validate_conditions",
]
