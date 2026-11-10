"""Policy engine (pure; no database access).

CONTRACT:

    evaluate(inp: EvaluationInput, policies: Sequence[PolicySpec]) -> EvaluationResult
        Deterministic. Enabled ENFORCE-mode matches decide the outcome by precedence
        DENY > REQUIRE_APPROVAL > RESTRICT > AUDIT > ALLOW (ties → higher priority, then name).
        MONITOR-mode matches are reported in ``monitor_matches`` and never change the decision.
        No match → ``default_decision`` (ALLOW unless the org configures AUDIT), with the explanation
        "No policy matched; default <X> applied". When RESTRICT wins, ``restrictions`` merges every
        matching RESTRICT policy (see ``restrictions.py``; integrations that cannot apply them must
        treat RESTRICT as DENY). Policies that cannot be evaluated never match and are listed in
        ``EvaluationResult.evaluation_errors``.

    validate_conditions(conditions) -> list[str]       # human-readable errors; [] = valid
    explain_conditions(conditions) -> str              # "tool.category is one of [http, email] AND ..."
    validate_restrictions(restrictions, outcome=None) -> list[str]

Condition DSL (JSON):
    {"all": [cond, ...]} | {"any": [cond, ...]} | {"not": cond} |
    {"field": "<dotted path into EvaluationInput.to_dict()>", "op": <op>, "value": <json>}
    ops: eq, neq, in, not_in, contains, not_contains, glob, any_glob, exists, empty, not_empty,
         gt, gte, lt, lte, is_true, is_false
    An empty condition object matches nothing (never everything).
    ``[*]`` in a path means "any element"; missing fields make a leaf false. Full semantics in
    ``conditions.py``; the field catalog (``FIELD_CATALOG``, served by GET /policies/fields) in
    ``fields.py``.

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
from app.engines.policy.fields import FIELD_CATALOG, OPERATORS
from app.engines.policy.restrictions import RESTRICTION_KEYS, validate_restrictions

__all__ = [
    "FIELD_CATALOG",
    "OPERATORS",
    "RESTRICTION_KEYS",
    "EvaluationInput",
    "EvaluationResult",
    "PolicyMatch",
    "PolicySpec",
    "evaluate",
    "explain_conditions",
    "validate_conditions",
    "validate_restrictions",
]
