"""Policy evaluation: which enabled policies match a tool request, and what ContextOS decides.

The data types live in :mod:`app.engines.policy.spec` and are re-exported here; the field names of
``EvaluationInput`` are the DSL's field paths and are persisted in ``PolicyDecision.input_snapshot``.
Condition semantics: :mod:`app.engines.policy.conditions`. RESTRICT semantics (and the fail-closed
rule for integrations that cannot apply restrictions): :mod:`app.engines.policy.restrictions`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.domain.enums import DECISION_PRECEDENCE, Decision, PolicyMode
from app.engines.policy.conditions import ConditionError, Outcome, evaluate_condition, explain
from app.engines.policy.restrictions import describe_restrictions, merge_restrictions
from app.engines.policy.spec import EvaluationInput, EvaluationResult, PolicyMatch, PolicySpec
from app.engines.policy.validation import validate_conditions

__all__ = [
    "EvaluationInput",
    "EvaluationResult",
    "PolicyMatch",
    "PolicySpec",
    "evaluate",
    "explain_conditions",
    "validate_conditions",
]

_MODES = {m.value for m in PolicyMode}


def _decision(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    upper = value.strip().upper()
    return upper if upper in DECISION_PRECEDENCE else None


def _match_explanation(outcome: Outcome) -> str:
    text = "Matched because " + " AND ".join(outcome.evidence)
    missing = sorted(set(outcome.missing))
    if missing:
        text += f". Not present in the input: {', '.join(missing)}"
    return text


def _sort_key(item: tuple[PolicySpec, PolicyMatch]) -> tuple[int, int, str, str]:
    spec, match = item
    return (-DECISION_PRECEDENCE[match.outcome], -int(spec.priority), spec.name.casefold(), spec.id)


def _names(items: list[tuple[PolicySpec, PolicyMatch]]) -> str:
    return ", ".join(f'"{m.name}" ({m.outcome})' for _, m in items)


def evaluate(
    inp: EvaluationInput, policies: Sequence[PolicySpec], *, default_decision: str = "ALLOW"
) -> EvaluationResult:
    """Evaluate ``policies`` against one (redacted) tool request. Deterministic and side-effect free."""
    default = _decision(default_decision)
    if default is None:
        raise ValueError(f"default_decision must be one of {sorted(DECISION_PRECEDENCE)}, got {default_decision!r}")
    data = inp.to_dict()
    enforce: list[tuple[PolicySpec, PolicyMatch]] = []
    monitor: list[tuple[PolicySpec, PolicyMatch]] = []
    errors: list[dict[str, str]] = []

    for spec in policies:
        if not spec.enabled:
            continue
        outcome = _decision(spec.outcome)
        mode = spec.mode.strip().lower() if isinstance(spec.mode, str) else ""
        if outcome is None:
            errors.append({"policy_id": spec.id, "name": spec.name, "error": f"unknown outcome {spec.outcome!r}"})
            continue
        if mode not in _MODES:
            errors.append({"policy_id": spec.id, "name": spec.name, "error": f"unknown mode {spec.mode!r}"})
            continue
        try:
            result = evaluate_condition(spec.conditions, data)
        except ConditionError as exc:
            errors.append({"policy_id": spec.id, "name": spec.name, "error": f"invalid conditions: {exc}"})
            continue
        if not result.matched:
            continue
        match = PolicyMatch(
            policy_id=spec.id,
            name=spec.name,
            version=spec.version,
            outcome=outcome,
            mode=mode,
            severity=str(spec.severity).lower(),
            explanation=_match_explanation(result),
        )
        (enforce if mode == PolicyMode.ENFORCE else monitor).append((spec, match))

    enforce.sort(key=_sort_key)
    monitor.sort(key=_sort_key)
    tail: list[str] = []
    if monitor:
        tail.append(f"Monitor mode (recorded only, not enforced): {_names(monitor)} would have applied")
    if errors:
        listed = "; ".join(f'"{e["name"]}" ({e["error"]})' for e in errors)
        tail.append(f"Could not evaluate {len(errors)} {'policy' if len(errors) == 1 else 'policies'}: {listed}")

    if not enforce:
        return EvaluationResult(
            decision=default,
            matched=[],
            monitor_matches=[m for _, m in monitor],
            explanation=". ".join([f"No policy matched; default {default} applied", *tail]),
            restrictions={},
            deciding_policy_id=None,
            evaluation_errors=errors,
        )

    top_spec, top = enforce[0]
    decision = top.outcome
    restrictions: dict[str, Any] = {}
    parts = [f'{decision} by policy "{top.name}" ({top.severity}, priority {top_spec.priority}). {top.explanation}']
    if decision == Decision.RESTRICT:
        merged, problems = merge_restrictions(
            [(s.name, s.restrictions) for s, m in enforce if m.outcome == Decision.RESTRICT]
        )
        if not merged and not problems:
            problems = ["the matching RESTRICT policies define no restrictions"]
        if problems:
            # Restrictions that cannot be expressed cannot be applied: fail closed.
            decision = Decision.DENY.value
            errors = errors + [{"policy_id": top.policy_id, "name": top.name, "error": p} for p in problems]
            parts = [
                f'DENY (fail closed): policy "{top.name}" requires RESTRICT but its restrictions cannot be '
                f"applied ({'; '.join(problems)}). {top.explanation}"
            ]
        else:
            restrictions = merged
            parts.append(f"Restrictions: {describe_restrictions(merged)}")
    if len(enforce) > 1:
        parts.append(f"Also matched: {_names(enforce[1:])}")
    return EvaluationResult(
        decision=decision,
        matched=[m for _, m in enforce],
        monitor_matches=[m for _, m in monitor],
        explanation=". ".join([*parts, *tail]),
        restrictions=restrictions,
        deciding_policy_id=top.policy_id,
        evaluation_errors=errors,
    )


def explain_conditions(conditions: dict[str, Any]) -> str:
    """Readable English, e.g. ``tool.category is one of [http, email] AND secrets_in_arguments is not empty``."""
    return explain(conditions)
