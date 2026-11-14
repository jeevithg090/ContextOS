"""Policy Studio dry runs: evaluate policies against an input without side effects.

Results are simulations, not historical outcomes. A recorded decision is re-evaluated against its
stored, redacted ``input_snapshot`` only (missing history is never reconstructed); a hand-written
input has its arguments redacted first, as the ingestion pipeline does for real tool calls. The
organisation's ``default_decision`` applies when no policy matches. Nothing is persisted.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import PayloadTooLargeError, ValidationFailedError
from app.domain.enums import DECISION_PRECEDENCE
from app.engines.policy import EvaluationInput, PolicySpec, evaluate
from app.engines.redaction import redact_value
from app.models import Organization, PolicyDecision
from app.services.bootstrap import effective_org_settings
from app.services.loaders import load_policy_specs, policy_to_spec
from app.services.policy_service import definition_errors, get_policy
from app.services.scoping import get_scoped

DRAFT_ID = "draft"
MAX_TEST_INPUT_BYTES = 256 * 1024
_INPUT_FIELDS: dict[str, type] = {
    f.name: type(f.default_factory())
    for f in dataclasses.fields(EvaluationInput)  # type: ignore[misc]
}

__all__ = ["DRAFT_ID", "MAX_TEST_INPUT_BYTES", "org_default_decision", "run_policy_test"]


def _raise_if_invalid(errors: list[str], message: str) -> None:
    if errors:
        raise ValidationFailedError(message, details={"errors": errors})


def org_default_decision(db: Session, org_id: str) -> str:
    """The decision when no policy matches: the organisation's ``default_decision`` setting."""
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    return str(effective_org_settings(org)["default_decision"]) if org else "ALLOW"


def _prepare_input(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    if len(json.dumps(data, default=str)) > MAX_TEST_INPUT_BYTES:
        raise PayloadTooLargeError(f"The test input is larger than {MAX_TEST_INPUT_BYTES // 1024} KB")
    errors = [
        f"input.{key}: must be {'an object' if expected is dict else 'a list'}"
        for key, expected in _INPUT_FIELDS.items()
        if data.get(key) is not None and not isinstance(data[key], expected)
    ]
    _raise_if_invalid(errors, "The test input is not a valid evaluation input")
    unknown = sorted(k for k in data if k not in _INPUT_FIELDS)
    if unknown:
        warnings.append(f"Ignored unknown input keys: {', '.join(unknown)}")
    cleaned = {k: v for k, v in data.items() if k in _INPUT_FIELDS}
    if isinstance(cleaned.get("arguments"), dict):
        redacted, matches = redact_value(cleaned["arguments"])
        cleaned["arguments"] = redacted if isinstance(redacted, dict) else {}
        if matches:
            warnings.append(
                "Secrets in the test arguments were redacted before evaluation, as the ingestion "
                "pipeline does for real tool calls"
            )
    return cleaned


def _recorded(row: PolicyDecision) -> dict[str, Any]:
    matched = row.matched_policies if isinstance(row.matched_policies, list) else []
    return {
        "id": row.id,
        "session_id": row.session_id,
        "agent_id": row.agent_id,
        "decision": row.decision,
        "enforcement": row.enforcement,
        "evaluated_at": row.evaluated_at,
        "explanation": row.explanation or "",
        "matched_policy_names": [
            str(m.get("name")) for m in matched if isinstance(m, dict) and m.get("name")
        ],
        "is_simulation": bool(row.is_simulation),
    }


def run_policy_test(
    db: Session,
    org_id: str,
    *,
    draft: dict[str, Any] | None,
    policy_ids: list[str],
    with_org_policies: bool,
    input_data: dict[str, Any] | None,
    policy_decision_id: str | None,
) -> dict[str, Any]:
    """Evaluate policies against an input without side effects. The result is a simulation."""
    warnings: list[str] = []
    recorded = None
    if policy_decision_id:
        row = get_scoped(db, PolicyDecision, policy_decision_id, org_id, label="Policy decision")
        if not isinstance(row.input_snapshot, dict) or not row.input_snapshot:
            raise ValidationFailedError("This decision has no recorded input, so it cannot be re-evaluated")
        raw, source, recorded = dict(row.input_snapshot), "policy_decision", _recorded(row)
    else:
        raw, source = _prepare_input(input_data or {}, warnings), "input"
    inp = EvaluationInput.from_dict(raw)

    specs: dict[str, PolicySpec] = {}
    meta: dict[str, tuple[bool, bool]] = {}  # id -> (draft, forced_enabled)
    if with_org_policies:
        for spec in load_policy_specs(db, org_id):
            specs[spec.id], meta[spec.id] = spec, (False, False)
    for pid in dict.fromkeys(policy_ids):
        policy = get_policy(db, org_id, pid)
        spec = policy_to_spec(policy)
        if not policy.enabled:
            spec = dataclasses.replace(spec, enabled=True)
            warnings.append(
                f'"{policy.name}" is disabled; it was evaluated as if enabled to show whether it would match'
            )
        specs[spec.id], meta[spec.id] = spec, (False, not policy.enabled)
    if draft is not None:
        _raise_if_invalid(
            definition_errors(
                outcome=draft["outcome"],
                conditions=draft["conditions"],
                restrictions=draft.get("restrictions") or {},
            ),
            "The draft policy is invalid",
        )
        version = get_policy(db, org_id, draft["id"]).version if draft.get("id") else 1
        draft_id = draft.get("id") or DRAFT_ID
        if not draft.get("enabled", True):
            warnings.append(
                "The draft is disabled; it was evaluated as if enabled to show whether it would match"
            )
        specs[draft_id] = PolicySpec(
            id=draft_id,
            name=draft.get("name") or "Draft policy",
            outcome=draft["outcome"],
            conditions=draft["conditions"],
            version=version,
            enabled=True,
            mode=draft.get("mode", "enforce"),
            priority=draft.get("priority", 100),
            severity=draft.get("severity", "medium"),
            restrictions=draft.get("restrictions") or {},
            description=draft.get("description"),
        )
        meta[draft_id] = (True, not draft.get("enabled", True))

    default = org_default_decision(db, org_id)
    result = evaluate(inp, list(specs.values()), default_decision=default)
    evaluated = sorted(
        specs.values(),
        key=lambda s: (
            -DECISION_PRECEDENCE.get(str(s.outcome).upper(), -1),
            -int(s.priority),
            s.name.casefold(),
        ),
    )
    return {
        "decision": result.decision,
        "matched": [m.to_dict() for m in result.matched],
        "monitor_matches": [m.to_dict() for m in result.monitor_matches],
        "explanation": result.explanation,
        "restrictions": result.restrictions,
        "deciding_policy_id": result.deciding_policy_id,
        "evaluation_errors": result.evaluation_errors,
        "default_decision": default,
        "evaluated_policies": [
            {
                "id": s.id,
                "name": s.name,
                "version": s.version,
                "outcome": s.outcome,
                "mode": s.mode,
                "draft": meta[s.id][0],
                "forced_enabled": meta[s.id][1],
            }
            for s in evaluated
        ],
        "source": source,
        "recorded": recorded,
        "evaluated_input": inp.to_dict(),
        "warnings": warnings,
    }
