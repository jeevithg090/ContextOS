"""Counterfactual policy replay (a SIMULATION, never history).

Each recorded ``PolicyDecision`` of a session is re-evaluated by the pure policy engine against its
stored, redacted ``input_snapshot`` under a hypothetical policy set:

* ``base`` "current" = every saved policy as configured now (disabled ones stay disabled unless an
  override enables them); "none" = no saved policies, so only drafts are evaluated.
* ``disable_policy_ids`` / ``overrides`` ({outcome?, mode?, enabled?}) change saved policies;
  ``add_policies`` are validated drafts (a draft with an ``id`` replaces that saved policy).

Events without a recorded decision, and decisions without a snapshot, are reported as not evaluable —
their inputs are never reconstructed. Each step also carries ``current_decision`` (today's saved
policies, unmodified) so drift caused by policy edits since the event is not mistaken for the effect of
the hypothetical change. Nothing is persisted, audited or returned to an integration.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationFailedError
from app.domain.enums import Decision, EventType
from app.engines.policy import EvaluationInput, EvaluationResult, PolicyMatch, PolicySpec, evaluate
from app.engines.policy.conditions import resolve
from app.engines.redaction import redact_value
from app.models import Agent, AgentSession, IngestedEvent, Organization, PolicyDecision
from app.schemas.replay import CounterfactualIn
from app.services.bootstrap import effective_org_settings
from app.services.loaders import load_policy_specs
from app.services.policy_service import definition_errors
from app.services.scoping import get_scoped
from app.services.sessions_service import timeline_query

MAX_DECISIONS = 2000
MAX_NOT_EVALUABLE_LISTED = 100
_BLOCKING = {Decision.DENY.value, Decision.REQUIRE_APPROVAL.value}
_ALLOWING = {Decision.ALLOW.value, Decision.AUDIT.value}
_TOOL_EVENTS = {EventType.TOOL_REQUESTED.value, EventType.TOOL_COMPLETED.value, EventType.TOOL_FAILED.value}


# ----------------------------------------------------------------------------- policy set


@dataclasses.dataclass
class _Entry:
    spec: PolicySpec
    source: str  # "saved" | "draft"
    changes: list[str]


def _override(entry: _Entry, override: Any) -> None:
    spec, changes = entry.spec, entry.changes
    updates: dict[str, Any] = {}
    if override.enabled is not None and override.enabled != spec.enabled:
        updates["enabled"] = override.enabled
        changes.append("enabled" if override.enabled else "disabled")
    if override.mode is not None and override.mode != spec.mode:
        updates["mode"] = override.mode
        changes.append(f"mode {spec.mode} → {override.mode}")
    if override.outcome is not None and override.outcome != str(spec.outcome).upper():
        if override.outcome == Decision.RESTRICT.value and not spec.restrictions:
            raise ValidationFailedError(
                "The hypothetical policy set is invalid",
                details={"errors": [f'overrides.{spec.id}: "{spec.name}" defines no restrictions, so it cannot be '
                                    "overridden to RESTRICT; add a draft RESTRICT policy instead"]},
            )
        updates["outcome"] = override.outcome
        if override.outcome != Decision.RESTRICT.value:
            updates["restrictions"] = {}
        changes.append(f"outcome {spec.outcome} → {override.outcome}")
    if updates:
        entry.spec = dataclasses.replace(spec, **updates)


def build_policy_set(db: Session, org_id: str, body: CounterfactualIn) -> tuple[list[_Entry], list[PolicySpec], list[str]]:
    """(hypothetical entries, today's saved specs, warnings). Raises 404/422 for invalid references."""
    ps = body.policy_set
    saved = load_policy_specs(db, org_id, include_disabled=True)
    by_id = {s.id: s for s in saved}
    for pid in [*ps.disable_policy_ids, *ps.overrides]:
        if pid not in by_id:
            raise NotFoundError(f"Policy '{pid}' not found")
    if ps.base == "none" and (ps.disable_policy_ids or ps.overrides):
        raise ValidationFailedError("The hypothetical policy set is invalid", details={"errors": [
            "disable_policy_ids and overrides change saved policies, which base 'none' excludes"]})
    both = sorted(set(ps.disable_policy_ids) & set(ps.overrides))
    if both:
        raise ValidationFailedError("The hypothetical policy set is invalid", details={"errors": [
            f"policy '{pid}' is both disabled and overridden; choose one" for pid in both]})

    entries: dict[str, _Entry] = {}
    if ps.base == "current":
        entries = {s.id: _Entry(s, "saved", []) for s in saved}
    for pid in dict.fromkeys(ps.disable_policy_ids):
        entry = entries[pid]
        if entry.spec.enabled:
            entry.spec = dataclasses.replace(entry.spec, enabled=False)
            entry.changes.append("disabled")
    for pid, override in ps.overrides.items():
        _override(entries[pid], override)

    warnings: list[str] = []
    errors: list[str] = []
    for n, draft in enumerate(ps.add_policies, start=1):
        loc = f"add_policies[{n - 1}]"
        problems = definition_errors(outcome=draft.outcome, conditions=draft.conditions,
                                     restrictions=draft.restrictions, name=draft.name, description=draft.description)
        errors += [f"{loc}: {p}" for p in problems]
        if problems:
            continue
        replaces = by_id.get(draft.id) if draft.id else None
        if draft.id and replaces is None:
            raise NotFoundError(f"Policy '{draft.id}' not found")
        draft_id = draft.id or f"draft-{n}"
        if not draft.enabled:
            warnings.append(f'Draft "{draft.name}" is disabled, so it cannot match anything')
        spec = PolicySpec(
            id=draft_id, name=draft.name, outcome=draft.outcome, conditions=draft.conditions,
            version=(replaces.version + 1) if replaces else 1, enabled=draft.enabled, mode=draft.mode,
            priority=draft.priority, severity=draft.severity, restrictions=draft.restrictions or {},
            description=draft.description,
        )
        entries[draft_id] = _Entry(spec, "draft", [f'replaces saved "{replaces.name}"'] if replaces else ["added"])
    if errors:
        raise ValidationFailedError("The hypothetical policy set is invalid", details={"errors": errors})
    if not any(e.spec.enabled for e in entries.values()):
        warnings.append("No enabled policy is in the hypothetical set; every decision falls back to the default")
    return list(entries.values()), saved, warnings


def _default_decision(db: Session, org_id: str, requested: str | None) -> str:
    if requested:
        return requested
    org = db.get(Organization, org_id)
    return str(effective_org_settings(org)["default_decision"]) if org else Decision.ALLOW.value


# ----------------------------------------------------------------------------- evidence


def _fields(node: Any, out: list[str], depth: int = 0) -> None:
    if depth > 32 or not isinstance(node, dict):
        return
    if isinstance(node.get("field"), str):
        out.append(node["field"])
    for key in ("all", "any"):
        if isinstance(node.get(key), list):
            for child in node[key]:
                _fields(child, out, depth + 1)
    if "not" in node:
        _fields(node["not"], out, depth + 1)


def _bounded(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= 300 else value[:299] + "…"
    if depth >= 3 and isinstance(value, dict | list):
        return "…"
    if isinstance(value, list):
        out = [_bounded(v, depth + 1) for v in value[:10]]
        return out + ([f"… {len(value) - 10} more"] if len(value) > 10 else [])
    if isinstance(value, dict):
        return {str(k): _bounded(v, depth + 1) for k, v in list(value.items())[:20]}
    return value


def _evidence(data: dict[str, Any], matches: list[PolicyMatch], specs: dict[str, PolicySpec]) -> list[dict[str, Any]]:
    """Snapshot values of every field the matching policies' conditions reference (already redacted;
    redacted again defensively before leaving the server)."""
    used: dict[str, list[str]] = {}
    for m in matches:
        spec = specs.get(m.policy_id)
        if spec is None:
            continue
        paths: list[str] = []
        _fields(spec.conditions, paths)
        for path in dict.fromkeys(paths):
            names = used.setdefault(path, [])
            if m.name not in names:
                names.append(m.name)
    out = []
    for path, names in used.items():
        try:
            found, values = resolve(data, path)
        except ValueError:
            found, values = False, []
        value = None
        if found:
            value = values[0] if len(values) == 1 and "*" not in path else values
            value, _ = redact_value(_bounded(value))
        out.append({"field": path, "present": found, "value": value, "policies": names})
    return out


# ----------------------------------------------------------------------------- comparison


def _match_out(m: PolicyMatch, drafts: set[str]) -> dict[str, Any]:
    return {**m.to_dict(), "draft": m.policy_id in drafts}


def _policy_changes(recorded: list[dict[str, Any]], result: EvaluationResult, entries: dict[str, _Entry],
                    base: str) -> list[dict[str, Any]]:
    hyp = {m.policy_id: m for m in result.matched}
    monitor = {m.policy_id for m in result.monitor_matches}
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in recorded:
        pid, name = str(rec.get("policy_id") or ""), str(rec.get("name") or rec.get("policy_id") or "policy")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        entry = entries.get(pid)
        if pid in hyp:
            if str(hyp[pid].outcome) != str(rec.get("outcome")).upper():
                changes.append({"policy_id": pid, "name": name, "change": "outcome_changed",
                                "detail": f"Still matches, but its outcome is {hyp[pid].outcome} instead of {rec.get('outcome')}"})
            continue
        if entry is None:
            detail = ("Not in the hypothetical set (base 'none' excludes saved policies)" if base == "none"
                      else "Deleted since this decision was recorded")
            changes.append({"policy_id": pid, "name": name, "change": "removed", "detail": detail})
        elif not entry.spec.enabled:
            detail = "Disabled in this simulation" if "disabled" in entry.changes else "Disabled since this decision"
            changes.append({"policy_id": pid, "name": name, "change": "disabled", "detail": detail})
        elif pid in monitor:
            changes.append({"policy_id": pid, "name": name, "change": "monitor",
                            "detail": "Matches in monitor mode, which is recorded only and never decides"})
        else:
            detail = "Its conditions do not match this recorded input"
            if isinstance(rec.get("version"), int) and rec["version"] != entry.spec.version:
                detail += f" (edited since: version {rec['version']} → {entry.spec.version})"
            changes.append({"policy_id": pid, "name": name, "change": "no_longer_matches", "detail": detail})
    for pid, m in hyp.items():
        if pid not in seen:
            origin = "draft" if entries.get(pid) and entries[pid].source == "draft" else "saved policy"
            changes.append({"policy_id": pid, "name": m.name, "change": "newly_matches",
                            "detail": f"This {origin} matches the recorded input ({m.outcome})"})
    return changes


def _explanation(original: str, enforcement: str, hypothetical: str, result: EvaluationResult) -> str:
    engine = result.explanation.strip().rstrip(".")
    if hypothetical != original:
        parts = [f"Hypothetically {hypothetical} instead of the recorded {original}", engine]
    else:
        parts = [f"Unchanged: the hypothetical policy set also returns {hypothetical}", engine]
    if hypothetical in _BLOCKING and hypothetical != original:
        if enforcement == "observed":
            parts.append("This call was only observed after it ran, so even this outcome could not have prevented "
                         "it — it would have been recorded, not enforced")
        elif enforcement == "advisory":
            parts.append("The integration was advisory, so it might not have honoured this outcome")
    return ". ".join(p for p in parts if p) + "."


# ----------------------------------------------------------------------------- service


def _not_evaluable(db: Session, org_id: str, session: AgentSession, agent: Agent) -> list[dict[str, Any]]:
    rows = db.execute(
        timeline_query(org_id, session, agent.name).with_only_columns(
            IngestedEvent.id, IngestedEvent.sequence, IngestedEvent.event_type, IngestedEvent.refs,
            IngestedEvent.processing_status,
        ).where(IngestedEvent.event_type.in_(_TOOL_EVENTS)).order_by(IngestedEvent.sequence)
    ).all()
    out = []
    for r in rows:
        refs = r.refs or {}
        if refs.get("policy_decision_id"):
            continue
        if r.processing_status == "error":
            out.append({"event_id": r.id, "sequence": r.sequence, "event_type": r.event_type,
                        "reason": "Processing failed for this event, so no policy decision was recorded"})
        elif r.event_type == EventType.TOOL_REQUESTED.value:
            out.append({"event_id": r.id, "sequence": r.sequence, "event_type": r.event_type,
                        "reason": "No policy decision was recorded for this tool request"})
    return out


def counterfactual(db: Session, org_id: str, body: CounterfactualIn) -> dict[str, Any]:
    session = get_scoped(db, AgentSession, body.session_id, org_id, label="Session")
    agent = get_scoped(db, Agent, session.agent_id, org_id, label="Agent")
    entries, saved, warnings = build_policy_set(db, org_id, body)
    default = _default_decision(db, org_id, body.default_decision)
    org_default = _default_decision(db, org_id, None)
    specs = [e.spec for e in entries]
    spec_by_id = {e.spec.id: e.spec for e in entries}
    entry_by_id = {e.spec.id: e for e in entries}
    drafts = {e.spec.id for e in entries if e.source == "draft"}

    rows = db.execute(
        select(PolicyDecision, IngestedEvent.sequence)
        .outerjoin(IngestedEvent, (IngestedEvent.id == PolicyDecision.event_id)
                   & (IngestedEvent.organization_id == org_id))
        .where(PolicyDecision.organization_id == org_id, PolicyDecision.session_id == session.id)
        .order_by(IngestedEvent.sequence.is_(None), IngestedEvent.sequence, PolicyDecision.evaluated_at)
        .limit(MAX_DECISIONS + 1)
    ).all()
    truncated = len(rows) > MAX_DECISIONS
    rows = rows[:MAX_DECISIONS]
    positions = {r.id: i for i, r in enumerate(db.execute(
        timeline_query(org_id, session, agent.name).with_only_columns(IngestedEvent.id)
        .order_by(IngestedEvent.sequence)).all())}

    not_evaluable = _not_evaluable(db, org_id, session, agent)
    steps: list[dict[str, Any]] = []
    summary = {"evaluated": 0, "changed": 0, "would_deny": 0, "would_pause": 0, "would_allow": 0,
               "would_restrict": 0, "drifted": 0, "transitions": {}}
    blocked = False
    for decision, sequence in rows:
        snapshot = decision.input_snapshot if isinstance(decision.input_snapshot, dict) else {}
        if not snapshot:
            not_evaluable.append({"event_id": decision.event_id, "sequence": sequence,
                                  "event_type": EventType.TOOL_REQUESTED.value,
                                  "policy_decision_id": decision.id,
                                  "reason": "The recorded decision has no input snapshot"})
            continue
        inp = EvaluationInput.from_dict(snapshot)
        data = inp.to_dict()
        result = evaluate(inp, specs, default_decision=default)
        current = evaluate(inp, saved, default_decision=org_default).decision
        original, hypothetical = str(decision.decision), result.decision
        changed = hypothetical != original
        recorded = [m for m in (decision.matched_policies or []) if isinstance(m, dict)]
        tool = data.get("tool") or {}
        steps.append({
            "decision_id": decision.id, "invocation_id": decision.tool_invocation_id, "event_id": decision.event_id,
            "sequence": sequence, "step_index": positions.get(decision.event_id or ""),
            "evaluated_at": decision.evaluated_at, "is_simulation": bool(decision.is_simulation),
            "tool": {"name": tool.get("name"), "category": tool.get("category")},
            "original_decision": original, "original_enforcement": decision.enforcement,
            "original_matches": [str(m.get("name") or m.get("policy_id")) for m in recorded],
            "original_explanation": decision.explanation or "",
            "hypothetical_decision": hypothetical, "changed": changed,
            "hypothetical_matches": [_match_out(m, drafts) for m in result.matched],
            "hypothetical_monitor_matches": [_match_out(m, drafts) for m in result.monitor_matches],
            "hypothetical_restrictions": result.restrictions, "evaluation_errors": result.evaluation_errors,
            "current_decision": current, "drifted": current != original,
            "policy_changes": _policy_changes(recorded, result, entry_by_id, body.policy_set.base),
            "explanation": _explanation(original, decision.enforcement, hypothetical, result),
            "evidence": _evidence(data, [*result.matched, *result.monitor_matches], spec_by_id),
            "after_hypothetical_block": blocked,
        })
        summary["evaluated"] += 1
        summary["changed"] += int(changed)
        summary["drifted"] += int(current != original)
        if hypothetical == Decision.DENY.value:
            summary["would_deny"] += 1
        elif hypothetical == Decision.REQUIRE_APPROVAL.value:
            summary["would_pause"] += 1
        elif hypothetical == Decision.RESTRICT.value:
            summary["would_restrict"] += 1
        elif hypothetical in _ALLOWING:
            summary["would_allow"] += 1
        if changed:
            key = f"{original}→{hypothetical}"
            summary["transitions"][key] = summary["transitions"].get(key, 0) + 1
        if (hypothetical == Decision.DENY.value and original != Decision.DENY.value) or (
                hypothetical == Decision.REQUIRE_APPROVAL.value and original not in _BLOCKING):
            blocked = True

    evaluated = sorted(entries, key=lambda e: (e.source != "draft", not e.changes, e.spec.name.casefold()))
    return {
        "session_id": session.id,
        "policy_set": {
            "base": body.policy_set.base, "default_decision": default, "warnings": warnings,
            "policies": [{"id": e.spec.id, "name": e.spec.name, "version": e.spec.version,
                          "outcome": str(e.spec.outcome).upper(), "mode": e.spec.mode, "enabled": e.spec.enabled,
                          "priority": e.spec.priority, "source": e.source, "changes": e.changes} for e in evaluated],
        },
        "steps": steps, "summary": summary,
        "not_evaluable_count": len(not_evaluable),
        "not_evaluable": not_evaluable[:MAX_NOT_EVALUABLE_LISTED],
        "truncated": truncated,
    }
