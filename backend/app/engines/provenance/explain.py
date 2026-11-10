"""Plain-language titles, explanations and evidence lines for risky provenance paths.

Wording rules: describe what ContextOS observed ("entered", "accessed", "sent"), never that content
"caused" an action; describe enforcement honestly (prevented only at an enforced boundary); always end
with the observed-relationship disclaimer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.domain.enums import Decision, ProvenanceNodeType, TrustLevel
from app.engines.provenance._util import OBSERVED_RELATIONSHIP_NOTE
from app.engines.provenance.signals import (
    ADVISORY_ONLY,
    AWAITING_APPROVAL,
    NOT_PREVENTED,
    PREVENTED,
    Detection,
    InvocationAnalysis,
    Leaf,
)

_LABEL_MAX = 60
_RULES_LISTED = 4
_TRUST_WORD: dict[str, str] = {
    TrustLevel.BLOCKED: "Blocked",
    TrustLevel.SUSPICIOUS: "Suspicious",
    TrustLevel.UNKNOWN: "Unclassified",
    TrustLevel.EXTERNAL: "External",
}
_TYPE_WORD: dict[str, str] = {
    ProvenanceNodeType.SOURCE: "source",
    ProvenanceNodeType.CONTEXT_ITEM: "context item",
    ProvenanceNodeType.SESSION: "session",
}


@dataclass(frozen=True)
class Story:
    origin: Mapping[str, Any]
    origin_trust: str
    origin_untrusted: bool
    detection: Detection
    injection: bool
    sessions: list[Mapping[str, Any]]
    sink: InvocationAnalysis
    siblings: list[InvocationAnalysis]
    secrets: bool
    order_verified: bool
    inferred_count: int


def quote(label: Any) -> str:
    text = str(label)
    if len(text) > _LABEL_MAX:
        text = text[: _LABEL_MAX - 1] + "…"
    return f'"{text}"'


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _labels(leaves: list[Leaf]) -> str:
    return _join([quote(leaf.label) for leaf in leaves])


def _sensitive_target(inv: InvocationAnalysis) -> str:
    if not inv.sensitive_resources:
        return "sensitive data"
    noun = "resource" if len(inv.sensitive_resources) == 1 else "resources"
    return f"sensitive {noun} {_labels(inv.sensitive_resources)}"


def _sibling_action(inv: InvocationAnalysis) -> str:
    if not inv.sensitive:
        return f"{inv.tool_label} returned content containing secrets ({_labels(inv.secret_items)})"
    action = f"{inv.tool_label} accessed {_sensitive_target(inv)}"
    return action + (" and returned content containing secrets" if inv.secret_items else "")


def _type_word(node: Mapping[str, Any]) -> str:
    return _TYPE_WORD.get(str(node.get("type")), str(node.get("type") or "node").replace("_", " "))


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _origin_phrase(story: Story) -> str:
    word = _TRUST_WORD.get(story.origin_trust, "Flagged") if story.origin_untrusted else "Flagged"
    return f"{word} {_type_word(story.origin)} {quote(story.origin['label'])}"


def _policy_verb(sink: InvocationAnalysis) -> str:
    if sink.status == "rejected":
        return "rejected"
    if sink.decision == Decision.REQUIRE_APPROVAL.value:
        return "held for approval"
    return "denied"


def _ran(sink: InvocationAnalysis) -> bool:
    """Only an unprevented call is described as having happened; others are described as attempts."""
    return sink.outcome == NOT_PREVENTED


def _action_phrase(story: Story) -> str:
    sink = story.sink
    tool = sink.tool_label
    if _ran(sink):
        access, send = "accessing", "sending data to"
    else:
        access, send = "attempting to access", "attempting to send data to"
    dest = quote(sink.destinations[0].label) if sink.destinations else None
    if sink.outbound and sink.sensitive:
        target = _labels(sink.sensitive_resources) or "sensitive data"
        return f"{tool} {access} {target} and {send} {dest}"
    if sink.outbound and story.siblings:
        return f"sensitive access and {tool} {send} {dest}"
    if sink.outbound:
        return f"{tool} {send} {sink.worst_destination} destination {dest}"
    if sink.sensitive:
        target = _labels(sink.sensitive_resources) or "sensitive data"
        return f"{tool} {access} {target}"
    return f"a {tool} call that policy {_policy_verb(sink)}"


def title(story: Story) -> str:
    verb = "preceded" if story.order_verified else "is linked to"
    suffix = " in a delegated session" if len(story.sessions) > 1 else ""
    return f"{_origin_phrase(story)} {verb} {_action_phrase(story)}{suffix}"


def _detection_clause(det: Detection) -> str:
    if det.max_severity is None:
        return ""
    rules = list(det.rule_ids[:_RULES_LISTED])
    more = len(det.rule_ids) - len(rules)
    listed = ", ".join(rules) + (f" and {more} more" if more > 0 else "")
    return f"; content on this path was flagged by detection at {det.max_severity} severity" + (
        f" ({listed})" if listed else ""
    )


def _sink_sentence(sink: InvocationAnalysis) -> str:
    access, send = ("accessed", "sent data to") if _ran(sink) else ("requested access to", "tried to send data to")
    actions = []
    if sink.sensitive_resources:
        actions.append(f"{access} {_sensitive_target(sink)}")
    elif sink.sensitive_flag:
        actions.append("involved data ContextOS marked as sensitive")
    for dest in sink.destinations:
        actions.append(f"{send} {quote(dest.label)} (classified {dest.classification})")
    if not actions:
        actions.append("was requested")
    sentence = f"{sink.tool_label} {_join(actions)}."
    if sink.secret_items:
        sentence += f" It returned content containing secrets ({_labels(sink.secret_items)})."
    return sentence


def _secret_sentence(story: Story) -> str:
    matched = story.sink.matched_fingerprints
    if matched:
        return (
            f"Its arguments contained {_plural(matched, 'secret fingerprint')} previously seen in this "
            "session's context — an inferred match by keyed fingerprint; raw secrets are never stored."
        )
    if story.secrets:
        return "Secrets were detected in the data involved (ContextOS keeps only their fingerprints)."
    return ""


def outcome_sentence(sink: InvocationAnalysis) -> str:
    decision = sink.decision
    if sink.outcome == PREVENTED:
        if sink.status == "rejected":
            return "A human rejected the approval request at an enforced execution boundary, so the call was prevented."
        return f"Policy returned {decision or 'a block'} at an enforced execution boundary, so the call was prevented."
    if sink.outcome == AWAITING_APPROVAL:
        return "Policy required human approval at an enforced execution boundary; the call is held until someone decides."
    if sink.outcome == ADVISORY_ONLY:
        return (f"Policy returned {decision or 'a block'} in advisory mode; ContextOS cannot confirm the "
                "integration honoured it.")
    if decision == Decision.DENY.value or sink.status in ("denied", "rejected"):
        return ("Policy flagged the call, but it was reported after it ran (observed), so nothing was prevented.")
    if decision == Decision.REQUIRE_APPROVAL.value:
        return "A human approved the call, so it was not prevented."
    if decision == Decision.RESTRICT.value:
        return "Policy allowed the call with restrictions; it was not prevented."
    if decision:
        return f"Policy returned {decision}; the call was not prevented."
    return "No blocking policy decision was recorded, so the call was not prevented."


def explanation(story: Story) -> str:
    origin = story.origin
    parts = [
        f"ContextOS recorded {_type_word(origin)} {quote(origin['label'])} with trust {story.origin_trust}"
        f"{_detection_clause(story.detection)}."
    ]
    if story.injection:
        parts.append("The detections include prompt-injection or instruction-override patterns.")
    if story.sessions:
        first, rest = story.sessions[0], story.sessions[1:]
        sentence = f"That content entered session {quote(first['label'])}"
        if rest:
            sentence += (", which handed work to " + _join([quote(s["label"]) for s in rest])
                         + " (a delegation or agent message), so the later session is downstream of the same content")
        parts.append(sentence + ".")
    for sibling in story.siblings:
        parts.append(f"In the same session, {_sibling_action(sibling)}.")
    parts.append(_sink_sentence(story.sink))
    secret = _secret_sentence(story)
    if secret:
        parts.append(secret)
    parts.append(outcome_sentence(story.sink))
    if not story.order_verified:
        parts.append("Timestamps were missing for at least one step, so the order of these events is not confirmed.")
    if story.inferred_count:
        parts.append(f"{_plural(story.inferred_count, 'relationship')} on this path "
                     f"{'was' if story.inferred_count == 1 else 'were'} inferred by ContextOS rather than directly reported.")
    parts.append(OBSERVED_RELATIONSHIP_NOTE)
    return " ".join(parts)


def reasons(story: Story) -> list[str]:
    sink = story.sink
    lines = [f"Origin {quote(story.origin['label'])}: trust {story.origin_trust}"]
    det = story.detection
    if det.max_severity:
        rules = ", ".join(det.rule_ids[:_RULES_LISTED])
        lines.append(f"Detections up to {det.max_severity} severity" + (f" ({rules})" if rules else ""))
    if story.injection:
        lines.append("Prompt-injection or instruction-override patterns detected upstream")
    if len(story.sessions) > 1:
        lines.append(f"Crossed {len(story.sessions)} sessions via delegation or agent messages")
    for sibling in story.siblings:
        lines.append(_sibling_action(sibling))
    access, send = ("accessed", "sent data to") if _ran(sink) else ("requested access to", "tried to send data to")
    if sink.sensitive_resources:
        lines.append(f"{sink.tool_label} {access} {_sensitive_target(sink)}")
    elif sink.sensitive_flag:
        lines.append(f"{sink.tool_label} involved sensitive data")
    for dest in sink.destinations:
        lines.append(f"{sink.tool_label} {send} {quote(dest.label)} ({dest.classification})")
    if sink.matched_fingerprints:
        lines.append("A session secret fingerprint matched the call's arguments (inferred)")
    elif story.secrets:
        lines.append("Secrets involved")
    if sink.policy_flagged and not (sink.sensitive or sink.outbound):
        lines.append(f"Policy {_policy_verb(sink)} the {sink.tool_label} call")
    lines.append("Outcome: " + sink.outcome.replace("_", " "))
    return lines
