"""Approvals for Claude Code tool calls.

1. :func:`await_approval` holds a ``REQUIRE_APPROVAL`` call while a person decides in the ContextOS
   Approval Centre, polling ``GET /decide/approvals/{id}`` until it is decided or the wait (default
   45 s, always inside the hook's own timeout) runs out.

2. Host-prompt records. When the hook answers ``ask``, Claude Code shows ITS permission prompt and
   the person may approve the call there instead. The PreToolUse and PostToolUse hooks are separate
   processes, so the PreToolUse hook leaves a small record (ids and the reason only — never tool
   input) under ``~/.contextos/claude_code/host_prompts/`` and the PostToolUse hook attaches it to
   ``tool.completed``. The server then sees that the call ran because a person approved it at the
   Claude Code prompt, not because the hook ignored a decision (see ``state`` for storage).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from contextos.client import ContextOSClient, approval_status_of
from contextos.errors import ApprovalTimeout, ContextOSError
from contextos.models import ApprovalStatus

from . import state

log = logging.getLogger("contextos.claude_code.approval")

DECIDED = frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED})


@dataclass(frozen=True)
class ApprovalOutcome:
    """``status``: approved | rejected | expired | cancelled | pending (still undecided) | error."""

    approval_id: str
    status: str
    note: str | None = None
    error: str | None = None

    @property
    def approved(self) -> bool:
        return self.status == ApprovalStatus.APPROVED


def await_approval(client: ContextOSClient, approval_id: str, wait_s: float, poll_s: float = 1.5) -> ApprovalOutcome:
    """Wait up to ``wait_s`` for a person to decide. Never raises."""
    try:
        if wait_s <= 0:
            approval = client.get_approval(approval_id)
        else:
            approval = client.wait_for_approval(approval_id, timeout_s=wait_s, poll_s=max(0.2, poll_s))
    except ApprovalTimeout:
        return ApprovalOutcome(approval_id, ApprovalStatus.PENDING)
    except ContextOSError as exc:  # unreachable at the first poll, auth, 404 ...
        return ApprovalOutcome(approval_id, "error", error=str(exc))
    status = approval_status_of(approval) or "error"
    note = approval.get("decision_note") if isinstance(approval, dict) else None
    if status not in DECIDED and status != ApprovalStatus.PENDING:
        return ApprovalOutcome(approval_id, "error", error=f"unrecognised approval status '{status}'")
    return ApprovalOutcome(approval_id, status, note=str(note)[:500] if note else None)


# -- host-prompt records ----------------------------------------------------------------------------

HOST_PROMPTS = "host_prompts"


def remember_host_prompt(correlation_id: str, *, reason: str, approval_id: str | None = None,
                         policy_decision_id: str | None = None) -> None:
    """Record that the hook handed this call to Claude Code's own permission prompt."""
    state.put(HOST_PROMPTS, correlation_id,
              {"reason": reason, "approval_id": approval_id, "policy_decision_id": policy_decision_id})


def take_host_prompt(correlation_id: str) -> dict[str, Any] | None:
    """Return and delete the record for ``correlation_id`` (``None`` when the hook never asked)."""
    record = state.get(HOST_PROMPTS, correlation_id, remove=True)
    if not record:
        return None
    return {k: record[k] for k in ("reason", "approval_id", "policy_decision_id") if record.get(k)}


__all__ = ["HOST_PROMPTS", "ApprovalOutcome", "await_approval", "remember_host_prompt", "take_host_prompt"]
