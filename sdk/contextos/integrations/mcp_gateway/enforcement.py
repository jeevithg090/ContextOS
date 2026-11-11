"""What the gateway does with each ContextOS answer to a ``tools/call``.

    ALLOW / AUDIT       forward the call to the upstream server
    DENY                do NOT contact the upstream server; return an error result to the host
    REQUIRE_APPROVAL    poll the approval for up to ``approval_timeout_s``; forward only when it is
                        approved, otherwise block (rejected, expired, cancelled or still pending). A
                        request the gateway stops waiting for (timeout, ``approval_timeout_s=0``, the
                        host cancelling the call) is withdrawn, so it can no longer be approved
    RESTRICT            apply every restriction (``contextos.restrictions``) and forward the
                        restricted arguments; any restriction the gateway cannot apply blocks the
                        call (fail closed)
    anything else       block (fail closed)

When ContextOS cannot be reached or fails while deciding (network error, timeout, 5xx) the fail
mode decides: ``closed`` (the default, because the gateway is an enforcement point) blocks the
call; ``open`` forwards it WITHOUT a decision and logs a warning. Either way the attempt is spooled
so ContextOS records it later (as observed, not enforced). A rejected or under-scoped API key and
any other 4xx answer always block.

Path restrictions: an MCP tool is opaque to the gateway, so only paths passed as arguments can be
checked. A call with a command-like argument (``command``, ``script``, ``code``...) may touch files
it does not name, so path restrictions on it block the call instead of being trusted.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import anyio
import anyio.to_thread

from contextos._args import to_jsonable
from contextos.client import ContextOSClient, approval_status_of, withdraw_approval
from contextos.errors import APIError, AuthError, ContextOSError, ServerError, Unreachable
from contextos.models import ApprovalStatus, Decision, DecisionResponse, EventEnvelope
from contextos.restrictions import OPAQUE_ARGUMENT_NAMES, apply_restrictions, scan_reports_secrets

log = logging.getLogger("contextos.mcp_gateway")

FAIL_MODES = ("closed", "open")
_REASON_CHARS = 1_500
# Argument names whose value is a program: files it touches are invisible to the gateway.

WaitCallback = Callable[[float, float, str], Awaitable[None]]


@dataclass
class Verdict:
    """Whether one call may be forwarded, with the arguments to forward and a plain-language message."""

    allowed: bool
    message: str
    arguments: dict[str, Any]
    decision: DecisionResponse | None = None
    outcome: str = ""  # allow | audit | approved | restricted | fail_open | denied | approval_* | fail_closed | ...
    fail_open: bool = False
    restrictions_applied: list[str] = field(default_factory=list)


def _clip(text: str | None, limit: int = _REASON_CHARS) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def deciding_policy(decision: DecisionResponse) -> str | None:
    """Name of the policy that produced the decision (first matched policy with the same outcome)."""
    matches = [m for m in decision.matched_policies if isinstance(m, Mapping) and m.get("name")]
    for match in matches:
        if str(match.get("outcome", "")).upper() == decision.decision.upper():
            return str(match["name"])
    return str(matches[0]["name"]) if matches else None


def policy_block_message(decision: DecisionResponse, detail: str | None = None) -> str:
    """``Blocked by ContextOS policy '<name>': <reason>`` (+ decision id), as shown to the agent."""
    policy = deciding_policy(decision)
    head = f"Blocked by ContextOS policy '{policy}'" if policy else f"Blocked by ContextOS ({decision.decision})"
    reason = _clip(decision.reason).rstrip(". ") or "no reason was given"
    text = f"{head}: {reason}"
    if detail:
        text += f" — {_clip(detail, 600).rstrip('. ')}"
    if decision.policy_decision_id:
        text += f" (decision {decision.policy_decision_id})"
    return text + ". The tool was not run."


def gateway_block_message(reason: str) -> str:
    """A block the gateway applied itself (no usable decision), as shown to the agent."""
    return f"Blocked by the ContextOS MCP gateway: {_clip(reason).rstrip('. ')}. The tool was not run."


def opaque_category(arguments: Mapping[str, Any]) -> str | None:
    """``"shell"`` when an argument holds a program, so path restrictions fail closed for this call."""
    return "shell" if any(str(name).lower() in OPAQUE_ARGUMENT_NAMES for name in arguments) else None


class Enforcer:
    """Asks ContextOS for a decision on one call and turns the answer into a :class:`Verdict`.

    The client is synchronous (httpx); every call to it runs in a worker thread so the MCP event
    loop keeps serving other requests. Approval polling is a cancellable async loop.
    """

    def __init__(
        self,
        client: ContextOSClient,
        *,
        fail_mode: str = "closed",
        approval_timeout_s: float = 300.0,
        poll_s: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        if fail_mode not in FAIL_MODES:
            raise ValueError(f"fail_mode must be one of {', '.join(FAIL_MODES)}")
        self.client = client
        self.fail_mode = fail_mode
        self.approval_timeout_s = max(0.0, approval_timeout_s)
        self.poll_s = max(0.05, poll_s)
        self._clock = clock
        self._sleep = sleep

    async def authorize(self, envelope: EventEnvelope, *, on_wait: WaitCallback | None = None) -> Verdict:
        arguments = dict(envelope.arguments or {})
        try:
            decision = await anyio.to_thread.run_sync(self.client.decide, envelope)
        except (Unreachable, ServerError) as exc:
            return await self._apply_fail_mode(exc, envelope)
        except AuthError as exc:
            return Verdict(False, gateway_block_message(f"ContextOS rejected the gateway's API key ({exc.message}); "
                                                        "failing closed"), arguments, outcome="auth_error")
        except APIError as exc:
            return Verdict(False, gateway_block_message(f"ContextOS could not evaluate this call ({exc.message}); "
                                                        "failing closed"), arguments, outcome="api_error")
        return await self.apply(decision, arguments, on_wait=on_wait)

    async def apply(self, decision: DecisionResponse, arguments: dict[str, Any], *,
                    on_wait: WaitCallback | None = None) -> Verdict:
        outcome = decision.decision.upper()
        if outcome in (Decision.ALLOW, Decision.AUDIT):
            return Verdict(True, f"Allowed by ContextOS ({outcome})", arguments, decision, outcome=outcome.lower())
        if outcome == Decision.DENY:
            return Verdict(False, policy_block_message(decision), arguments, decision, outcome="denied")
        if outcome == Decision.REQUIRE_APPROVAL:
            return await self._await_approval(decision, arguments, on_wait)
        if outcome == Decision.RESTRICT:
            return await anyio.to_thread.run_sync(self._restrict, decision, arguments)
        return Verdict(False, gateway_block_message(f"ContextOS returned an unrecognised decision "
                                                    f"'{decision.decision}'; failing closed"),
                       arguments, decision, outcome="unknown_decision")

    # -- fail modes -----------------------------------------------------------------------------

    async def _apply_fail_mode(self, exc: ContextOSError, envelope: EventEnvelope) -> Verdict:
        what = "unreachable" if isinstance(exc, Unreachable) else "failing"
        arguments = dict(envelope.arguments or {})
        tool = envelope.tool.name if envelope.tool else "tool"
        await anyio.to_thread.run_sync(self._spool_unguarded, envelope)
        if self.fail_mode == "open":
            log.warning("ContextOS is %s (%s); fail mode 'open' forwards tool '%s' WITHOUT a policy decision",
                        what, exc, tool)
            return Verdict(True, f"ContextOS is {what}; forwarded without a decision (fail mode 'open')",
                           arguments, outcome="fail_open", fail_open=True)
        log.warning("ContextOS is %s (%s); tool '%s' blocked (fail mode 'closed')", what, exc, tool)
        return Verdict(False, gateway_block_message(f"ContextOS is {what} ({exc}) and the gateway fails closed"),
                       arguments, outcome="fail_closed")

    def _spool_unguarded(self, envelope: EventEnvelope) -> None:
        """Store the attempt offline (same event id, so a later re-send is not a duplicate)."""
        metadata = {**envelope.metadata, "decision_unavailable": True, "fail_mode": self.fail_mode,
                    "local_outcome": "forwarded_without_decision" if self.fail_mode == "open" else "not_run"}
        try:
            self.client.spool_events([envelope.model_copy(update={"metadata": metadata})])
        except OSError as exc:
            log.warning("Could not spool the undecided tool attempt: %s", exc)

    # -- approvals ------------------------------------------------------------------------------

    async def _await_approval(self, decision: DecisionResponse, arguments: dict[str, Any],
                              on_wait: WaitCallback | None) -> Verdict:
        approval_id = decision.approval_id
        if (decision.approval_status or "").lower() == ApprovalStatus.APPROVED:
            return Verdict(True, f"Already approved in ContextOS (approval {approval_id})", arguments, decision,
                           outcome="approved")
        if not approval_id:
            return Verdict(False, policy_block_message(decision, "approval is required but ContextOS returned no "
                                                       "approval id"), arguments, decision, outcome="approval_missing")
        timeout = self.approval_timeout_s
        if timeout <= 0:
            status = await self._withdraw(approval_id, "The MCP gateway is configured not to wait for approvals.")
            if status != ApprovalStatus.APPROVED:
                return Verdict(False, policy_block_message(decision, f"approval {approval_id} "
                                                           f"{self._stale(status)}: this gateway is configured not "
                                                           "to wait for approvals"),
                               arguments, decision, outcome="approval_not_awaited")
            return Verdict(True, f"Approved in ContextOS (approval {approval_id})", arguments, decision,
                           outcome="approved")
        log.info("Tool call is waiting for approval %s (up to %.0fs)", approval_id, timeout)
        started = self._clock()
        deadline = started + timeout
        status, note = ApprovalStatus.PENDING.value, None
        try:
            while True:
                remaining = deadline - self._clock()
                if remaining <= 0:
                    status = await self._withdraw(approval_id, f"The MCP gateway stopped waiting after {timeout:.0f}s.")
                    if status in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED):
                        break  # a person decided just before the withdrawal
                    return Verdict(False, policy_block_message(
                        decision, f"approval {approval_id} was not decided within {timeout:.0f}s and "
                                  f"{self._stale(status)}; call the tool again to request a new approval"),
                        arguments, decision, outcome="approval_timeout")
                await self._report_wait(on_wait, self._clock() - started, timeout,
                                        f"Waiting for approval {approval_id} in ContextOS")
                await self._sleep(min(self.poll_s, remaining))
                try:
                    approval = await anyio.to_thread.run_sync(self.client.get_approval, approval_id)
                except Unreachable as exc:  # transient: keep waiting until the deadline
                    log.info("Approval poll failed (%s); retrying", exc)
                    continue
                except ContextOSError as exc:
                    return Verdict(False, policy_block_message(decision, f"could not check approval {approval_id} "
                                                               f"({exc})"),
                                   arguments, decision, outcome="approval_error")
                status = approval_status_of(approval) or ApprovalStatus.PENDING.value
                note = approval.get("decision_note") if isinstance(approval, dict) else None
                if status != ApprovalStatus.PENDING:
                    break
        except anyio.get_cancelled_exc_class():
            # The MCP host cancelled the request (or the gateway is shutting down): nothing waits any more.
            with anyio.CancelScope(shield=True), anyio.move_on_after(5):
                await self._withdraw(approval_id, "The MCP host cancelled the tool call while it waited for approval.")
            raise
        if status == ApprovalStatus.APPROVED:
            return Verdict(True, f"Approved in ContextOS (approval {approval_id})", arguments, decision,
                           outcome="approved")
        detail = f"approval {approval_id} was {status}" + (f": {_clip(str(note), 300)}" if note else "")
        return Verdict(False, policy_block_message(decision, detail), arguments, decision, outcome=f"approval_{status}")

    async def _withdraw(self, approval_id: str, reason: str) -> str | None:
        """Withdraw an approval nothing waits on any more; returns its status afterwards (or None)."""
        return await anyio.to_thread.run_sync(withdraw_approval, self.client, approval_id, reason)

    @staticmethod
    def _stale(status: str | None) -> str:
        if status == ApprovalStatus.CANCELLED:
            return "was withdrawn from ContextOS"
        return "is still pending in ContextOS (approving it now will not run this call)"

    @staticmethod
    async def _report_wait(on_wait: WaitCallback | None, elapsed: float, total: float, message: str) -> None:
        if on_wait is None:
            return
        try:
            await on_wait(elapsed, total, message)
        except Exception as exc:  # noqa: BLE001 - progress is a courtesy; it never changes the outcome
            log.debug("Could not report approval progress to the MCP host: %s", exc)

    # -- restrictions ---------------------------------------------------------------------------

    def _restrict(self, decision: DecisionResponse, arguments: dict[str, Any]) -> Verdict:
        def verify(masked: dict[str, Any]) -> bool | None:
            text = json.dumps(to_jsonable(masked), ensure_ascii=False, default=str)
            found = scan_reports_secrets(self.client.scan(text, source_type="other"))
            return None if found is None else not found

        result = apply_restrictions(
            decision.restrictions, arguments, category_hint=opaque_category(arguments), path_args=None,
            verify_redaction=verify, jsonable=to_jsonable,
        )
        if not result.allowed:
            return Verdict(False, policy_block_message(decision, result.reason), arguments, decision,
                           outcome="restriction_not_applied")
        return Verdict(True, "Forwarded with ContextOS restrictions applied", result.arguments, decision,
                       outcome="restricted", restrictions_applied=result.applied)


__all__ = [
    "FAIL_MODES",
    "OPAQUE_ARGUMENT_NAMES",
    "Enforcer",
    "Verdict",
    "deciding_policy",
    "gateway_block_message",
    "opaque_category",
    "policy_block_message",
]
