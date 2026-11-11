"""PreToolUse enforcement: turn a ContextOS decision into a Claude Code hook answer.

The hook can only make Claude Code STRICTER, never more permissive. It never returns
``permissionDecision: "allow"`` because that skips Claude Code's own permission prompt. Every
allowed outcome is "no decision": the call continues through Claude Code's normal permission flow.

=====================  ============================================================================
ContextOS decision     Hook answer
=====================  ============================================================================
ALLOW, AUDIT           no decision (Claude Code's own permission rules still apply)
DENY                   ``deny`` + a reason citing the policy (Claude reads it as the tool error)
REQUIRE_APPROVAL       wait up to ``approval_wait_s`` for the Approval Centre: approved → no
                       decision; rejected / expired / cancelled → ``deny``; still pending →
                       ``ask`` (default) or ``deny`` (``on_approval_timeout``)
RESTRICT               restrictions that only check (paths, size) pass → no decision; secrets that
                       must be masked → ``ask`` with ``updatedInput`` (the masked input; the person
                       sees it); anything that cannot be applied → ``deny`` (fail closed)
anything else          ``deny`` (fail closed)
=====================  ============================================================================

When ContextOS cannot decide (unreachable, 5xx, an input too large to evaluate, the hook's own
time budget exhausted) the fail mode applies: ``closed`` → ``deny``, ``ask`` → ``ask``, ``open`` →
no decision plus a visible warning. A rejected or under-scoped API key always denies. In every
fail-mode case the attempt is spooled so ContextOS later records it (as observed, not enforced).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from contextos.client import ContextOSClient
from contextos.errors import (
    APIError,
    AuthError,
    ContextOSError,
    ServerError,
    Unreachable,
)
from contextos.models import ApprovalStatus, Decision, DecisionResponse, EventEnvelope
from contextos.redact import mask_text
from contextos.restrictions import apply_restrictions, scan_reports_secrets

from . import mapping
from .approval import await_approval, remember_host_prompt
from .hook_config import POLL_S, HookConfig
from .mapping import HookInput
from .observe import remember_delegation

log = logging.getLogger("contextos.claude_code")

MAX_DECIDE_BYTES = 500_000  # the server rejects events above 512 kB
MAX_REASON_CHARS = 1_800
# Tools whose file access is not fully described by a path argument (commands, patterns, subagents).
PATH_OPAQUE_TOOLS = frozenset({"Bash", "PowerShell", "BashOutput", "Glob", "Grep", "Agent", "Task"})
PATH_ARGS = {"Read": ["file_path"], "Write": ["file_path"], "Edit": ["file_path"], "MultiEdit": ["file_path"],
             "NotebookEdit": ["notebook_path"], "NotebookRead": ["notebook_path"], "LS": ["path"]}

Permission = Literal["deny", "ask"]


@dataclass
class Verdict:
    """The hook's answer. ``permission`` is ``None`` (no decision), ``"deny"`` or ``"ask"`` — never allow."""

    permission: Permission | None = None
    reason: str | None = None
    updated_input: dict[str, Any] | None = None
    system_message: str | None = None
    outcome: str = "no_decision"  # for diagnostics: allow, audit, deny, approved, rejected, fail_closed, ...
    decision: DecisionResponse | None = None
    notes: dict[str, Any] = field(default_factory=dict)

    def to_output(self) -> dict[str, Any] | None:
        """Hook stdout JSON, or ``None`` to print nothing (normal permission flow)."""
        out: dict[str, Any] = {}
        if self.permission is not None:
            if self.permission not in ("deny", "ask"):  # defensive: the hook must never weaken permissions
                raise ValueError(f"refusing to emit permissionDecision {self.permission!r}")
            specific: dict[str, Any] = {"hookEventName": "PreToolUse", "permissionDecision": self.permission,
                                        "permissionDecisionReason": _clip(self.reason or "Blocked by ContextOS")}
            if self.updated_input is not None:
                specific["updatedInput"] = self.updated_input
            out["hookSpecificOutput"] = specific
        if self.system_message:
            out["systemMessage"] = _clip(self.system_message, 600)
        return out or None


def _clip(text: str, limit: int = MAX_REASON_CHARS) -> str:
    masked, _ = mask_text(text)  # server text is already redacted; this is a second, local guard
    return masked if len(masked) <= limit else masked[: limit - 1] + "…"


def _policies(decision: DecisionResponse) -> str:
    """The enforce-mode policies that produced this decision (an AUDIT match did not block anything)."""
    enforced = [m for m in decision.matched_policies
                if isinstance(m, dict) and m.get("name") and m.get("mode", "enforce") == "enforce"]
    wanted = (decision.decision or "").upper()
    if any(m.get("outcome") for m in enforced):
        deciding = [m for m in enforced if str(m.get("outcome") or "").upper() == wanted]
    else:  # a server that does not report outcomes: cite every enforce-mode match
        deciding = enforced
    names = [f"“{m['name']}”" + (f", {m['severity']}" if m.get("severity") else "") for m in deciding]
    return "; ".join(dict.fromkeys(names)) or "organisation default decision"


def _ref(decision: DecisionResponse) -> str:
    return f"ContextOS decision {decision.policy_decision_id}" if decision.policy_decision_id else "ContextOS"


def fail_mode_verdict(cfg_fail_mode: str, tool: str, why: str) -> Verdict:
    """Answer when ContextOS could not decide (see module docstring)."""
    if cfg_fail_mode == "open":
        return Verdict(None, system_message=f"ContextOS could not check {tool} ({why}); fail mode 'open' let it "
                       "continue WITHOUT a policy decision.", outcome="fail_open", notes={"why": why})
    if cfg_fail_mode == "ask":
        return Verdict("ask", reason=f"ContextOS could not check this {tool} call ({why}). Approve it only if you "
                       "trust it; it has no ContextOS policy decision.", outcome="fail_ask", notes={"why": why})
    return Verdict("deny", reason=f"ContextOS could not check this {tool} call ({why}) and its fail mode is "
                   "'closed', so the call was blocked. Tell the user ContextOS is unavailable; do not try to "
                   "achieve the same result another way.",
                   system_message=f"ContextOS blocked {tool}: {why} (fail mode 'closed')", outcome="fail_closed",
                   notes={"why": why})


class PreToolUseEnforcer:
    """Requests a decision for one PreToolUse payload and maps it to a :class:`Verdict`."""

    def __init__(self, client: ContextOSClient, cfg: HookConfig, *, deadline: float,
                 clock: Callable[[], float] = time.monotonic, poll_s: float = POLL_S) -> None:
        self.client = client
        self.cfg = cfg
        self.deadline = deadline
        self.clock = clock
        self.poll_s = poll_s

    # -- entry point ------------------------------------------------------------------------------

    def run(self, h: HookInput) -> Verdict:
        tool = h.tool_name
        try:
            envelope = mapping.tool_request(h, self.client.agent)
        except ValueError as exc:
            return self._unavailable(h, None, f"the decision request could not be built: {type(exc).__name__}")
        size = len(json.dumps(envelope.to_wire(), ensure_ascii=False, default=str).encode("utf-8"))
        if size > MAX_DECIDE_BYTES:
            return self._unavailable(h, envelope, f"the tool input is {size:,} bytes, above the "
                                     f"{MAX_DECIDE_BYTES:,}-byte limit ContextOS can evaluate")
        try:
            decision = self.client.decide(envelope)
        except AuthError as exc:
            return Verdict("deny", reason=f"ContextOS rejected this hook's API key ({exc.message}), so the {tool} call "
                           "was blocked (fail closed). Ask the user to run `contextos doctor`.",
                           system_message=f"ContextOS blocked {tool}: API key rejected ({exc.message})",
                           outcome="auth_error")
        except (Unreachable, ServerError) as exc:
            what = "unreachable" if isinstance(exc, Unreachable) else f"failing (HTTP {exc.status_code})"
            return self._unavailable(h, envelope, f"ContextOS is {what}")
        except APIError as exc:
            return self._unavailable(h, None, f"ContextOS could not evaluate the call ({exc.message})")
        verdict = self._apply(h, decision)
        verdict.decision = decision
        if verdict.permission == "ask":
            remember_host_prompt(h.correlation_id, reason=verdict.outcome,
                                 approval_id=decision.approval_id, policy_decision_id=decision.policy_decision_id)
        if h.is_delegation and verdict.permission != "deny":
            self._report_delegation(h)
        return verdict

    # -- decision mapping -------------------------------------------------------------------------

    def _apply(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        outcome = (decision.decision or "").upper()
        tool = h.tool_name
        if outcome in (Decision.ALLOW, Decision.AUDIT):
            return Verdict(None, outcome=outcome.lower())
        if outcome == Decision.DENY:
            return Verdict("deny", reason=f"ContextOS policy blocked this {tool} call. Policy: {_policies(decision)}. "
                           f"{decision.reason} ({_ref(decision)}.) Do not try to achieve the same result another "
                           "way; tell the user what was blocked and why.",
                           system_message=f"ContextOS denied {tool} — {_policies(decision)}", outcome="deny")
        if outcome == Decision.REQUIRE_APPROVAL:
            return self._approval(h, decision)
        if outcome == Decision.RESTRICT:
            return self._restrict(h, decision)
        return Verdict("deny", reason=f"ContextOS returned an unrecognised decision '{decision.decision}' for this "
                       f"{tool} call, so it was blocked (fail closed). ({_ref(decision)}.)", outcome="unrecognised")

    def _approval(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        tool = h.tool_name
        if (decision.approval_status or "").lower() == ApprovalStatus.APPROVED:
            return Verdict(None, outcome="approved")
        if not decision.approval_id:
            return Verdict("deny", reason=f"ContextOS requires approval for this {tool} call but returned no approval "
                           f"id, so it was blocked (fail closed). ({_ref(decision)}.)", outcome="approval_missing")
        wait = max(0.0, min(self.cfg.effective_approval_wait_s, self.deadline - self.clock() - 1.0))
        result = await_approval(self.client, decision.approval_id, wait, self.poll_s)
        if result.approved:
            return Verdict(None, outcome="approved", notes={"approval_id": result.approval_id})
        if result.status in (ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED):
            note = f" Reviewer note: {result.note}" if result.note else ""
            return Verdict("deny", reason=f"ContextOS approval {result.approval_id} for this {tool} call was "
                           f"{result.status}.{note} Policy: {_policies(decision)}. Do not retry it another way.",
                           system_message=f"ContextOS approval {result.approval_id} {result.status}: {tool} blocked",
                           outcome=f"approval_{result.status}")
        if result.status == "error":
            return Verdict("deny", reason=f"ContextOS requires approval for this {tool} call, but approval "
                           f"{result.approval_id} could not be checked ({result.error}), so it was blocked (fail "
                           "closed).", outcome="approval_error")
        summary = f"{decision.reason} Policy: {_policies(decision)}."
        if self.cfg.on_approval_timeout == "deny":
            # Approvals belong to one call: approving this request later does not run anything, and a
            # retry is a new call with a new approval request. Say so, so nobody waits on a dead request.
            return Verdict("deny", reason=f"ContextOS approval {result.approval_id} for this {tool} call is still "
                           f"pending after {wait:.0f}s, so it was blocked. {summary} Approving that request now "
                           "will not run this call. If the user still wants it, they can ask you to retry and "
                           f"approve the new request in the ContextOS Approval Centre within {wait:.0f}s.",
                           system_message=f"ContextOS approval {result.approval_id} pending: {tool} blocked",
                           outcome="approval_timeout_deny")
        return Verdict("ask", reason=f"ContextOS approval {result.approval_id} pending — approve in the Approval Centre "
                       f"or here. {summary}", outcome="approval_pending",
                       notes={"approval_id": result.approval_id})

    def _restrict(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        tool = h.tool_name
        restrictions = decision.restrictions or {}
        has_paths = restrictions.get("allowed_path_globs") is not None or bool(restrictions.get("deny_path_globs"))
        if has_paths and (tool in PATH_OPAQUE_TOOLS or tool.startswith("mcp__")):
            problem = (f"path restrictions cannot be checked for {tool} (it can touch files that are not named in "
                       "its arguments)")
            return self._restrict_denied(tool, decision, problem)

        def verify(masked: dict[str, Any]) -> bool | None:
            text = json.dumps(masked, ensure_ascii=False, default=str)
            found = scan_reports_secrets(self.client.scan(text, source_type="other"))
            return None if found is None else not found

        _, _, server = mapping.split_tool_name(tool)
        outcome = apply_restrictions(restrictions, h.tool_input, category_hint=None,
                                     path_args=PATH_ARGS.get(tool) if server is None else None,
                                     verify_redaction=verify, cwd=h.cwd)
        if not outcome.allowed:
            return self._restrict_denied(tool, decision, outcome.reason or "a restriction could not be met")
        applied = "; ".join(outcome.applied) or "restrictions satisfied"
        if outcome.arguments == h.tool_input:
            return Verdict(None, outcome="restrict_satisfied", notes={"applied": outcome.applied})
        return Verdict("ask", updated_input=outcome.arguments,
                       reason=f"ContextOS restricted this {tool} call: {applied}. The input shown is the restricted "
                       f"version; approve it only if it still does what you intended. Policy: {_policies(decision)}. "
                       f"({_ref(decision)}.)", outcome="restricted",
                       notes={"applied": outcome.applied, "redacted_types": outcome.redacted_types})

    def _restrict_denied(self, tool: str, decision: DecisionResponse, problem: str) -> Verdict:
        return Verdict("deny", reason=f"ContextOS allows this {tool} call only with restrictions, and {problem}; the "
                       f"call was blocked (fail closed). Policy: {_policies(decision)}. ({_ref(decision)}.)",
                       system_message=f"ContextOS blocked {tool}: restriction not applicable", outcome="restrict_denied")

    # -- helpers ----------------------------------------------------------------------------------

    def _unavailable(self, h: HookInput, envelope: EventEnvelope | None, why: str) -> Verdict:
        verdict = fail_mode_verdict(self.cfg.fail_mode, h.tool_name, why)
        if envelope is not None:
            local = {"fail_closed": "not_run", "fail_ask": "asked_user", "fail_open": "ran_unguarded"}[verdict.outcome]
            metadata = {**envelope.metadata, "decision_unavailable": True, "fail_mode": self.cfg.fail_mode,
                        "local_outcome": local}
            try:
                self.client.spool_events([envelope.model_copy(update={"metadata": metadata})])
            except OSError as exc:
                log.debug("Could not spool the undecided tool request: %s", exc.strerror or exc)
        if verdict.permission == "ask":
            remember_host_prompt(h.correlation_id, reason=verdict.outcome)
        if h.is_delegation and verdict.permission != "deny":
            self._report_delegation(h, spool_only=True)
        return verdict

    def _report_delegation(self, h: HookInput, *, spool_only: bool = False) -> None:
        try:
            event = mapping.delegation(h, self.client.agent)
            if spool_only:
                self.client.spool_events([event])
            else:
                self.client.send_events([event])
            remember_delegation(h, self.client.agent)
        except (ContextOSError, OSError, ValueError) as exc:
            log.debug("Could not report the delegation: %s", exc)


__all__ = ["MAX_DECIDE_BYTES", "PATH_OPAQUE_TOOLS", "PreToolUseEnforcer", "Verdict", "fail_mode_verdict"]
