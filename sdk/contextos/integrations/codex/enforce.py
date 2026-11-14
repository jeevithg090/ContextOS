"""PreToolUse enforcement: turn a ContextOS decision into a Codex hook answer.

What Codex does with a PreToolUse answer (``codex-rs/hooks/src/events/pre_tool_use.rs`` and
``engine/output_parser.rs`` at ``rust-v0.158.0-alpha.2.1``):

- exit 2 with a non-empty reason on stderr → the call is BLOCKED; the reason reaches the model;
- exit 0 with no output → the call continues through Codex's own approval policy and sandbox;
- exit 0 with ``permissionDecision: "allow"`` plus ``updatedInput`` → the call continues with the
  rewritten input (still through Codex's approval policy and sandbox: the outcome carries no
  approval, only the new input);
- everything else — ``ask``, ``allow`` without ``updatedInput``, unknown fields, other exit codes,
  a crash, a timeout — marks the hook as failed and the call RUNS.

So this hook blocks only through exit 2 (that channel also survives text a login shell prints on
stdout, which would corrupt a JSON answer), never answers ``ask``, and uses ``allow`` only to carry
a rewritten input. :class:`Verdict` refuses any other combination.

=====================  ============================================================================
ContextOS decision     Hook answer
=====================  ============================================================================
ALLOW, AUDIT           continue (Codex's own approval policy and sandbox still apply)
DENY                   block, with a reason citing the policy
REQUIRE_APPROVAL       wait up to ``approval_wait_s`` for the Approval Centre: approved → continue;
                       rejected / expired / cancelled → block; still pending → the request is
                       withdrawn from the Approval Centre and the call is blocked (Codex cannot ask)
RESTRICT               restrictions that only check (paths, size) pass → continue; secrets that must
                       be masked → continue with the masked input (``updatedInput``); anything that
                       cannot be applied or checked → block (fail closed)
anything else          block (fail closed)
=====================  ============================================================================

When ContextOS cannot decide (unreachable, 5xx, an input too large to evaluate, the hook's own time
budget exhausted): ``closed`` (default) and ``ask`` block, ``open`` continues with a visible warning.
A rejected or under-scoped API key always blocks. In every fail-mode case the attempt is spooled so
ContextOS later records it as observed, not enforced.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from contextos.client import ContextOSClient, withdraw_approval
from contextos.errors import (
    APIError,
    AuthError,
    ContextOSError,
    ServerError,
    Unreachable,
)
from contextos.integrations.hookkit import (
    ApprovalOutcome,
    Records,
    await_approval,
    clip,
    decision_ref,
    policies_text,
)
from contextos.models import ApprovalStatus, Decision, DecisionResponse, EventEnvelope
from contextos.restrictions import apply_restrictions, check_paths, scan_reports_secrets

from . import mapping
from .config import POLL_S, CodexHookConfig
from .mapping import HookInput

log = logging.getLogger("contextos.codex")

MAX_DECIDE_BYTES = 500_000  # the server rejects events above 512 kB
MAX_REASON_CHARS = 1_800
BLOCK_EXIT = 2  # Codex: exit 2 + reason on stderr blocks the tool call
# Tools whose file access is not fully described by their arguments (commands, sub-agents). Codex
# names namespaced tools "<namespace><name>" in hook payloads, e.g. "multi_agent_v1send_input".
_AGENT_TOOLS = ("spawn_agent", "send_input", "send_message", "followup_task", "resume_agent")
PATH_OPAQUE_TOOLS = frozenset({"Bash", *_AGENT_TOOLS, *(f"multi_agent_v1{name}" for name in _AGENT_TOOLS)})
PATH_ARGS = {"view_image": ["path"]}
_PATCH_HEADER = re.compile(
    r"^[ \t]*\*\*\*[ \t]*(Add File|Delete File|Update File|Move to):[ \t]*(.*?)[ \t]*$", re.MULTILINE
)
# Any other "*** ... File/Move ..." line (except the grammar's "*** End of File" marker).
_PATCH_LIKE_HEADER = re.compile(
    r"^[ \t]*\*\*\*(?![ \t]*End of File[ \t]*$).*(?:File|Move)", re.MULTILINE | re.IGNORECASE
)
RECORDS = Records("codex")
DELEGATIONS = "delegations"

Kind = Literal["continue", "block", "rewrite", "warn"]


@dataclass
class Verdict:
    """The hook's answer: ``continue`` (no output), ``block`` (exit 2), ``rewrite`` or ``warn`` (JSON)."""

    kind: Kind = "continue"
    reason: str | None = None
    updated_input: dict[str, Any] | None = None
    system_message: str | None = None
    outcome: str = "no_decision"  # diagnostics: allow, audit, deny, approved, fail_closed, restricted ...
    decision: DecisionResponse | None = None
    notes: dict[str, Any] = field(default_factory=dict)

    def answer(self) -> tuple[int, str | None, str | None]:
        """``(exit code, stdout, stderr)`` for Codex. Never ``ask``; ``allow`` only with ``updatedInput``."""
        if self.kind == "block":
            # Codex shows "<hook> blocked ...: {reason}. Command: {command}", so no trailing full stop here.
            reason = (
                clip(self.reason or "Blocked by ContextOS", MAX_REASON_CHARS).rstrip().rstrip(".")
                or "Blocked"
            )
            return BLOCK_EXIT, None, reason + "\n"
        if self.kind == "continue":
            return 0, None, None
        out: dict[str, Any] = {}
        if self.kind == "rewrite":
            if not isinstance(self.updated_input, dict):  # defensive: "allow" alone would be a failed hook
                raise ValueError("refusing to emit permissionDecision 'allow' without updatedInput")
            out["hookSpecificOutput"] = {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": self.updated_input,
            }
        elif self.kind != "warn":
            raise ValueError(f"unknown verdict kind {self.kind!r}")
        if self.system_message:
            out["systemMessage"] = clip(self.system_message, 600)
        if not out:
            return 0, None, None
        return 0, json.dumps(out, ensure_ascii=False) + "\n", None


def fail_mode_verdict(cfg_fail_mode: str, tool: str, why: str) -> Verdict:
    """Answer when ContextOS could not decide (see module docstring)."""
    if cfg_fail_mode == "open":
        return Verdict(
            "warn",
            system_message=f"ContextOS could not check {tool} ({why}); fail mode 'open' let it "
            "continue WITHOUT a policy decision.",
            outcome="fail_open",
            notes={"why": why},
        )
    mode = (
        "'closed'" if cfg_fail_mode == "closed" else "'ask' (Codex hooks cannot ask, so it acts as 'closed')"
    )
    return Verdict(
        "block",
        reason=f"ContextOS could not check this {tool} call ({why}) and its fail mode is "
        f"{mode}, so the call was blocked. Tell the user ContextOS is unavailable; do not try to "
        "achieve the same result another way.",
        outcome="fail_closed",
        notes={"why": why},
    )


def patch_paths(patch: str) -> list[str] | None:
    """File paths an ``apply_patch`` input touches, or ``None`` when they cannot be read reliably."""
    if "*** Begin Patch" not in patch:
        return None
    found = [m.group(2) for m in _PATCH_HEADER.finditer(patch)]
    if not found or any(not p for p in found):
        return None
    if len(_PATCH_LIKE_HEADER.findall(patch)) != len(found):
        return None  # a header-like line this parser does not understand: do not guess
    return found


class PreToolUseEnforcer:
    """Requests a decision for one PreToolUse payload and maps it to a :class:`Verdict`."""

    def __init__(
        self,
        client: ContextOSClient,
        cfg: CodexHookConfig,
        *,
        deadline: float,
        clock: Callable[[], float] = time.monotonic,
        poll_s: float = POLL_S,
    ) -> None:
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
            return self._unavailable(
                h, None, f"the decision request could not be built: {type(exc).__name__}"
            )
        size = len(json.dumps(envelope.to_wire(), ensure_ascii=False, default=str).encode("utf-8"))
        if size > MAX_DECIDE_BYTES:
            return self._unavailable(
                h,
                envelope,
                f"the tool input is {size:,} bytes, above the "
                f"{MAX_DECIDE_BYTES:,}-byte limit ContextOS can evaluate",
            )
        try:
            decision = self.client.decide(envelope)
        except AuthError as exc:
            return Verdict(
                "block",
                reason=f"ContextOS rejected this hook's API key ({exc.message}), so the {tool} "
                "call was blocked (fail closed). Ask the user to run `contextos doctor`.",
                outcome="auth_error",
            )
        except (Unreachable, ServerError) as exc:
            what = "unreachable" if isinstance(exc, Unreachable) else f"failing (HTTP {exc.status_code})"
            return self._unavailable(h, envelope, f"ContextOS is {what}")
        except APIError as exc:
            return self._unavailable(h, None, f"ContextOS could not evaluate the call ({exc.message})")
        verdict = self._apply(h, decision)
        verdict.decision = decision
        if h.is_delegation and verdict.kind != "block":
            self._report_delegation(h)
        return verdict

    # -- decision mapping -------------------------------------------------------------------------

    def _apply(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        outcome = (decision.decision or "").upper()
        tool = h.tool_name
        if outcome in (Decision.ALLOW, Decision.AUDIT):
            return Verdict("continue", outcome=outcome.lower())
        if outcome == Decision.DENY:
            return Verdict(
                "block",
                reason=f"ContextOS policy blocked this {tool} call. Policy: "
                f"{policies_text(decision)}. {decision.reason} ({decision_ref(decision)}.) Do not try to "
                "achieve the same result another way; tell the user what was blocked and why.",
                outcome="deny",
            )
        if outcome == Decision.REQUIRE_APPROVAL:
            return self._approval(h, decision)
        if outcome == Decision.RESTRICT:
            return self._restrict(h, decision)
        return Verdict(
            "block",
            reason=f"ContextOS returned an unrecognised decision '{decision.decision}' for this "
            f"{tool} call, so it was blocked (fail closed). ({decision_ref(decision)}.)",
            outcome="unrecognised",
        )

    def _approval(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        tool = h.tool_name
        if (decision.approval_status or "").lower() == ApprovalStatus.APPROVED:
            return Verdict("continue", outcome="approved")
        if not decision.approval_id:
            return Verdict(
                "block",
                reason=f"ContextOS requires approval for this {tool} call but returned no "
                f"approval id, so it was blocked (fail closed). ({decision_ref(decision)}.)",
                outcome="approval_missing",
            )
        wait = max(0.0, min(self.cfg.effective_approval_wait_s, self.deadline - self.clock() - 1.0))
        result = await_approval(self.client, decision.approval_id, wait, self.poll_s)
        withdrawn = False
        if result.status == ApprovalStatus.PENDING:
            # The hook blocks the call now, so approving this request later would run nothing:
            # withdraw it. A person may have decided it a moment ago (409 carries that status).
            after = withdraw_approval(
                self.client,
                result.approval_id,
                f"The Codex hook stopped waiting after {wait:.0f}s and blocked the call.",
            )
            if after in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED):
                result = ApprovalOutcome(result.approval_id, after)
            withdrawn = after == ApprovalStatus.CANCELLED
        if result.approved:
            return Verdict("continue", outcome="approved", notes={"approval_id": result.approval_id})
        if result.status in (ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED):
            note = f" Reviewer note: {result.note}" if result.note else ""
            return Verdict(
                "block",
                reason=f"ContextOS approval {result.approval_id} for this {tool} call was "
                f"{result.status}.{note} Policy: {policies_text(decision)}. Do not retry it another way.",
                outcome=f"approval_{result.status}",
            )
        if result.status == "error":
            return Verdict(
                "block",
                reason=f"ContextOS requires approval for this {tool} call, but approval "
                f"{result.approval_id} could not be checked ({result.error}), so it was blocked (fail "
                "closed).",
                outcome="approval_error",
            )
        stale = (
            "The request was withdrawn from the Approval Centre, so it can no longer be approved."
            if withdrawn
            else "Approving that request now will not run this call."
        )
        return Verdict(
            "block",
            reason=f"ContextOS approval {result.approval_id} for this {tool} call was still "
            f"pending after {wait:.0f}s, so it was blocked. {decision.reason} Policy: "
            f"{policies_text(decision)}. {stale} If the user still wants it, they can ask you to retry and "
            f"approve the new request in the ContextOS Approval Centre within {wait:.0f}s.",
            outcome="approval_timeout",
            notes={"approval_withdrawn": withdrawn},
        )

    def _restrict(self, h: HookInput, decision: DecisionResponse) -> Verdict:
        tool = h.tool_name
        restrictions = dict(decision.restrictions or {})
        has_paths = restrictions.get("allowed_path_globs") is not None or bool(
            restrictions.get("deny_path_globs")
        )
        if has_paths:
            if tool in PATH_OPAQUE_TOOLS or tool.startswith("mcp__"):
                return self._restrict_denied(
                    tool,
                    decision,
                    f"path restrictions cannot be checked for {tool} (it can "
                    "touch files that are not named in its arguments)",
                )
            if tool == "apply_patch":
                problem = self._patch_path_problem(h, restrictions)
                if problem:
                    return self._restrict_denied(tool, decision, problem)
                # Checked here: the generic check below would refuse the patch's "command" argument.
                restrictions.pop("allowed_path_globs", None)
                restrictions.pop("deny_path_globs", None)
                if not restrictions:
                    return Verdict(
                        "continue",
                        outcome="restrict_satisfied",
                        notes={"applied": ["all patched file paths are within the permitted patterns"]},
                    )

        def verify(masked: dict[str, Any]) -> bool | None:
            text = json.dumps(masked, ensure_ascii=False, default=str)
            found = scan_reports_secrets(self.client.scan(text, source_type="other"))
            return None if found is None else not found

        outcome = apply_restrictions(
            restrictions,
            h.tool_input,
            category_hint=None,
            path_args=PATH_ARGS.get(tool),
            verify_redaction=verify,
            cwd=h.cwd,
        )
        if not outcome.allowed:
            return self._restrict_denied(tool, decision, outcome.reason or "a restriction could not be met")
        applied = "; ".join(outcome.applied) or "restrictions satisfied"
        if outcome.arguments == h.tool_input:
            return Verdict("continue", outcome="restrict_satisfied", notes={"applied": outcome.applied})
        if not isinstance(h.data.get("tool_input"), dict) or not self._rewritable(tool, outcome.arguments):
            return self._restrict_denied(
                tool,
                decision,
                "the restricted input cannot be handed back to Codex in the shape this tool expects",
            )
        return Verdict(
            "rewrite",
            updated_input=outcome.arguments,
            system_message=f"ContextOS restricted {tool}: {applied}. The call runs with the restricted "
            f"input ({decision_ref(decision)}).",
            outcome="restricted",
            notes={"applied": outcome.applied, "redacted_types": outcome.redacted_types},
        )

    @staticmethod
    def _rewritable(tool: str, arguments: dict[str, Any]) -> bool:
        # Codex rebuilds Bash and apply_patch calls from a string ``command`` (handlers/mod.rs).
        if tool in ("Bash", "apply_patch"):
            return set(arguments) == {"command"} and isinstance(arguments.get("command"), str)
        return True

    @staticmethod
    def _patch_path_problem(h: HookInput, restrictions: dict[str, Any]) -> str | None:
        patch = h.tool_input.get("command")
        paths = patch_paths(patch) if isinstance(patch, str) else None
        if paths is None:
            return "the files this patch touches could not be read from it, so path restrictions cannot be checked"
        allowed, denied = restrictions.get("allowed_path_globs"), restrictions.get("deny_path_globs")
        if (allowed is not None and not isinstance(allowed, list)) or (
            denied is not None and not isinstance(denied, list)
        ):
            return "path restrictions are malformed"
        return check_paths(paths, allowed, denied, h.cwd)

    def _restrict_denied(self, tool: str, decision: DecisionResponse, problem: str) -> Verdict:
        return Verdict(
            "block",
            reason=f"ContextOS allows this {tool} call only with restrictions, and {problem}; "
            f"the call was blocked (fail closed). Policy: {policies_text(decision)}. "
            f"({decision_ref(decision)}.)",
            outcome="restrict_denied",
        )

    # -- helpers ----------------------------------------------------------------------------------

    def _unavailable(self, h: HookInput, envelope: EventEnvelope | None, why: str) -> Verdict:
        verdict = fail_mode_verdict(self.cfg.fail_mode, h.tool_name, why)
        if envelope is not None:
            local = "ran_unguarded" if verdict.kind != "block" else "not_run"
            metadata = {
                **envelope.metadata,
                "decision_unavailable": True,
                "fail_mode": self.cfg.fail_mode,
                "local_outcome": local,
            }
            try:
                self.client.spool_events([envelope.model_copy(update={"metadata": metadata})])
            except OSError as exc:
                log.debug("Could not spool the undecided tool request: %s", exc.strerror or exc)
        if h.is_delegation and verdict.kind != "block":
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


def remember_delegation(h: HookInput, agent: Any) -> None:
    """Keep ``{child_agent, child_session_id}`` for a ``spawn_agent`` call, keyed by its tool_use_id."""
    RECORDS.put(
        DELEGATIONS,
        f"tool:{h.session_id}:{h.correlation_id}",
        {"child_agent": mapping.child_agent(agent, h).name, "child_session_id": mapping.child_session_id(h)},
    )


__all__ = [
    "BLOCK_EXIT",
    "DELEGATIONS",
    "MAX_DECIDE_BYTES",
    "PATH_OPAQUE_TOOLS",
    "RECORDS",
    "PreToolUseEnforcer",
    "Verdict",
    "fail_mode_verdict",
    "patch_paths",
    "remember_delegation",
]
