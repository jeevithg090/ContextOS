"""Building blocks shared by the command-hook integrations (Claude Code, OpenAI Codex).

Both hosts run one short-lived process per hook event, write the payload as JSON on stdin and
kill the process at a hard timeout. Everything here is host-neutral:

- :func:`run_with_budget` runs work in a daemon thread and gives up at the budget, so a hook
  always answers before the host kills it (a killed hook lets the tool run on both hosts).
- :func:`read_stdin` reads the payload with a size cap.
- :func:`configure_logging` keeps SDK logging off stderr unless ``CONTEXTOS_DEBUG=1`` (hosts show
  stray stderr as hook errors, and Codex uses stderr as the reason of a blocking answer).
- :func:`policies_text`, :func:`decision_ref`, :func:`clip` build the text of a blocking answer.
- :func:`await_approval` polls ``GET /decide/approvals/{id}`` for a ``REQUIRE_APPROVAL`` decision.
- :class:`Records` keeps tiny JSON records shared between hook processes of one host
  (ids, names and reasons only — never tool input, results or secrets).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from contextos.client import ContextOSClient, approval_status_of
from contextos.config import contextos_home
from contextos.errors import ApprovalTimeout, ContextOSError
from contextos.models import ApprovalStatus, DecisionResponse
from contextos.redact import mask_text

log = logging.getLogger("contextos.hookkit")

DECIDED = frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED,
                     ApprovalStatus.CANCELLED})
MAX_RECORD_AGE_S = 24 * 3600
_LOGGING_READY: set[str] = set()


def is_debug(env: Any) -> bool:
    return str(env.get("CONTEXTOS_DEBUG", "")).strip().lower() in ("1", "true", "yes")


def configure_logging(debug: bool, prefix: str) -> None:
    """Silence SDK logging unless debugging; then log to stderr with ``prefix`` (once per process)."""
    if "contextos" in _LOGGING_READY:
        return
    _LOGGING_READY.add("contextos")
    root = logging.getLogger("contextos")
    if debug:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(f"{prefix} %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
    else:
        root.addHandler(logging.NullHandler())
    root.propagate = False


def read_stdin(stream: IO[bytes], limit: int, error: type[Exception]) -> bytes:
    """Read at most ``limit`` bytes; a larger payload raises ``error`` (never echoing the content)."""
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise error(f"the hook input is larger than {limit:,} bytes")
    return data


def run_with_budget(fn: Callable[[], Any], budget_s: float, *, name: str = "contextos-hook") -> tuple[bool, Any]:
    """Run ``fn`` in a daemon thread; ``(finished, result)``. Exceptions propagate to the caller."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the calling thread
            box["error"] = exc

    worker = threading.Thread(target=target, name=name, daemon=True)
    worker.start()
    worker.join(max(0.1, budget_s))
    if worker.is_alive():
        return False, None
    if "error" in box:
        raise box["error"]
    return True, box.get("value")


def clip(text: str, limit: int) -> str:
    """Mask secrets (server text is already redacted; this is a second, local guard) and cut to ``limit``."""
    masked, _ = mask_text(text)
    return masked if len(masked) <= limit else masked[: limit - 1] + "…"


def policies_text(decision: DecisionResponse) -> str:
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


def decision_ref(decision: DecisionResponse) -> str:
    return f"ContextOS decision {decision.policy_decision_id}" if decision.policy_decision_id else "ContextOS"


# -- approvals -------------------------------------------------------------------------------------


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
    """Wait up to ``wait_s`` for a person to decide in the Approval Centre. Never raises."""
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


# -- records shared between hook processes ---------------------------------------------------------


class Records:
    """JSON records under ``$CONTEXTOS_HOME/<namespace>/<kind>/`` (directory 0700, files 0600).

    Records hold ids, names and reasons only and expire after a day. Failures are logged at debug
    level and never raised: a record that cannot be kept only loses attribution, never a decision.
    """

    def __init__(self, namespace: str) -> None:
        self.namespace = namespace

    def directory(self, kind: str) -> Path:
        return contextos_home() / self.namespace / kind

    def _path(self, kind: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:40]
        return self.directory(kind) / f"{digest}.json"

    def put(self, kind: str, key: str, record: dict[str, Any]) -> None:
        directory = self.directory(kind)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
            fd = os.open(self._path(kind, key), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({**{k: v for k, v in record.items() if v is not None}, "_at": time.time()}, handle)
            self._prune(directory)
        except OSError as exc:
            log.debug("Could not store %s record: %s", kind, exc.strerror or exc)

    def get(self, kind: str, key: str, *, remove: bool = False) -> dict[str, Any] | None:
        path = self._path(kind, key)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if remove:
            path.unlink(missing_ok=True)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict) or time.time() - float(data.get("_at") or 0) > MAX_RECORD_AGE_S:
            return None
        data.pop("_at", None)
        return data

    @staticmethod
    def _prune(directory: Path) -> None:
        cutoff = time.time() - MAX_RECORD_AGE_S
        for entry in directory.glob("*.json"):
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink(missing_ok=True)
            except OSError:
                continue


__all__ = [
    "DECIDED",
    "MAX_RECORD_AGE_S",
    "ApprovalOutcome",
    "Records",
    "await_approval",
    "clip",
    "configure_logging",
    "decision_ref",
    "is_debug",
    "policies_text",
    "read_stdin",
    "run_with_budget",
]
