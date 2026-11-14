"""Offline spool for non-blocking events.

When the server is unreachable, observability events (session, context, prompt, tool.completed,
...) are appended to ``~/.contextos/spool/<agent>.jsonl`` and re-sent after the next successful
send. Event ids are idempotency keys, so a re-send of an event the server already has is recorded
as ``duplicate``, never twice.

Guarantees and limits:
- Decisions (``POST /decide``) are NEVER spooled: a tool waiting for a decision fails per its fail mode.
- Secrets are masked (``contextos.redact``) before an event touches disk; the spool directory is
  0700 and files are 0600.
- The spool is size-capped (default 5 MiB per agent). When full, new events are dropped and a
  warning is logged; ``contextos doctor`` reports the spool size.
- Concurrent writers (e.g. one hook process per tool call) are serialised with an advisory file
  lock where the platform supports it (POSIX ``fcntl``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contextos.config import contextos_home
from contextos.errors import ContextOSError
from contextos.redact import mask_value

try:  # POSIX advisory locks; Windows falls back to best-effort (atomic renames still apply)
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows only
    fcntl = None  # type: ignore[assignment]

log = logging.getLogger("contextos.spool")

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
_STALE_CLAIM_S = 600
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.\-]+")


def spool_dir() -> Path:
    return contextos_home() / "spool"


def spool_path_for(agent_name: str) -> Path:
    safe = _SAFE_NAME_RE.sub("_", agent_name).strip("._") or "agent"
    return spool_dir() / f"{safe[:100]}.jsonl"


@dataclass(frozen=True)
class SpoolStats:
    path: Path
    events: int
    bytes: int


class Spool:
    """JSONL spool for one agent. Thread- and process-safe for append and flush."""

    def __init__(self, path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._warned_full = False

    @classmethod
    def for_agent(cls, agent_name: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Spool:
        return cls(spool_path_for(agent_name), max_bytes=max_bytes)

    # -- internals ------------------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError as exc:
            log.warning("Could not restrict spool directory permissions: %s", exc.strerror)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_dir()
        lock_path = self.path.with_suffix(".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _append_lines(self, lines: list[str]) -> int:
        """Append under the lock (caller holds it). Returns how many lines were written."""
        size = self.path.stat().st_size if self.path.exists() else 0
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        written = 0
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)  # existing files keep 0600 even if created by an older version
            for line in lines:
                data = (line + "\n").encode("utf-8")
                if size + len(data) > self.max_bytes:
                    break
                os.write(fd, data)
                size += len(data)
                written += 1
        finally:
            os.close(fd)
        dropped = len(lines) - written
        if dropped:
            if not self._warned_full:
                log.warning(
                    "ContextOS spool %s is full (%d bytes cap); %d event(s) dropped. "
                    "Reconnect to the server or raise spool_max_bytes.",
                    self.path,
                    self.max_bytes,
                    dropped,
                )
                self._warned_full = True
        return written

    # -- public API -----------------------------------------------------------------------------

    def append(self, events: list[dict[str, Any]]) -> int:
        """Mask secrets and append wire-format events. Returns the number stored (rest dropped: full)."""
        if not events:
            return 0
        lines = []
        for event in events:
            masked, kinds = mask_value(event)
            if kinds:
                masked.setdefault("metadata", {})["client_redacted_before_spool"] = sorted(set(kinds))
            lines.append(json.dumps(masked, separators=(",", ":"), ensure_ascii=False))
        with self._locked():
            return self._append_lines(lines)

    def stats(self) -> SpoolStats:
        files = [self.path, *self._claims()]
        count = 0
        total = 0
        for file in files:
            if not file.exists():
                continue
            total += file.stat().st_size
            with file.open("rb") as handle:
                count += sum(1 for line in handle if line.strip())
        return SpoolStats(self.path, count, total)

    def _claims(self) -> list[Path]:
        if not self.path.parent.exists():
            return []
        return sorted(self.path.parent.glob(self.path.name + ".*.flushing"))

    def flush(self, send: Callable[[list[dict[str, Any]]], list[str]], *, batch_size: int = 200) -> int:
        """Re-send spooled events with ``send``.

        ``send(events)`` must return the ids it delivered (accepted, duplicate, or rejected for
        good) and raise on transport failure. Undelivered events go back to the spool. Returns the
        number of delivered events.
        """
        claimed: list[Path] = []
        with self._locked():
            now = time.time()
            for stale in self._claims():  # left behind by a crashed flusher
                if now - stale.stat().st_mtime > _STALE_CLAIM_S:
                    claimed.append(stale)
            if self.path.exists() and self.path.stat().st_size > 0:
                claim = self.path.with_name(f"{self.path.name}.{uuid.uuid4().hex[:12]}.flushing")
                os.replace(self.path, claim)
                claimed.append(claim)
        delivered = 0
        for claim in claimed:
            delivered += self._flush_claim(claim, send, batch_size)
        return delivered

    def _flush_claim(
        self, claim: Path, send: Callable[[list[dict[str, Any]]], list[str]], batch_size: int
    ) -> int:
        events: list[dict[str, Any]] = []
        for raw in claim.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError:
                log.warning("Discarding a corrupt line in spool %s", claim.name)
        delivered = 0
        pending = events
        while pending:
            batch = pending[:batch_size]
            try:
                done = set(send(batch))
            except ContextOSError as exc:  # transport/server failure: keep everything not yet delivered
                log.info(
                    "Spool flush paused (%s); %d event(s) kept for later", type(exc).__name__, len(pending)
                )
                break
            delivered += sum(1 for e in batch if e.get("event_id") in done)
            leftover = [e for e in batch if e.get("event_id") not in done]
            pending = leftover + pending[len(batch) :]
            if leftover:
                break
        remaining = pending
        if remaining:
            with self._locked():
                self._append_lines(
                    [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in remaining]
                )
        claim.unlink(missing_ok=True)
        return delivered


__all__ = ["DEFAULT_MAX_BYTES", "Spool", "SpoolStats", "spool_dir", "spool_path_for"]
