"""In-process pub/sub for live updates (Server-Sent Events).

Deliberately simple: a single API process fans out notifications to connected browsers. Messages
are small notifications ({"type", "id", "org_id", ...}) — clients refetch details through the API,
so no sensitive payloads travel over the stream. Replace with Redis/NATS only when running several
API replicas (see docs/ARCHITECTURE_DECISIONS.md).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)


class EventBus:
    def __init__(self, max_queue: int = 500) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._max_queue = max_queue
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, org_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._max_queue)
        self._subscribers[org_id].add(queue)
        return queue

    def unsubscribe(self, org_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers[org_id].discard(queue)

    def publish(self, org_id: str, message: dict[str, Any]) -> None:
        """Thread-safe publish. Safe to call from sync request handlers (threadpool)."""
        message = {**message, "org_id": org_id}
        for queue in list(self._subscribers.get(org_id, ())):
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(self._offer, queue, message)
            else:
                self._offer(queue, message)

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
        if queue.full():
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()  # drop oldest; clients refetch on reconnect anyway
        queue.put_nowait(message)


bus = EventBus()
