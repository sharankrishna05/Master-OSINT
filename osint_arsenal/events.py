from __future__ import annotations
import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    def __init__(self):
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)

    def subscribe(self, channel: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs[channel].append(q)
        return q

    def unsubscribe(self, channel: str, q: asyncio.Queue):
        if q in self._subs[channel]:
            self._subs[channel].remove(q)

    async def publish(self, channel: str, event: str, data: Any):
        for q in list(self._subs[channel]):
            await q.put({"event": event, "data": data})


bus = EventBus()
