from __future__ import annotations
import time
from typing import Any


class MemoryCache:
    def __init__(self, ttl: int = 600):
        self._store: dict[str, tuple[float, Any]] = {}
        self.ttl = ttl

    def get(self, key: str) -> Any | None:
        item = self._store.get(key)
        if not item:
            return None
        expires, value = item
        if time.time() > expires:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl: int | None = None):
        self._store[key] = (time.time() + (ttl or self.ttl), value)

    def clear(self):
        self._store.clear()


cache = MemoryCache()
