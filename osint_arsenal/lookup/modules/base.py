from __future__ import annotations
from abc import ABC, abstractmethod


class SiteModule(ABC):
    name: str = "base"
    category: str = "uncategorized"
    supported: set[str] = set()

    @abstractmethod
    async def check(self, client, query: str) -> dict:
        ...


class ModuleRegistry:
    def __init__(self):
        self._mods: dict[str, SiteModule] = {}

    def register(self, m: SiteModule):
        self._mods[m.name] = m

    def all(self) -> list[SiteModule]:
        return list(self._mods.values())

    def for_kind(self, kind: str) -> list[SiteModule]:
        return [m for m in self._mods.values() if kind in m.supported]

    def get(self, name: str) -> SiteModule | None:
        return self._mods.get(name)


registry = ModuleRegistry()
