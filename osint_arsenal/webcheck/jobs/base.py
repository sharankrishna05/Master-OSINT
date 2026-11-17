from __future__ import annotations
from abc import ABC, abstractmethod


class Job(ABC):
    name: str = "base"
    label: str = "Base Job"
    group: str = "Misc"

    @abstractmethod
    async def run(self, ctx: dict):
        ...


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, Job] = {}

    def register(self, job: Job):
        self._jobs[job.name] = job

    def all(self) -> list[Job]:
        return list(self._jobs.values())

    def get(self, name: str) -> Job | None:
        return self._jobs.get(name)


registry = JobRegistry()
