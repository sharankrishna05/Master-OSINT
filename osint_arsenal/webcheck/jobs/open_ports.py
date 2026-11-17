from __future__ import annotations
import asyncio
from .base import Job, registry


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993,
                995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                8443, 9200, 11211, 27017]


class OpenPortsJob(Job):
    name = "open_ports"
    label = "Open Ports"
    group = "Network"

    async def run(self, ctx: dict):
        host = ctx["host"]
        sem = asyncio.Semaphore(30)
        tasks = [self._check(host, p, sem) for p in COMMON_PORTS]
        results = await asyncio.gather(*tasks)
        return {"open": [p for p in results if p], "checked": len(COMMON_PORTS)}

    async def _check(self, host: str, port: int, sem: asyncio.Semaphore):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=2)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None


registry.register(OpenPortsJob())
