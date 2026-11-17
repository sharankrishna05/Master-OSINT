from __future__ import annotations
import time
from .base import Job, registry


class ServerStatusJob(Job):
    name = "server_status"
    label = "Server Status & Latency"
    group = "Network"

    async def run(self, ctx: dict):
        client = ctx["client"]
        t0 = time.time()
        r = await client.get(ctx["url"])
        latency_ms = round((time.time() - t0) * 1000, 2)
        return {
            "status_code": r.status_code,
            "latency_ms": latency_ms,
            "http_version": r.http_version,
            "is_up": r.status_code < 500,
        }


registry.register(ServerStatusJob())
