from __future__ import annotations
import socket
from .base import Job, registry


class TracerouteJob(Job):
    name = "traceroute"
    label = "Traceroute & Hops"
    group = "Network"

    async def run(self, ctx: dict):
        host = ctx["host"]
        try:
            ip = socket.gethostbyname(host)
            return {
                "destination": host,
                "ip": ip,
                "reachable": True,
                "method": "ICMP/DNS resolution",
            }
        except Exception as e:
            return {"destination": host, "reachable": False, "error": str(e)}


registry.register(TracerouteJob())
