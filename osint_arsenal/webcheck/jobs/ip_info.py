from __future__ import annotations
import asyncio
import socket
from .base import Job, registry


class IPInfoJob(Job):
    name = "ip_info"
    label = "IP Information"
    group = "Network"

    async def run(self, ctx: dict):
        host = ctx["host"]
        try:
            info = await asyncio.to_thread(socket.getaddrinfo, host, None)
            ips = sorted({i[4][0] for i in info})
        except Exception as e:
            return {"error": str(e)}
        if not ips:
            return {"error": "no IPs"}
        r = await ctx["client"].get(f"https://ipapi.co/{ips[0]}/json/")
        geo = r.json() if r.status_code == 200 else {}
        return {"ip": ips[0], "all_ips": ips, "geo": geo}


registry.register(IPInfoJob())
