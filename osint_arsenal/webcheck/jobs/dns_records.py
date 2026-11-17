from __future__ import annotations
import asyncio
from .base import Job, registry


class DNSRecordsJob(Job):
    name = "dns_records"
    label = "DNS Records"
    group = "Network"

    async def run(self, ctx: dict):
        try:
            import dns.resolver
        except ImportError:
            return {"error": "dnspython missing"}
        host = ctx["host"]
        out: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, host, rtype)
                out[rtype] = [str(r).rstrip(".") for r in ans]
            except Exception:
                out[rtype] = []
        return out


registry.register(DNSRecordsJob())
