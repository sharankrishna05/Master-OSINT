from __future__ import annotations
import asyncio
from .base import Job, registry


class WhoisJob(Job):
    name = "whois_lookup"
    label = "WHOIS"
    group = "Domain"

    async def run(self, ctx: dict):
        try:
            import whois
        except ImportError:
            return {"error": "python-whois missing"}
        try:
            w = await asyncio.to_thread(whois.whois, ctx["host"])
        except Exception as e:
            return {"error": str(e)}
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers or [],
            "emails": w.emails or [],
        }


registry.register(WhoisJob())
