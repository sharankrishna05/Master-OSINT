from __future__ import annotations
from .base import Job, registry


class HSTSJob(Job):
    name = "hsts"
    label = "HSTS Audit"
    group = "Security"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.head(ctx["url"])
        hsts_header = r.headers.get("strict-transport-security", "")
        if not hsts_header:
            return {"enabled": False, "details": "Strict-Transport-Security header not present"}
        
        max_age = None
        for part in hsts_header.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=")[1])
                except ValueError:
                    pass
        return {
            "enabled": True,
            "header": hsts_header,
            "max_age": max_age,
            "include_subdomains": "includesubdomains" in hsts_header.lower(),
            "preload": "preload" in hsts_header.lower(),
        }


registry.register(HSTSJob())
