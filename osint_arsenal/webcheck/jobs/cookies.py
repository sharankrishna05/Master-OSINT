from __future__ import annotations
from .base import Job, registry


class CookiesJob(Job):
    name = "cookies"
    label = "Cookies Audit"
    group = "Security"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.get(ctx["url"])
        results = []
        for c in r.cookies.jar:
            results.append({
                "name": c.name,
                "value": c.value[:20] + "..." if len(c.value) > 20 else c.value,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "http_only": c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"),
            })
        return {"cookies": results, "count": len(results)}


registry.register(CookiesJob())
