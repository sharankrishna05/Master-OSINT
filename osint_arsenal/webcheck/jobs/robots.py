from __future__ import annotations
from urllib.parse import urljoin
from .base import Job, registry


class RobotsJob(Job):
    name = "robots"
    label = "Robots.txt"
    group = "Crawling"

    async def run(self, ctx: dict):
        client = ctx["client"]
        target = urljoin(ctx["url"], "/robots.txt")
        try:
            r = await client.get(target)
            if r.status_code == 200:
                lines = [line.strip() for line in r.text.splitlines() if line.strip() and not line.strip().startswith("#")]
                return {"found": True, "url": target, "lines": lines[:50], "total_rules": len(lines)}
            return {"found": False, "status": r.status_code}
        except Exception as e:
            return {"found": False, "error": str(e)}


registry.register(RobotsJob())
