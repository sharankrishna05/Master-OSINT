from __future__ import annotations
import re
from urllib.parse import urljoin
from .base import Job, registry


class SitemapJob(Job):
    name = "sitemap"
    label = "Sitemap.xml"
    group = "Crawling"

    async def run(self, ctx: dict):
        client = ctx["client"]
        target = urljoin(ctx["url"], "/sitemap.xml")
        try:
            r = await client.get(target)
            if r.status_code == 200:
                locs = re.findall(r"<loc>(.*?)</loc>", r.text, re.IGNORECASE)
                return {"found": True, "url": target, "entries": locs[:30], "total_entries": len(locs)}
            return {"found": False, "status": r.status_code}
        except Exception as e:
            return {"found": False, "error": str(e)}


registry.register(SitemapJob())
