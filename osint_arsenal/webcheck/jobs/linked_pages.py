from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
from .base import Job, registry


class LinkedPagesJob(Job):
    name = "linked_pages"
    label = "Linked Pages & Anchors"
    group = "Crawling"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.get(ctx["url"])
        host = ctx["host"]
        internal = set()
        external = set()
        for href in re.findall(r'href=[\'"]([^\'"#\s]+)[\'"]', r.text, re.I):
            full = urljoin(ctx["url"], href)
            p = urlparse(full)
            if p.scheme in ("http", "https"):
                if p.netloc == host or p.netloc.endswith("." + host):
                    internal.add(full)
                else:
                    external.add(full)
        return {
            "internal_count": len(internal),
            "external_count": len(external),
            "internal_sample": list(internal)[:20],
            "external_sample": list(external)[:20],
        }


registry.register(LinkedPagesJob())
