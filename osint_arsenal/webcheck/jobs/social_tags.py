from __future__ import annotations
import re
from .base import Job, registry


class SocialTagsJob(Job):
    name = "social_tags"
    label = "Social & OpenGraph Tags"
    group = "Meta"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.get(ctx["url"])
        html = r.text
        og = {}
        for m in re.finditer(r'<meta[^>]+property=[\'"](og:[^\'"]+)[\'"][^>]+content=[\'"]([^\'"]*)[\'"]', html, re.I):
            og[m.group(1)] = m.group(2)
        twitter = {}
        for m in re.finditer(r'<meta[^>]+name=[\'"](twitter:[^\'"]+)[\'"][^>]+content=[\'"]([^\'"]*)[\'"]', html, re.I):
            twitter[m.group(1)] = m.group(2)
        return {"og": og, "twitter": twitter}


registry.register(SocialTagsJob())
