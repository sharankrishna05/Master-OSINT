from __future__ import annotations
from .base import Job, registry


class HeadersJob(Job):
    name = "headers"
    label = "HTTP Headers"
    group = "HTTP"

    async def run(self, ctx: dict):
        r = await ctx["client"].head(ctx["url"])
        return {k: v for k, v in r.headers.items()}


registry.register(HeadersJob())
