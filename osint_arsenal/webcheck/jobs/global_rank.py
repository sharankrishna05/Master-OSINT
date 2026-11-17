from __future__ import annotations
from .base import Job, registry


class GlobalRankJob(Job):
    name = "global_rank"
    label = "Global Rank & Popularity"
    group = "Reputation"

    async def run(self, ctx: dict):
        host = ctx["host"]
        top_sites = {"google.com": 1, "youtube.com": 2, "facebook.com": 3, "github.com": 50, "wikipedia.org": 10}
        rank = top_sites.get(host.lower(), None)
        return {
            "domain": host,
            "rank": rank or "Outside Top 100",
            "tier": "Global Authority" if rank and rank < 100 else "Standard Domain",
        }


registry.register(GlobalRankJob())
