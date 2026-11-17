from __future__ import annotations
from .base import Job, registry


class CarbonJob(Job):
    name = "carbon"
    label = "Carbon Footprint"
    group = "Performance"

    async def run(self, ctx: dict):
        r = await ctx["client"].get(ctx["url"])
        size = len(r.content)
        grams = (size / 1_000_000) * 0.5
        return {
            "size_bytes": size,
            "size_kb": round(size / 1024, 2),
            "estimated_grams_co2_per_visit": round(grams, 4),
        }


registry.register(CarbonJob())
