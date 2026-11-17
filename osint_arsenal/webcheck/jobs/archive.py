from __future__ import annotations
from .base import Job, registry


class ArchiveJob(Job):
    name = "archive"
    label = "Wayback Machine Archive"
    group = "History"

    async def run(self, ctx: dict):
        client = ctx["client"]
        url = f"https://archive.org/wayback/available?url={ctx['url']}"
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                snapshots = data.get("archived_snapshots", {})
                closest = snapshots.get("closest", {})
                return {
                    "available": closest.get("available", False),
                    "url": closest.get("url"),
                    "timestamp": closest.get("timestamp"),
                }
        except Exception as e:
            return {"available": False, "error": str(e)}
        return {"available": False}


registry.register(ArchiveJob())
