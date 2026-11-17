from __future__ import annotations
from .base import Job, registry


class ServerInfoJob(Job):
    name = "server_info"
    label = "Server Info"
    group = "HTTP"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.head(ctx["url"])
        headers = r.headers
        return {
            "server": headers.get("server", "Hidden/Unknown"),
            "powered_by": headers.get("x-powered-by", None),
            "aspnet_version": headers.get("x-aspnet-version", None),
            "via": headers.get("via", None),
        }


registry.register(ServerInfoJob())
