from __future__ import annotations
import httpx
from .base import Job, registry


class RedirectsJob(Job):
    name = "redirects"
    label = "Redirect Chain"
    group = "HTTP"

    async def run(self, ctx: dict):
        chain = []
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as unredirected_client:
            current_url = ctx["url"]
            for _ in range(10):
                try:
                    r = await unredirected_client.get(current_url)
                    chain.append({
                        "url": str(r.url),
                        "status": r.status_code,
                        "location": r.headers.get("location"),
                    })
                    if 300 <= r.status_code < 400 and "location" in r.headers:
                        current_url = str(r.headers["location"])
                        if not current_url.startswith("http"):
                            current_url = str(r.url.join(current_url))
                    else:
                        break
                except Exception as e:
                    chain.append({"url": current_url, "error": str(e)})
                    break
        return {"chain": chain, "total_hops": len(chain) - 1}


registry.register(RedirectsJob())
