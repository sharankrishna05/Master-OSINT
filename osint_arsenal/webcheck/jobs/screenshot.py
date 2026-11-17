from __future__ import annotations
from .base import Job, registry


class ScreenshotJob(Job):
    name = "screenshot"
    label = "Website Screenshot"
    group = "Media"

    async def run(self, ctx: dict):
        url = ctx["url"]
        # Public thumbnail preview endpoint
        thumbnail_url = f"https://image.thum.io/get/width/600/crop/800/{url}"
        return {
            "screenshot_available": True,
            "preview_url": thumbnail_url,
            "target": url,
        }


registry.register(ScreenshotJob())
