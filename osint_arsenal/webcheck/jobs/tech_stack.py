from __future__ import annotations
import json
from pathlib import Path
from .base import Job, registry


HERE = Path(__file__).parent.parent / "data"


class TechStackJob(Job):
    name = "tech_stack"
    label = "Tech Stack"
    group = "Content"

    def __init__(self):
        path = HERE / "tech_fingerprints.json"
        self.fingerprints = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []

    async def run(self, ctx: dict):
        r = await ctx["client"].get(ctx["url"])
        body = r.text.lower()
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        detected = []
        for fp in self.fingerprints:
            if "header" in fp:
                h, _, val = fp["header"].partition(":")
                if h.strip() in headers and val.strip() in headers[h.strip()]:
                    detected.append({"name": fp["name"], "via": "header"})
            if "html" in fp and fp["html"].lower() in body:
                detected.append({"name": fp["name"], "via": "html"})
            if "cookie" in fp and fp["cookie"].lower() in r.text.lower():
                detected.append({"name": fp["name"], "via": "cookie"})
        seen = set(); out = []
        for d in detected:
            k = (d["name"], d["via"])
            if k not in seen:
                seen.add(k); out.append(d)
        return out


registry.register(TechStackJob())
