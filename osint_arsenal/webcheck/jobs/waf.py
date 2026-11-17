from __future__ import annotations
from .base import Job, registry


class WAFJob(Job):
    name = "waf"
    label = "WAF Detection"
    group = "Security"

    async def run(self, ctx: dict):
        client = ctx["client"]
        r = await client.get(ctx["url"])
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        server = headers.get("server", "")
        
        detected = []
        if "cf-ray" in headers or "cloudflare" in server:
            detected.append("Cloudflare")
        if "x-amz-cf-id" in headers or "awselb" in headers.get("set-cookie", ""):
            detected.append("AWS CloudFront / WAF")
        if "akamai" in server or "x-akamai-transformed" in headers:
            detected.append("Akamai")
        if "x-sucuri-id" in headers or "sucuri" in server:
            detected.append("Sucuri CloudProxy")
        if "imperva" in server or "incap_ses" in headers.get("set-cookie", ""):
            detected.append("Imperva Incapsula")
        if "fastly" in headers.get("x-served-by", ""):
            detected.append("Fastly")

        return {
            "has_waf": len(detected) > 0,
            "detected": detected,
            "server": server or "unknown",
        }


registry.register(WAFJob())
