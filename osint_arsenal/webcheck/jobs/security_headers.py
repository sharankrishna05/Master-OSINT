from __future__ import annotations
from .base import Job, registry


EXPECTED = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Content-Type-Options", "X-Frame-Options",
    "Referrer-Policy", "Permissions-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
]


class SecurityHeadersJob(Job):
    name = "security_headers"
    label = "Security Headers"
    group = "Security"

    async def run(self, ctx: dict):
        r = await ctx["client"].head(ctx["url"])
        present = {k: r.headers.get(k) for k in EXPECTED if k in r.headers}
        missing = [k for k in EXPECTED if k not in r.headers]
        return {
            "present": present, "missing": missing,
            "score": round(len(present) / len(EXPECTED), 2),
        }


registry.register(SecurityHeadersJob())
