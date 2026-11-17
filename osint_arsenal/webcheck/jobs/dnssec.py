from __future__ import annotations
import dns.resolver
from .base import Job, registry


class DNSSECJob(Job):
    name = "dnssec"
    label = "DNSSEC Validation"
    group = "DNS"

    async def run(self, ctx: dict):
        host = ctx["host"]
        try:
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            ans = resolver.resolve(host, "A")
            has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in ans.response.answer)
            return {"dnssec_enabled": has_rrsig, "domain": host}
        except Exception as e:
            return {"dnssec_enabled": False, "error": str(e)}


registry.register(DNSSECJob())
