from __future__ import annotations
import dns.resolver
from .base import Job, registry


class TxtRecordsJob(Job):
    name = "txt_records"
    label = "DNS TXT Records"
    group = "DNS"

    async def run(self, ctx: dict):
        host = ctx["host"]
        records = []
        try:
            ans = dns.resolver.resolve(host, "TXT")
            for r in ans:
                records.append(b"".join(r.strings).decode("utf-8", errors="ignore"))
        except Exception as e:
            return {"records": [], "error": str(e)}
        return {"records": records, "count": len(records)}


registry.register(TxtRecordsJob())
