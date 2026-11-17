from __future__ import annotations
import dns.resolver
from .base import Job, registry


class EmailConfigJob(Job):
    name = "email_config"
    label = "Email Security (SPF/DMARC/MX)"
    group = "DNS"

    async def run(self, ctx: dict):
        host = ctx["host"]
        res = {"mx": [], "spf": None, "dmarc": None}
        resolver = dns.resolver.Resolver()
        try:
            mx_ans = resolver.resolve(host, "MX")
            res["mx"] = [str(r.exchange).rstrip(".") for r in mx_ans]
        except Exception:
            pass
        try:
            txt_ans = resolver.resolve(host, "TXT")
            for r in txt_ans:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if txt.startswith("v=spf1"):
                    res["spf"] = txt
        except Exception:
            pass
        try:
            dmarc_ans = resolver.resolve(f"_dmarc.{host}", "TXT")
            for r in dmarc_ans:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=DMARC1" in txt:
                    res["dmarc"] = txt
        except Exception:
            pass
        return res


registry.register(EmailConfigJob())
