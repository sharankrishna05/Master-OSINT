from __future__ import annotations
import asyncio
from .base import SiteModule, registry


class WhoisModule(SiteModule):
    name = "WHOIS"
    category = "major"
    supported = {"domain"}

    async def check(self, client, query: str) -> dict:
        try:
            import whois
            w = await asyncio.to_thread(whois.whois, query)
            return {
                "status": "found", "url": None, "http_status": None,
                "confidence": 1.0,
                "evidence": {
                    "registrar": str(w.registrar),
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": w.name_servers,
                    "emails": w.emails,
                },
            }
        except Exception as e:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": str(e)}}


class DNSRecordModule(SiteModule):
    name = "DNS"
    category = "major"
    supported = {"domain"}

    async def check(self, client, query: str) -> dict:
        try:
            import dns.resolver
        except ImportError:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": "dnspython missing"}}
        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, query, rtype)
                records[rtype] = [str(r).rstrip(".") for r in ans]
            except Exception:
                records[rtype] = []
        has_any = any(records.values())
        return {
            "status": "found" if has_any else "not_found",
            "url": None, "http_status": None,
            "confidence": 0.95 if has_any else 0.7,
            "evidence": {"records": records, "domain": query},
        }


def load_builtin():
    registry.register(WhoisModule())
    registry.register(DNSRecordModule())
