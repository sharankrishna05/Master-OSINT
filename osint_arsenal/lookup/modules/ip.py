from __future__ import annotations
import asyncio
from .base import SiteModule, registry


class IPInfoModule(SiteModule):
    name = "IPInfo"
    category = "major"
    supported = {"ip"}

    async def check(self, client, query: str) -> dict:
        try:
            import ipaddress
            ipaddress.ip_address(query)
        except Exception as e:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": f"not an IP: {e}"}}
        try:
            r = await client.get(f"https://ipapi.co/{query}/json/")
            if r.status_code == 200:
                return {"status": "found",
                        "url": f"https://ipapi.co/{query}/json/",
                        "http_status": 200, "confidence": 0.9,
                        "evidence": r.json()}
            return {"status": "inconclusive", "url": None,
                    "http_status": r.status_code, "confidence": 0.3, "evidence": {}}
        except Exception as e:
            return {"status": "error", "url": None, "confidence": 0.0,
                    "evidence": {"error": str(e)}}


class ReverseDNSModule(SiteModule):
    name = "ReverseDNS"
    category = "medium"
    supported = {"ip"}

    async def check(self, client, query: str) -> dict:
        try:
            import socket
            host, aliases, _ = await asyncio.to_thread(socket.gethostbyaddr, query)
            return {"status": "found", "url": None, "http_status": None,
                    "confidence": 0.9,
                    "evidence": {"ptr": host, "aliases": aliases}}
        except Exception as e:
            return {"status": "not_found", "url": None, "confidence": 0.7,
                    "evidence": {"error": str(e)}}


def load_builtin():
    registry.register(IPInfoModule())
    registry.register(ReverseDNSModule())
