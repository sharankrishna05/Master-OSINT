from __future__ import annotations
import hashlib
from .base import SiteModule, registry


class GravatarModule(SiteModule):
    name = "Gravatar"
    category = "major"
    supported = {"email"}

    async def check(self, client, query: str) -> dict:
        h = hashlib.md5(query.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        try:
            r = await client.get(url)
        except Exception as e:
            return {"status": "error", "url": url, "confidence": 0.0,
                    "evidence": {"error": str(e)}}
        if r.status_code == 200:
            return {"status": "found", "url": f"https://gravatar.com/{h}",
                    "http_status": 200, "confidence": 0.95,
                    "evidence": {"avatar_hash": h}}
        return {"status": "not_found", "url": url,
                "http_status": r.status_code, "confidence": 0.9, "evidence": {}}


class EmailMXModule(SiteModule):
    name = "EmailMX"
    category = "medium"
    supported = {"email"}

    async def check(self, client, query: str) -> dict:
        domain = query.split("@")[-1]
        try:
            import dns.resolver
            ans = dns.resolver.resolve(domain, "MX")
            mx = [str(r.exchange).rstrip(".") for r in ans]
            return {"status": "found", "url": None, "http_status": None,
                    "confidence": 1.0, "evidence": {"mx": mx, "domain": domain}}
        except Exception as e:
            return {"status": "inconclusive", "url": None, "http_status": None,
                    "confidence": 0.3,
                    "evidence": {"error": str(e), "domain": domain}}


class DisposableModule(SiteModule):
    name = "DisposableCheck"
    category = "major"
    supported = {"email"}

    async def check(self, client, query: str) -> dict:
        from ...config import settings
        domain = query.split("@")[-1].lower()
        path = settings.data_dir.parent / "lookup" / "data" / "disposable_domains.txt"
        if not path.exists():
            return {"status": "inconclusive", "url": None,
                    "confidence": 0.3, "evidence": {}}
        names = {l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()}
        return {"status": "found", "url": None, "confidence": 1.0,
                "evidence": {"disposable": domain in names, "domain": domain}}


def load_builtin():
    registry.register(GravatarModule())
    registry.register(EmailMXModule())
    registry.register(DisposableModule())
