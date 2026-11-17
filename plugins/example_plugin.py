"""Example plugin.

Rename to `lookup_mysite.py` to add a lookup module, or
`webcheck_mycheck.py` to add a webcheck job.

This example adds a lookup module.
"""

from osint_arsenal.lookup.modules.base import SiteModule, registry  # noqa


class PyPIUserModule(SiteModule):
    name = "PyPIUser"
    category = "medium"
    supported = {"username"}

    async def check(self, client, query: str) -> dict:
        url = f"https://pypi.org/user/{query}/"
        try:
            r = await client.get(url)
        except Exception as e:
            return {"status": "error", "url": url, "confidence": 0.0,
                    "evidence": {"error": str(e)}}
        if r.status_code == 200:
            return {"status": "found", "url": url, "http_status": 200,
                    "confidence": 0.8, "evidence": {"site": "pypi"}}
        if r.status_code == 404:
            return {"status": "not_found", "url": url, "http_status": 404,
                    "confidence": 0.9, "evidence": {}}
        return {"status": "inconclusive", "url": url,
                "http_status": r.status_code, "confidence": 0.3, "evidence": {}}


MODULE = PyPIUserModule()
