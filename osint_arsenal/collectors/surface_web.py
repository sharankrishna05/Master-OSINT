import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class DuckDuckGoCollector(BaseCollector):
    name = "DuckDuckGo Public Search"
    category = "surface_web"
    legal_class = "public"
    rate_limit = 20

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        url = "https://html.duckduckgo.com/html/"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            try:
                resp = await client.post(url, data={"q": f'"{target}"'}, headers=headers)
                if resp.status_code == 200:
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload={"html_len": len(resp.text), "status": "indexed_results_observed"}
                    )
                    raw.compute_hash()
                    findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="general",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.75,
            threat_indicators=["PUBLICLY_INDEXED_SURFACE_SURFACE"],
            entities_discovered=[],
            attributes=raw.payload,
            evidence_hash=raw.evidence_sha256
        )

class WaybackCdxCollector(BaseCollector):
    name = "Wayback Machine CDX Index"
    category = "archives"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&limit=15"
        async with httpx.AsyncClient(timeout=12.0) as client:
            try:
                resp = await client.get(cdx_url)
                if resp.status_code == 200:
                    data = resp.json()
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload={"records": data[1:] if len(data) > 1 else []}
                    )
                    raw.compute_hash()
                    findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        records = raw.payload.get("records", [])
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="domain",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.95,
            threat_indicators=["HISTORICAL_ARCHIVE_EXPOSURE"] if records else [],
            entities_discovered=[],
            attributes={"snapshot_count": len(records)},
            evidence_hash=raw.evidence_sha256
        )
