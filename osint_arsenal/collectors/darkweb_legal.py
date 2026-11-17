import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class AhmiaClearnetIndexCollector(BaseCollector):
    name = "Ahmia Clearnet Index"
    category = "darkweb_legal"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        url = f"https://ahmia.fi/search/?q={target}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200 and "No results" not in resp.text:
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload={"clearnet_index_matches": True, "evidence": "Reference found in public search index"}
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
            target_type="indicator",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.70,
            threat_indicators=["PUBLIC_DARKWEB_INDEX_REFERENCE"],
            entities_discovered=[],
            mitre_attack_ids=["T1596"],
            attributes=raw.payload,
            evidence_hash=raw.evidence_sha256
        )
