import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class PublicPasteAndBucketCollector(BaseCollector):
    name = "Public Paste & Bucket Reconnaissance"
    category = "deep_web"
    legal_class = "public"
    rate_limit = 15

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        # Clearnet public paste index query via Google Dork simulation & public indexes
        url = f"https://psbdmp.ws/api/search/{target}"
        headers = {"User-Agent": "Nostromo-OSINT/2.0"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload={"pastes_found": data[:5], "count": len(data)}
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        count = raw.payload.get("count", 0)
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="paste_dump",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.88,
            threat_indicators=["PUBLIC_PASTEBIN_LEAK_OBSERVED"] if count > 0 else [],
            entities_discovered=[],
            mitre_attack_ids=["T1593.001"],
            attributes={"total_pastes": count},
            evidence_hash=raw.evidence_sha256
        )
