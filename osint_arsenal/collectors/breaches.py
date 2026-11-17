import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class PublicCisaKevCollector(BaseCollector):
    name = "CISA KEV Catalog"
    category = "threat_intel"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    kev_data = resp.json().get("vulnerabilities", [])
                    matched = [v for v in kev_data if target.lower() in str(v).lower()]
                    if matched:
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload={"matched_vulnerabilities": matched[:5]}
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        vulns = raw.payload.get("matched_vulnerabilities", [])
        cves = [v.get("cveID", "") for v in vulns]
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="software/vendor",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.99,
            threat_indicators=["KNOWN_EXPLOITED_VULNERABILITY_KEV"] if cves else [],
            entities_discovered=[],
            mitre_attack_ids=["T1190"],
            attributes={"cves": cves},
            evidence_hash=raw.evidence_sha256
        )
