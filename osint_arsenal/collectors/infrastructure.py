import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class CrtShCertificateCollector(BaseCollector):
    name = "crt.sh Certificate Transparency"
    category = "infrastructure"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        if target_type not in ["domain", "url"]:
            return findings
            
        url = f"https://crt.sh/?q={target}&output=json"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    certs = resp.json()
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload={"certificates": certs[:25]}
                    )
                    raw.compute_hash()
                    findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        certs = raw.payload.get("certificates", [])
        subdomains = list(set([c.get("name_value", "") for c in certs if "name_value" in c]))
        entities = [{"type": "domain", "value": sub} for sub in subdomains[:10]]
        
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="domain",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.98,
            threat_indicators=["SUBDOMAIN_ENUMERATION_DISCOVERED"] if subdomains else [],
            entities_discovered=entities,
            attributes={"certificate_count": len(certs), "subdomains": subdomains[:10]},
            evidence_hash=raw.evidence_sha256
        )

class GreyNoiseCommunityCollector(BaseCollector):
    name = "GreyNoise Community"
    category = "infrastructure"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        if target_type != "ip":
            return findings
        url = f"https://api.greynoise.io/v3/community/{target}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload=resp.json()
                    )
                    raw.compute_hash()
                    findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        noise = raw.payload.get("noise", False)
        riot = raw.payload.get("riot", False)
        classification = raw.payload.get("classification", "unknown")
        
        indicators = []
        if classification == "malicious":
            indicators.append("INTERNET_MASS_SCANNER_MALICIOUS")
        elif noise:
            indicators.append("INTERNET_NOISE_SCANNER")
            
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="ip",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.90,
            threat_indicators=indicators,
            entities_discovered=[],
            attributes={"riot": riot, "noise": noise, "classification": classification},
            evidence_hash=raw.evidence_sha256
        )
