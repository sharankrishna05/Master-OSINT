import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class GeoSpatialCollector(BaseCollector):
    name = "IP Geolocation & OpenStreetMap BGP"
    category = "geospatial"
    legal_class = "public"
    rate_limit = 30

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        if target_type != "ip":
            return findings

        # Public ip-api clearnet lookup
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload=data
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        payload = raw.payload
        country = payload.get("country", "Unknown")
        city = payload.get("city", "Unknown")
        lat = payload.get("lat", 0.0)
        lon = payload.get("lon", 0.0)
        asn = payload.get("as", "")
        org = payload.get("org", "")

        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="ip",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.98,
            threat_indicators=["PHYSICAL_GEOLOCATION_ESTABLISHED"],
            entities_discovered=[
                {"type": "asn", "value": asn},
                {"type": "organization", "value": org},
                {"type": "country", "value": country}
            ],
            mitre_attack_ids=["T1590.005"],
            attributes={
                "country": country,
                "city": city,
                "coordinates": f"{lat}, {lon}",
                "asn": asn,
                "org": org
            },
            evidence_hash=raw.evidence_sha256
        )
