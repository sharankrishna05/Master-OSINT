import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class PublicSocialMediaCollector(BaseCollector):
    name = "Public Social Firehose & Identity Matrix"
    category = "social_media"
    legal_class = "public"
    rate_limit = 20

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        if target_type not in ["username", "email", "domain"]:
            return findings

        # Public Reddit API search (requires no auth for search.json)
        url = f"https://www.reddit.com/search.json?q={target}&limit=5&sort=relevance"
        headers = {"User-Agent": "NostromoOSINT/2.0"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    children = data.get("data", {}).get("children", [])
                    if children:
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload={"reddit_mentions": len(children), "samples": [c["data"]["title"] for c in children[:3]]}
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        count = raw.payload.get("reddit_mentions", 0)
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="social_mention",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.85,
            threat_indicators=["PUBLIC_FORUM_DISCUSSION_IDENTIFIED"],
            entities_discovered=[],
            mitre_attack_ids=["T1593.001"],
            attributes=raw.payload,
            evidence_hash=raw.evidence_sha256
        )
