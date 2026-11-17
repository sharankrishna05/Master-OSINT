import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class PublicRepoSecretCollector(BaseCollector):
    name = "Public Code Repository Scanner"
    category = "code_repos"
    legal_class = "public"
    rate_limit = 10

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        # Search public GitHub code search API (lawful rate-limited query)
        url = f"https://api.github.com/search/code?q={target}+in:file&per_page=5"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Nostromo-OSINT/2.0"
        }
        if self.api_key:
            headers["Authorization"] = f"token {self.api_key}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    if items:
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload={"total_count": data.get("total_count", 0), "matches": items[:5]}
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        matches = raw.payload.get("matches", [])
        total = raw.payload.get("total_count", 0)
        repo_entities = []
        
        for m in matches:
            repo = m.get("repository", {}).get("full_name", "")
            if repo:
                repo_entities.append({"type": "github_repo", "value": repo})

        indicators = ["PUBLIC_CODE_REPO_MATCH_FOUND"]
        if total > 5:
            indicators.append("HIGH_FREQUENCY_SOURCE_CODE_EXPOSURE")

        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="code_reference",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.92,
            threat_indicators=indicators,
            entities_discovered=repo_entities,
            mitre_attack_ids=["T1593.003"],
            attributes={"total_repo_matches": total},
            evidence_hash=raw.evidence_sha256
        )
