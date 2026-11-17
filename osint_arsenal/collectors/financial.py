import httpx
import uuid
from typing import List
from .base import BaseCollector, RawFinding, NormalizedFinding

class FinancialSanctionsCollector(BaseCollector):
    name = "OpenSanctions & Public Corporate Intelligence"
    category = "financial"
    legal_class = "public"
    rate_limit = 15

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        # Querying OpenSanctions public search API
        url = f"https://api.opensanctions.org/search/default?q={target}&limit=5"
        headers = {"User-Agent": "Nostromo-OSINT/2.0 (Academic Research; Compliance TLP:WHITE)"}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if results:
                        raw = RawFinding(
                            source_module=self.name,
                            collector_category=self.category,
                            target=target,
                            payload={"matches": results, "total": len(results)}
                        )
                        raw.compute_hash()
                        findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        matches = raw.payload.get("matches", [])
        indicators = []
        entities = []

        for m in matches:
            schema = m.get("schema", "")
            caption = m.get("caption", "")
            if "Sanction" in schema or "Person" in schema:
                indicators.append(f"SANCTION_RECORD_OBSERVED: {caption}")
            entities.append({"type": "entity_name", "value": caption})

        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="entity",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.96,
            threat_indicators=indicators if indicators else ["PUBLIC_BUSINESS_ENTITY_IDENTIFIED"],
            entities_discovered=entities[:10],
            mitre_attack_ids=["T1589"],
            attributes={"total_records": len(matches), "dataset": "OpenSanctions/OFAC Consolidated"},
            evidence_hash=raw.evidence_sha256
        )

class CryptoExplorerCollector(BaseCollector):
    name = "Public Blockchain Ledger Explorer"
    category = "financial"
    legal_class = "public"

    async def collect(self, target: str, target_type: str) -> List[RawFinding]:
        findings = []
        # Check if target resembles an Ethereum or Bitcoin public address
        is_eth = target.startswith("0x") and len(target) == 42
        is_btc = (target.startswith("1") or target.startswith("3") or target.startswith("bc1")) and 26 <= len(target) <= 42

        if not (is_eth or is_btc):
            return findings

        # Query public blockchain summary
        network = "ethereum" if is_eth else "bitcoin"
        url = f"https://blockchain.info/rawaddr/{target}?limit=5" if is_btc else f"https://api.blockcypher.com/v1/eth/main/addrs/{target}/balance"

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    raw = RawFinding(
                        source_module=self.name,
                        collector_category=self.category,
                        target=target,
                        payload={"network": network, "ledger_data": resp.json()}
                    )
                    raw.compute_hash()
                    findings.append(raw)
            except Exception:
                pass
        return findings

    async def normalize(self, raw: RawFinding) -> NormalizedFinding:
        network = raw.payload.get("network", "unknown")
        return NormalizedFinding(
            id=str(uuid.uuid4()),
            target=raw.target,
            target_type="crypto_wallet",
            source_name=self.name,
            category=self.category,
            timestamp=raw.timestamp,
            confidence=0.99,
            threat_indicators=["PUBLIC_BLOCKCHAIN_WALLET_LOCATED"],
            entities_discovered=[{"type": "wallet_address", "value": raw.target}],
            mitre_attack_ids=["T1589.001"],
            attributes={"ledger_network": network},
            evidence_hash=raw.evidence_sha256
        )
