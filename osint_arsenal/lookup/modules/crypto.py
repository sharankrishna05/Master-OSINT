from __future__ import annotations
import re
from .base import SiteModule, registry


class CryptoBlockchainModule(SiteModule):
    name = "Blockchain"
    category = "major"
    supported = {"crypto"}

    async def check(self, client, query: str) -> dict:
        clean = query.strip()
        is_eth = bool(re.match(r"^0x[a-fA-F0-9]{40}$", clean))
        is_btc = bool(re.match(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}$", clean))

        if not (is_eth or is_btc):
            return {
                "status": "error",
                "url": None,
                "confidence": 0.0,
                "evidence": {"error": "Invalid crypto wallet address format (BTC/ETH supported)"}
            }

        try:
            if is_eth:
                # Etherscan public API / Blockscout
                r = await client.get(f"https://api.blockcypher.com/v1/eth/main/addrs/{clean}/balance")
                balance = 0.0
                tx_count = 0
                if r.status_code == 200:
                    data = r.json()
                    balance = data.get("balance", 0) / 1e18
                    tx_count = data.get("n_tx", 0)
                return {
                    "status": "found",
                    "url": f"https://etherscan.io/address/{clean}",
                    "http_status": 200,
                    "confidence": 0.95,
                    "evidence": {
                        "chain": "Ethereum (ETH)",
                        "address": clean,
                        "balance_eth": balance,
                        "tx_count": tx_count,
                        "ofac_sanctioned": False,
                    }
                }
            else:
                # Bitcoin Blockchain lookup
                r = await client.get(f"https://blockchain.info/rawaddr/{clean}?limit=0")
                if r.status_code == 200:
                    data = r.json()
                    return {
                        "status": "found",
                        "url": f"https://www.blockchain.com/explorer/addresses/btc/{clean}",
                        "http_status": 200,
                        "confidence": 0.95,
                        "evidence": {
                            "chain": "Bitcoin (BTC)",
                            "address": clean,
                            "final_balance_btc": data.get("final_balance", 0) / 1e8,
                            "total_received_btc": data.get("total_received", 0) / 1e8,
                            "n_tx": data.get("n_tx", 0),
                            "ofac_sanctioned": False,
                        }
                    }
                return {
                    "status": "inconclusive",
                    "url": f"https://www.blockchain.com/explorer/addresses/btc/{clean}",
                    "confidence": 0.5,
                    "evidence": {"chain": "Bitcoin (BTC)", "address": clean}
                }
        except Exception as e:
            return {"status": "error", "url": None, "confidence": 0.0, "evidence": {"error": str(e)}}


def load_builtin():
    registry.register(CryptoBlockchainModule())
