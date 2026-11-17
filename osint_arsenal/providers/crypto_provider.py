import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class CryptoBlockchainProvider(BaseOSINTProvider):
    name = "Public Blockchain Ledger"
    website = "https://www.blockchain.com"
    api_endpoint = "https://blockchain.info / Blockcypher"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.CRYPTO]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-BC-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip()

        # Distinguish BTC vs ETH
        if clean_target.startswith("0x") and len(clean_target) == 42:
            # Ethereum address
            endpoint = f"https://api.blockcypher.com/v1/eth/main/addrs/{clean_target}/balance"
            crypto_type = "Ethereum (ETH)"
        else:
            # Bitcoin address
            endpoint = f"https://blockchain.info/rawaddr/{clean_target}?limit=5"
            crypto_type = "Bitcoin (BTC)"

        headers = {"User-Agent": "Nostromo-OSINT/3.0"}

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    data["crypto_network"] = crypto_type
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message=f"{crypto_type} ledger confirmed.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                elif resp.status_code in [400, 404]:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.NO_RESULT,
                        status_message=f"Address not found on {crypto_type} public ledger.",
                        http_status_code=resp.status_code,
                        endpoint_queried=endpoint,
                        raw_response={"status": resp.status_code}
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"Blockchain API returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code,
                        endpoint_queried=endpoint,
                        raw_response={"error": resp.text}
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="Blockchain node query timed out after 8.0s.",
                    endpoint_queried=endpoint
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=str(e),
                    endpoint_queried=endpoint
                )

    def normalize(self, raw_response: RawProviderResponse) -> Dict[str, Any]:
        data = raw_response.raw_response
        crypto_type = data.get("crypto_network", "Unknown")

        if "Bitcoin" in crypto_type:
            # Blockchain.info format
            final_balance_satoshis = data.get("final_balance", 0)
            btc_balance = final_balance_satoshis / 100000000.0
            total_received_btc = data.get("total_received", 0) / 100000000.0
            total_sent_btc = data.get("total_sent", 0) / 100000000.0
            txs = []
            for tx in data.get("txs", [])[:5]:
                txs.append({
                    "hash": tx.get("hash"),
                    "time": tx.get("time"),
                    "fee": tx.get("fee")
                })

            return {
                "network": "Bitcoin Mainnet",
                "address": data.get("address"),
                "balance_btc": btc_balance,
                "total_received_btc": total_received_btc,
                "total_sent_btc": total_sent_btc,
                "transaction_count": data.get("n_tx", 0),
                "recent_transactions": txs
            }
        else:
            # Ethereum / Blockcypher format
            balance_wei = data.get("balance", 0)
            eth_balance = balance_wei / 1e18 if balance_wei else 0
            return {
                "network": "Ethereum Mainnet",
                "address": data.get("address"),
                "balance_eth": eth_balance,
                "total_received_eth": (data.get("total_received", 0) / 1e18),
                "total_sent_eth": (data.get("total_sent", 0) / 1e18),
                "transaction_count": data.get("n_tx", 0),
                "unconfirmed_txs": data.get("unconfirmed_n_tx", 0)
            }
