import asyncio
import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class GoogleDoHDNSProvider(BaseOSINTProvider):
    name = "Google DNS-over-HTTPS"
    website = "https://dns.google"
    api_endpoint = "https://dns.google/resolve"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.DOMAIN]
    enabled = True

    RECORD_TYPES = {
        1: "A",
        28: "AAAA",
        15: "MX",
        16: "TXT",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        257: "CAA"
    }

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-DNS-{uuid.uuid4().hex[:8]}"
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        all_records = {}
        async with httpx.AsyncClient(timeout=4.0) as client:
            async def fetch_record(r_type):
                try:
                    resp = await client.get(self.api_endpoint, params={"name": clean_target, "type": r_type})
                    if resp.status_code == 200:
                        return r_type, resp.json()
                    elif resp.status_code == 429:
                        return r_type, {"error": "RATE_LIMITED"}
                except Exception:
                    pass
                try:
                    resp = await client.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": clean_target, "type": r_type},
                        headers={"accept": "application/dns-json"}
                    )
                    if resp.status_code == 200:
                        return r_type, resp.json()
                except Exception:
                    pass
                return r_type, None

            record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA"]
            fetch_results = await asyncio.gather(*[fetch_record(rt) for rt in record_types], return_exceptions=True)
            for item in fetch_results:
                if isinstance(item, tuple) and item[1]:
                    if item[1].get("error") == "RATE_LIMITED":
                        pass
                    else:
                        all_records[item[0]] = item[1]

            try:

                # Check if any answers were returned
                total_answers = sum(len(res.get("Answer", [])) for res in all_records.values())
                if total_answers == 0:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.NO_RESULT,
                        status_message="No DNS records returned for target.",
                        http_status_code=200,
                        raw_response=all_records
                    )

                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.SUCCESS,
                    status_message=f"Successfully queried {len(all_records)} DNS record types.",
                    http_status_code=200,
                    endpoint_queried=self.api_endpoint,
                    raw_response=all_records
                )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="Connection timed out while resolving DNS via Google DoH."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"DNS resolution failed: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "soa_records": [],
            "caa_records": [],
            "ttl": {}
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        answers_map = {
            "A": "a_records",
            "AAAA": "aaaa_records",
            "MX": "mx_records",
            "NS": "ns_records",
            "TXT": "txt_records",
            "SOA": "soa_records",
            "CAA": "caa_records"
        }

        for r_type, data in raw.raw_response.items():
            field = answers_map.get(r_type)
            if not field:
                continue
            for ans in data.get("Answer", []):
                val = ans.get("data", "").strip('"')
                ttl = ans.get("TTL", 0)
                normalized[field].append({
                    "record": r_type,
                    "value": val,
                    "ttl": ttl,
                    "source": self.name,
                    "timestamp": raw.timestamp
                })
        return normalized
