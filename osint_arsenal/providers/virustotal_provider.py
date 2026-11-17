import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class VirusTotalProvider(BaseOSINTProvider):
    name = "VirusTotal v3"
    website = "https://www.virustotal.com"
    api_endpoint = "https://www.virustotal.com/api/v3"
    method = "GET"
    authentication = "api_key"
    supported_inputs = [InputType.DOMAIN, InputType.IP, InputType.HASH, InputType.URL]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-VT-{uuid.uuid4().hex[:8]}"

        # REQUIREMENT 5 & 27: Strict No-Fabrication Check
        if not self.api_key:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.AUTH_REQUIRED,
                status_message="Threat intelligence provider could not be queried because authentication was unavailable.",
                endpoint_queried=self.api_endpoint
            )

        clean_target = target.strip()
        type_path = {
            InputType.DOMAIN: f"domains/{clean_target}",
            InputType.IP: f"ip_addresses/{clean_target}",
            InputType.HASH: f"files/{clean_target}",
            InputType.URL: f"urls/{clean_target}"
        }.get(input_type)

        endpoint = f"{self.api_endpoint}/{type_path}"
        headers = {"x-apikey": self.api_key, "User-Agent": "Nostromo-OSINT/3.0"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="VirusTotal analysis retrieved successfully.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=resp.json()
                    )
                elif resp.status_code == 404:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.NO_RESULT,
                        status_message="No result was returned by this provider for the target indicator.",
                        http_status_code=404
                    )
                elif resp.status_code == 429:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.RATE_LIMITED,
                        status_message="VirusTotal API quota exceeded (free tier limit 4 requests/min).",
                        http_status_code=429
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"VirusTotal request failed with HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="VirusTotal connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"VirusTotal error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "reputation": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "last_analysis_stats": {},
            "categories": {}
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        attr = raw.raw_response.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        normalized["reputation"] = attr.get("reputation", 0)
        normalized["malicious_count"] = stats.get("malicious", 0)
        normalized["suspicious_count"] = stats.get("suspicious", 0)
        normalized["harmless_count"] = stats.get("harmless", 0)
        normalized["undetected_count"] = stats.get("undetected", 0)
        normalized["total_engines"] = sum(stats.values())
        normalized["last_analysis_stats"] = stats
        normalized["categories"] = attr.get("categories", {})
        return normalized
