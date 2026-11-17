import httpx
import uuid
import os
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class AbuseIPDBProvider(BaseOSINTProvider):
    name = "AbuseIPDB Threat Intelligence"
    website = "https://www.abuseipdb.com"
    api_endpoint = "https://api.abuseipdb.com/api/v2/check"
    method = "GET"
    authentication = "api_key"
    supported_inputs = [InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-ABUSE-{uuid.uuid4().hex[:8]}"

        if not self.api_key:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.AUTH_REQUIRED,
                status_message="AbuseIPDB provider could not be queried because authentication API key was unavailable.",
                endpoint_queried=self.api_endpoint
            )

        endpoint = self.api_endpoint
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Nostromo-OSINT/3.0"
        }
        params = {"ipAddress": target.strip(), "maxAgeInDays": 90, "verbose": True}

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="AbuseIPDB IP reputation score retrieved.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                elif resp.status_code == 401:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.AUTH_REQUIRED,
                        status_message="Invalid AbuseIPDB API key provided.",
                        http_status_code=401,
                        endpoint_queried=endpoint,
                        raw_response=resp.json() if resp.text else {}
                    )
                elif resp.status_code == 429:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.RATE_LIMITED,
                        status_message="AbuseIPDB rate limit exceeded.",
                        http_status_code=429,
                        endpoint_queried=endpoint
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"AbuseIPDB returned HTTP {resp.status_code}",
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
                    status_message="AbuseIPDB timed out after 8.0s.",
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
        data = raw_response.raw_response.get("data", {})
        return {
            "ip_address": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt")
        }
