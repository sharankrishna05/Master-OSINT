import os
import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class OpenSanctionsProvider(BaseOSINTProvider):
    name = "OpenSanctions Global Watchlist"
    website = "https://www.opensanctions.org"
    api_endpoint = "https://api.opensanctions.org/search/default"
    method = "GET"
    authentication = "api_key"
    supported_inputs = [InputType.ORGANIZATION, InputType.USERNAME, InputType.DOMAIN]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-OS-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip()
        endpoint = self.api_endpoint
        api_key = self.api_key or os.getenv("OPENSANCTIONS_API_KEY", "")

        if not api_key:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.AUTH_REQUIRED,
                status_message="OpenSanctions API requires an API key (OPENSANCTIONS_API_KEY).",
                endpoint_queried=endpoint
            )

        headers = {"User-Agent": "Nostromo-OSINT/3.0", "Authorization": f"ApiKey {api_key}"}
        params = {"q": clean_target, "limit": 5}

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if not results:
                        return RawProviderResponse(
                            collection_id=collection_id,
                            provider=self.name,
                            target=target,
                            input_type=input_type.value,
                            status=ProviderStatus.NO_RESULT,
                            status_message="No international sanctions or PEP matches found for entity.",
                            http_status_code=200,
                            endpoint_queried=endpoint,
                            raw_response=data
                        )
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message=f"Found {len(results)} potential international sanctions/PEP matches.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"OpenSanctions API returned HTTP {resp.status_code}",
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
                    status_message="OpenSanctions API timed out after 8.0s.",
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
        results = data.get("results", [])
        sanction_entries = []
        for item in results:
            sanction_entries.append({
                "id": item.get("id"),
                "caption": item.get("caption"),
                "schema": item.get("schema"),
                "datasets": item.get("datasets", []),
                "properties": {
                    "topics": item.get("properties", {}).get("topics", []),
                    "nationality": item.get("properties", {}).get("nationality", []),
                    "notes": item.get("properties", {}).get("notes", [])[:1] if item.get("properties", {}).get("notes") else []
                }
            })
        return {
            "total_matches": data.get("total", len(sanction_entries)),
            "matches": sanction_entries
        }
