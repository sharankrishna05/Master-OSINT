import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class GreyNoiseCommunityProvider(BaseOSINTProvider):
    name = "GreyNoise Community"
    website = "https://viz.greynoise.io"
    api_endpoint = "https://api.greynoise.io/v3/community"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-GN-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip()

        endpoint = f"{self.api_endpoint}/{clean_target}"
        headers = {"Accept": "application/json", "User-Agent": "Nostromo-OSINT/3.0"}
        if self.api_key:
            headers["key"] = self.api_key

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="GreyNoise classification retrieved.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                elif resp.status_code == 404:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"noise": False, "riot": False, "message": "IP not observed scanning the internet."}
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="IP verified not observed scanning the internet (Benign).",
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
                        status_message=f"GreyNoise returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="GreyNoise connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"GreyNoise error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "noise": False,
            "riot": False,
            "classification": "unknown",
            "name": "unknown",
            "link": ""
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        d = raw.raw_response
        normalized["noise"] = d.get("noise", False)
        normalized["riot"] = d.get("riot", False)
        normalized["classification"] = d.get("classification", "unknown")
        normalized["name"] = d.get("name", "unknown")
        normalized["link"] = d.get("link", "")
        return normalized
