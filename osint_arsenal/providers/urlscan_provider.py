import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class URLScanSearchProvider(BaseOSINTProvider):
    name = "URLScan.io Public Search"
    website = "https://urlscan.io"
    api_endpoint = "https://urlscan.io/api/v1/search"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.DOMAIN, InputType.URL, InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-URLSCAN-{uuid.uuid4().hex[:8]}"
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        endpoint = f"{self.api_endpoint}/?q=domain:{clean_target}&size=5"
        headers = {"User-Agent": "Nostromo-OSINT/3.0"}
        if self.api_key:
            headers["API-Key"] = self.api_key

        async with httpx.AsyncClient(timeout=12.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
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
                            status_message="No public scans indexed for this target on URLScan.io.",
                            http_status_code=200,
                            raw_response=data
                        )
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message=f"Retrieved {len(results)} historical scan profiles from URLScan.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                elif resp.status_code == 429:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.RATE_LIMITED,
                        status_message="URLScan.io public rate limit exceeded.",
                        http_status_code=429
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"URLScan returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="URLScan connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"URLScan error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "total_scans": 0,
            "recent_ips": [],
            "server_technologies": [],
            "titles": []
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        results = raw.raw_response.get("results", [])
        normalized["total_scans"] = len(results)

        for item in results:
            page = item.get("page", {})
            ip = page.get("ip")
            if ip and ip not in normalized["recent_ips"]:
                normalized["recent_ips"].append(ip)
            
            server = page.get("server")
            if server and server not in normalized["server_technologies"]:
                normalized["server_technologies"].append(server)

            title = page.get("title")
            if title and title not in normalized["titles"]:
                normalized["titles"].append(title)

        return normalized
