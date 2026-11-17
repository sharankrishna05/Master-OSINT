import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class ShodanHostProvider(BaseOSINTProvider):
    name = "Shodan Computer Search"
    website = "https://www.shodan.io"
    api_endpoint = "https://api.shodan.io/shodan/host"
    method = "GET"
    authentication = "api_key"
    supported_inputs = [InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-SHODAN-{uuid.uuid4().hex[:8]}"

        if not self.api_key:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.AUTH_REQUIRED,
                status_message="Shodan host provider could not be queried because authentication API key was unavailable.",
                endpoint_queried=self.api_endpoint
            )

        clean_target = target.strip()
        endpoint = f"{self.api_endpoint}/{clean_target}?key={self.api_key}"

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="Shodan host infrastructure profile retrieved.",
                        http_status_code=200,
                        endpoint_queried=f"{self.api_endpoint}/{clean_target}",
                        raw_response=data
                    )
                elif resp.status_code == 404:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.NO_RESULT,
                        status_message="No open ports or services found in Shodan database.",
                        http_status_code=404,
                        endpoint_queried=f"{self.api_endpoint}/{clean_target}",
                        raw_response={"status": 404, "message": "Not Found"}
                    )
                elif resp.status_code == 401:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.AUTH_REQUIRED,
                        status_message="Invalid Shodan API key provided.",
                        http_status_code=401,
                        endpoint_queried=f"{self.api_endpoint}/{clean_target}"
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"Shodan returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code,
                        endpoint_queried=f"{self.api_endpoint}/{clean_target}",
                        raw_response={"error": resp.text}
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="Shodan API timed out after 8.0s.",
                    endpoint_queried=f"{self.api_endpoint}/{clean_target}"
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=str(e),
                    endpoint_queried=f"{self.api_endpoint}/{clean_target}"
                )

    def normalize(self, raw_response: RawProviderResponse) -> Dict[str, Any]:
        data = raw_response.raw_response
        return {
            "ip_str": data.get("ip_str"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "city": data.get("city"),
            "country_name": data.get("country_name")
        }
