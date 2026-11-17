import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class IPInfoGeoProvider(BaseOSINTProvider):
    name = "IP Geolocation & ASN Intelligence"
    website = "http://ip-api.com"
    api_endpoint = "http://ip-api.com/json"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-IP-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip()

        endpoint = f"http://ip-api.com/json/{clean_target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query"

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return RawProviderResponse(
                            collection_id=collection_id,
                            provider=self.name,
                            target=target,
                            input_type=input_type.value,
                            status=ProviderStatus.SUCCESS,
                            status_message="IP intelligence retrieved successfully.",
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
                            status=ProviderStatus.NO_RESULT,
                            status_message=f"IP provider returned: {data.get('message', 'invalid IP')}",
                            http_status_code=200,
                            raw_response=data
                        )
                elif resp.status_code == 429:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.RATE_LIMITED,
                        status_message="ip-api rate limit (45 req/min) exceeded.",
                        http_status_code=429
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"IP service returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="IP service connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"IP provider error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "ip": raw.target,
            "country": "Unknown",
            "country_code": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": "Unknown",
            "isp": "Unknown",
            "organization": "Unknown",
            "asn": "Unknown",
            "reverse_dns": "Unknown"
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        data = raw.raw_response
        normalized["country"] = data.get("country", "Unknown")
        normalized["country_code"] = data.get("countryCode", "Unknown")
        normalized["region"] = data.get("regionName", "Unknown")
        normalized["city"] = data.get("city", "Unknown")
        normalized["latitude"] = data.get("lat")
        normalized["longitude"] = data.get("lon")
        normalized["timezone"] = data.get("timezone", "Unknown")
        normalized["isp"] = data.get("isp", "Unknown")
        normalized["organization"] = data.get("org", "Unknown")
        normalized["asn"] = data.get("as", "Unknown")
        normalized["reverse_dns"] = data.get("reverse", "Unknown")
        return normalized
