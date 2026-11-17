import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class CrtShCertificateProvider(BaseOSINTProvider):
    name = "crt.sh Certificate Transparency"
    website = "https://crt.sh"
    api_endpoint = "https://crt.sh"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.DOMAIN, InputType.URL]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-CRT-{uuid.uuid4().hex[:8]}"
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        endpoint = f"https://crt.sh/?q={clean_target}&output=json"
        headers = {"User-Agent": "Nostromo-OSINT/3.0"}

        async with httpx.AsyncClient(timeout=6.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if not data:
                            return RawProviderResponse(
                                collection_id=collection_id,
                                provider=self.name,
                                target=target,
                                input_type=input_type.value,
                                status=ProviderStatus.NO_RESULT,
                                status_message="Zero Certificate Transparency logs found for target.",
                                http_status_code=200
                            )
                        return RawProviderResponse(
                            collection_id=collection_id,
                            provider=self.name,
                            target=target,
                            input_type=input_type.value,
                            status=ProviderStatus.SUCCESS,
                            status_message=f"Retrieved {len(data)} Certificate Transparency logs.",
                            http_status_code=200,
                            endpoint_queried=endpoint,
                            raw_response={"certificates": data[:30]}
                        )
                    except Exception:
                        return RawProviderResponse(
                            collection_id=collection_id,
                            provider=self.name,
                            target=target,
                            input_type=input_type.value,
                            status=ProviderStatus.FAILED,
                            status_message="crt.sh returned non-JSON response."
                        )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"crt.sh server returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="crt.sh connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"crt.sh error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "certificates": [],
            "subdomains": [],
            "total_certificates": 0
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        certs = raw.raw_response.get("certificates", [])
        subdomains_set = set()

        for c in certs:
            common_name = c.get("common_name", "")
            name_val = c.get("name_value", "")
            issuer = c.get("issuer_name", "")
            entry_timestamp = c.get("entry_timestamp", "")
            not_before = c.get("not_before", "")
            not_after = c.get("not_after", "")
            serial = c.get("serial_number", "")

            # Extract distinct subdomains
            for name in name_val.split("\n"):
                clean = name.strip()
                if clean:
                    subdomains_set.add(clean)

            normalized["certificates"].append({
                "common_name": common_name,
                "subject_alt_names": name_val.replace("\n", ", "),
                "issuer": issuer,
                "valid_from": not_before,
                "valid_to": not_after,
                "serial_number": serial,
                "source": self.name,
                "entry_timestamp": entry_timestamp
            })

        normalized["subdomains"] = sorted(list(subdomains_set))
        normalized["total_certificates"] = len(certs)
        return normalized
