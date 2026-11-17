import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class RdapWhoisProvider(BaseOSINTProvider):
    name = "RDAP Registry WHOIS"
    website = "https://rdap.org"
    api_endpoint = "https://rdap.org/domain"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.DOMAIN, InputType.IP]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-WHOIS-{uuid.uuid4().hex[:8]}"
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        endpoint = f"https://rdap.org/{'ip' if input_type == InputType.IP else 'domain'}/{clean_target}"
        headers = {"Accept": "application/rdap+json", "User-Agent": "Nostromo-OSINT/3.0"}

        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="RDAP records successfully parsed.",
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
                        status_message="No RDAP registry record located for target.",
                        http_status_code=404
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"RDAP query failed with HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="RDAP authority server connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"RDAP error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "registrar": "Unknown",
            "created": "Unknown",
            "expires": "Unknown",
            "last_changed": "Unknown",
            "status": [],
            "nameservers": [],
            "entities": []
        }
        if raw.status != ProviderStatus.SUCCESS:
            return normalized

        data = raw.raw_response

        # Parse RDAP events for registration and expiration dates
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            if action == "registration":
                normalized["created"] = date_str
            elif action == "expiration":
                normalized["expires"] = date_str
            elif action == "last changed":
                normalized["last_changed"] = date_str

        # Parse domain status
        normalized["status"] = data.get("status", [])

        # Parse nameservers
        for ns in data.get("nameservers", []):
            if "ldhName" in ns:
                normalized["nameservers"].append(ns["ldhName"])

        # Parse entities (Registrar / Registrant)
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [])
            ent_name = "Unknown"
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        ent_name = prop[3]
            if "registrar" in roles:
                normalized["registrar"] = ent_name
            normalized["entities"].append({"role": roles, "name": ent_name})

        return normalized
