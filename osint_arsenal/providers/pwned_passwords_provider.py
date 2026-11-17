import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class HIBPPwnedPasswordsProvider(BaseOSINTProvider):
    name = "HIBP Pwned Passwords (k-Anonymity)"
    website = "https://haveibeenpwned.com"
    api_endpoint = "https://api.pwnedpasswords.com/range"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.HASH]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-HIBP-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip().upper()

        if len(clean_target) != 40:
            return RawProviderResponse(
                collection_id=collection_id,
                provider=self.name,
                target=target,
                input_type=input_type.value,
                status=ProviderStatus.NOT_SUPPORTED,
                status_message="HIBP k-Anonymity API requires a 40-character SHA-1 hash."
            )

        prefix = clean_target[:5]
        suffix = clean_target[5:]
        endpoint = f"{self.api_endpoint}/{prefix}"
        headers = {"User-Agent": "Nostromo-OSINT/3.0"}

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    matched_count = 0
                    for line in resp.text.splitlines():
                        if ":" in line:
                            s, cnt = line.split(":")
                            if s.strip().upper() == suffix.upper():
                                matched_count = int(cnt.strip())
                                break

                    if matched_count == 0:
                        return RawProviderResponse(
                            collection_id=collection_id,
                            provider=self.name,
                            target=target,
                            input_type=input_type.value,
                            status=ProviderStatus.NO_RESULT,
                            status_message="No breach occurrences found for this hash in HIBP database.",
                            http_status_code=200,
                            raw_response={"occurrences": 0}
                        )

                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message=f"Hash identified in {matched_count} public breach occurrences.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response={"occurrences": matched_count, "hash_prefix": prefix}
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"HIBP API returned HTTP {resp.status_code}",
                        http_status_code=resp.status_code
                    )
            except httpx.TimeoutException:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.TIMEOUT,
                    status_message="HIBP connection timed out."
                )
            except Exception as e:
                return RawProviderResponse(
                    collection_id=collection_id,
                    provider=self.name,
                    target=target,
                    input_type=input_type.value,
                    status=ProviderStatus.FAILED,
                    status_message=f"HIBP error: {str(e)}"
                )

    def normalize(self, raw: RawProviderResponse) -> Dict[str, Any]:
        normalized = {
            "occurrences": 0,
            "status": "CLEAN"
        }
        if raw.status == ProviderStatus.SUCCESS:
            normalized["occurrences"] = raw.raw_response.get("occurrences", 0)
            normalized["status"] = "EXPOSED_IN_PUBLIC_BREACHES"
        return normalized
