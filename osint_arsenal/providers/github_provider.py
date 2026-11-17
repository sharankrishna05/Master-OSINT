import httpx
import uuid
from typing import Dict, Any, List
from .base import BaseOSINTProvider, InputType, ProviderStatus, RawProviderResponse

class GitHubPublicUserProvider(BaseOSINTProvider):
    name = "GitHub Public Intelligence"
    website = "https://github.com"
    api_endpoint = "https://api.github.com/users"
    method = "GET"
    authentication = "none"
    supported_inputs = [InputType.USERNAME, InputType.EMAIL]
    enabled = True

    async def collect(self, target: str, input_type: InputType) -> RawProviderResponse:
        collection_id = f"COL-GH-{uuid.uuid4().hex[:8]}"
        clean_target = target.strip()

        if input_type == InputType.EMAIL:
            # Search users by public email
            endpoint = f"https://api.github.com/search/users?q={clean_target}+in:email"
        else:
            endpoint = f"https://api.github.com/users/{clean_target}"

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Nostromo-OSINT/3.0"
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    # If email search, inspect items
                    if input_type == InputType.EMAIL:
                        items = data.get("items", [])
                        if not items:
                            return RawProviderResponse(
                                collection_id=collection_id,
                                provider=self.name,
                                target=target,
                                input_type=input_type.value,
                                status=ProviderStatus.NO_RESULT,
                                status_message="No public GitHub user matched this email address.",
                                http_status_code=200,
                                endpoint_queried=endpoint,
                                raw_response=data
                            )
                        # Fetch the first user profile
                        first_user = items[0]["login"]
                        user_resp = await client.get(f"https://api.github.com/users/{first_user}", headers=headers)
                        if user_resp.status_code == 200:
                            data = user_resp.json()

                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.SUCCESS,
                        status_message="GitHub public profile verified.",
                        http_status_code=200,
                        endpoint_queried=endpoint,
                        raw_response=data
                    )
                elif resp.status_code == 404:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.NO_RESULT,
                        status_message="No public GitHub profile found for this handle.",
                        http_status_code=404,
                        endpoint_queried=endpoint,
                        raw_response={"status": 404, "message": "Not Found"}
                    )
                elif resp.status_code == 403:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.RATE_LIMITED,
                        status_message="GitHub public API rate limit reached (60 req/hr unauthenticated).",
                        http_status_code=403,
                        endpoint_queried=endpoint,
                        raw_response=resp.json() if resp.text else {}
                    )
                else:
                    return RawProviderResponse(
                        collection_id=collection_id,
                        provider=self.name,
                        target=target,
                        input_type=input_type.value,
                        status=ProviderStatus.FAILED,
                        status_message=f"GitHub API returned HTTP {resp.status_code}",
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
                    status_message="GitHub API timed out after 8.0s.",
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
        return {
            "login": data.get("login"),
            "name": data.get("name"),
            "id": data.get("id"),
            "node_id": data.get("node_id"),
            "avatar_url": data.get("avatar_url"),
            "profile_url": data.get("html_url"),
            "company": data.get("company"),
            "blog": data.get("blog"),
            "location": data.get("location"),
            "email": data.get("email"),
            "bio": data.get("bio"),
            "twitter_username": data.get("twitter_username"),
            "public_repos": data.get("public_repos"),
            "public_gists": data.get("public_gists"),
            "followers": data.get("followers"),
            "following": data.get("following"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at")
        }
