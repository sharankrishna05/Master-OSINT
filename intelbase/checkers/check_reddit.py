"""Reddit email registration checker."""
import aiohttp
from .base import BaseChecker
from ..models import CheckResult
from ..config import get_default_headers

class RedditChecker(BaseChecker):
    site_name = "Reddit"
    category = "Community"
    login_url = "https://www.reddit.com/login/"

    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        url = "https://www.reddit.com/api/v1/email_available"
        params = {"email": email}
        headers = get_default_headers({
            "Referer": "https://www.reddit.com/register/"
        })

        try:
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    # Reddit returns "true" if email is available (NOT registered)
                    # "false" if email is already taken/registered
                    if data.strip().lower() == "false":
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=True,
                            status="EXISTS",
                            details="Email is registered to a Reddit account",
                            login_url=self.login_url
                        )
                    elif data.strip().lower() == "true":
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=False,
                            status="NOT_FOUND",
                            details="Email is not registered on Reddit",
                            login_url=self.login_url
                        )
                    else:
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=None,
                            status="ERROR",
                            details=f"Unexpected Reddit response: {data[:50]}",
                            login_url=self.login_url
                        )
                elif resp.status == 429:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="RATE_LIMITED",
                        details="Reddit rate limited request",
                        login_url=self.login_url
                    )
                else:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="ERROR",
                        details=f"Reddit returned HTTP {resp.status}",
                        login_url=self.login_url
                    )
        except Exception as e:
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Reddit check error: {str(e)}",
                login_url=self.login_url
            )
