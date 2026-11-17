"""Twitter / X email registration checker."""
import re
import aiohttp
from .base import BaseChecker
from ..models import CheckResult
from ..config import get_default_headers

class TwitterChecker(BaseChecker):
    site_name = "Twitter / X"
    category = "Social Media"
    login_url = "https://x.com/login"

    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        # Twitter account flow initialization probe
        url = "https://api.twitter.com/1.1/users/email_available.json"
        params = {"email": email}
        headers = get_default_headers({
            "Referer": "https://twitter.com/signup"
        })

        try:
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # email_available: false means email is ALREADY REGISTERED / TAKEN
                    # email_available: true means email is NOT registered
                    is_taken = not data.get("taken", True) if "taken" in data else not data.get("valid", True)
                    if "taken" in data:
                        is_taken = bool(data.get("taken"))
                    
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=is_taken,
                        status="EXISTS" if is_taken else "NOT_FOUND",
                        details="Account registered on Twitter/X" if is_taken else "Email available / not registered",
                        login_url=self.login_url
                    )
                elif resp.status == 429:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="RATE_LIMITED",
                        details="Twitter API rate limited request (HTTP 429)",
                        login_url=self.login_url
                    )
                else:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="ERROR",
                        details=f"Twitter endpoint returned HTTP {resp.status}",
                        login_url=self.login_url
                    )
        except Exception as e:
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Twitter check exception: {str(e)}",
                login_url=self.login_url
            )
