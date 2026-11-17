"""Spotify email registration checker."""
import aiohttp
from .base import BaseChecker
from ..models import CheckResult
from ..config import get_default_headers

class SpotifyChecker(BaseChecker):
    site_name = "Spotify"
    category = "Music & Media"
    login_url = "https://accounts.spotify.com/en/login"

    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        url = "https://spclient.wg.spotify.com/signup/public/v1/account"
        params = {"validate": "1", "email": email}
        headers = get_default_headers({
            "Origin": "https://www.spotify.com",
            "Referer": "https://www.spotify.com/signup"
        })

        try:
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    status_code = data.get("status")
                    errors = data.get("errors", {})

                    # Status 20 means email already exists on Spotify
                    # Status 1 means valid / email not registered
                    if status_code == 20 or "email" in errors:
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=True,
                            status="EXISTS",
                            details="Email is linked to an existing Spotify account",
                            login_url=self.login_url
                        )
                    elif status_code == 1:
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=False,
                            status="NOT_FOUND",
                            details="Email is available / not registered on Spotify",
                            login_url=self.login_url
                        )
                    else:
                        return CheckResult(
                            site_name=self.site_name,
                            category=self.category,
                            exists=None,
                            status="NOT_FOUND",
                            details="No existing Spotify account detected",
                            login_url=self.login_url
                        )
                elif resp.status == 429:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="RATE_LIMITED",
                        details="Spotify rate limited request (HTTP 429)",
                        login_url=self.login_url
                    )
                else:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="ERROR",
                        details=f"Spotify returned HTTP {resp.status}",
                        login_url=self.login_url
                    )
        except Exception as e:
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Spotify check error: {str(e)}",
                login_url=self.login_url
            )
