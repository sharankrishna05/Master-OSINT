"""Discord email registration checker."""
import aiohttp
from .base import BaseChecker
from ..models import CheckResult
from ..config import get_default_headers

class DiscordChecker(BaseChecker):
    site_name = "Discord"
    category = "Communication"
    login_url = "https://discord.com/login"

    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        url = "https://discord.com/api/v9/auth/register"
        payload = {
            "email": email,
            "username": "osint_probe_user",
            "password": "Password123!@#Probe",
            "consent": True
        }
        headers = get_default_headers({
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/register",
            "Content-Type": "application/json"
        })

        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                data = await resp.json()
                errors = data.get("errors", {})
                email_err = errors.get("email", {})
                err_code = email_err.get("_errors", [{}])[0].get("code", "")
                err_msg = email_err.get("_errors", [{}])[0].get("message", "")

                # Discord returns EMAIL_ALREADY_REGISTERED
                if err_code == "EMAIL_ALREADY_REGISTERED" or "already registered" in err_msg.lower():
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=True,
                        status="EXISTS",
                        details="Account registered on Discord (EMAIL_ALREADY_REGISTERED)",
                        login_url=self.login_url
                    )
                elif resp.status == 429:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=None,
                        status="RATE_LIMITED",
                        details="Discord rate limit / captcha encountered",
                        login_url=self.login_url
                    )
                else:
                    return CheckResult(
                        site_name=self.site_name,
                        category=self.category,
                        exists=False,
                        status="NOT_FOUND",
                        details="Email not currently linked to a Discord account",
                        login_url=self.login_url
                    )
        except Exception as e:
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Discord check error: {str(e)}",
                login_url=self.login_url
            )
