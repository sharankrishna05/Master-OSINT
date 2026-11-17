"""GitHub email registration checker."""
import re
import aiohttp
from .base import BaseChecker
from ..models import CheckResult
from ..config import get_default_headers

class GitHubChecker(BaseChecker):
    site_name = "GitHub"
    category = "Developer"
    login_url = "https://github.com/login"

    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        reset_url = "https://github.com/password_reset"
        headers = get_default_headers({
            "Origin": "https://github.com",
            "Referer": "https://github.com/password_reset"
        })

        # Step 1: Obtain CSRF authenticity token
        async with session.get(reset_url, headers=headers) as resp:
            if resp.status == 429:
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=None,
                    status="RATE_LIMITED",
                    details="Rate limit encountered fetching reset token",
                    login_url=self.login_url
                )
            if resp.status != 200:
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=None,
                    status="ERROR",
                    details=f"Failed to access password reset page (HTTP {resp.status})",
                    login_url=self.login_url
                )

            html = await resp.text()
            token_match = re.search(r'name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']', html)
            if not token_match:
                token_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']authenticity_token["\']', html)
            
            csrf_token = token_match.group(1) if token_match else None

        if not csrf_token:
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details="Could not extract GitHub authenticity_token",
                login_url=self.login_url
            )

        # Step 2: Post password reset request
        post_data = {
            "authenticity_token": csrf_token,
            "email": email
        }

        async with session.post(reset_url, data=post_data, headers=headers, allow_redirects=True) as post_resp:
            post_html = await post_resp.text()

            # Analyze response patterns
            # Negative indicators: "Can't find that email", "No user found"
            if "Can't find that email" in post_html or "can't find that email" in post_html.lower():
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=False,
                    status="NOT_FOUND",
                    details="No account registered with this email address",
                    login_url=self.login_url
                )
            
            # Positive indicators: "Check your email", redirect to confirmation, or 200 with instructions
            if (
                "Check your email" in post_html
                or "instructions have been sent" in post_html.lower()
                or "password_reset/done" in str(post_resp.url)
            ):
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=True,
                    status="EXISTS",
                    details="Account confirmed on GitHub via password recovery probe",
                    login_url=self.login_url
                )

            # If rate limited on post
            if post_resp.status == 429 or "rate limit" in post_html.lower():
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=None,
                    status="RATE_LIMITED",
                    details="Rate limit hit during recovery post",
                    login_url=self.login_url
                )

            # Fallback if page structure altered
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details="Ambiguous response pattern from GitHub recovery endpoint",
                login_url=self.login_url
            )
