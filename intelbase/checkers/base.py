"""Abstract Base Checker for website account detection."""
import time
import logging
from abc import ABC, abstractmethod
import aiohttp
from ..models import CheckResult
from ..config import get_default_headers, DEFAULT_TOTAL_TIMEOUT, DEFAULT_CONNECT_TIMEOUT

logger = logging.getLogger("intelbase.checker")

class BaseChecker(ABC):
    site_name: str = "Unknown"
    category: str = "General"
    login_url: str = ""

    @abstractmethod
    async def _execute_check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        """Site-specific check logic to be implemented by child classes."""
        pass

    async def check(self, session: aiohttp.ClientSession, email: str) -> CheckResult:
        """Wrapper ensuring latency tracking, timeout safety, and standardized error handling."""
        start_time = time.monotonic()
        try:
            res = await self._execute_check(session, email)
            res.latency_ms = round((time.monotonic() - start_time) * 1000, 2)
            return res
        except aiohttp.ClientResponseError as e:
            latency = round((time.monotonic() - start_time) * 1000, 2)
            if e.status == 429:
                return CheckResult(
                    site_name=self.site_name,
                    category=self.category,
                    exists=None,
                    status="RATE_LIMITED",
                    details=f"Rate limited by {self.site_name} (HTTP 429)",
                    latency_ms=latency,
                    login_url=self.login_url
                )
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"HTTP error {e.status}: {e.message}",
                latency_ms=latency,
                login_url=self.login_url
            )
        except aiohttp.ClientConnectorError as e:
            latency = round((time.monotonic() - start_time) * 1000, 2)
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Connection error: {str(e)}",
                latency_ms=latency,
                login_url=self.login_url
            )
        except Exception as e:
            latency = round((time.monotonic() - start_time) * 1000, 2)
            return CheckResult(
                site_name=self.site_name,
                category=self.category,
                exists=None,
                status="ERROR",
                details=f"Check failed: {str(e)}",
                latency_ms=latency,
                login_url=self.login_url
            )
