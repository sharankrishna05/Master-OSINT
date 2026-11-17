from __future__ import annotations
import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import httpx
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

logger = logging.getLogger("dorkforge.engines")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
]

class BaseEngine(ABC):
    """Abstract base class for search engine adapters."""

    name: str = "base"

    def __init__(
        self,
        rate_limit: float = 1.0,
        concurrency_cap: int = 2,
        timeout: float = 12.0,
        api_key: Optional[str] = None
    ):
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(concurrency_cap)
        self.timeout = timeout
        self.api_key = api_key
        self._last_request_time = 0.0

    def get_random_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1"
        }

    async def _throttle(self):
        """Enforce per-engine rate limit with light randomized jitter."""
        async with asyncio.Lock():
            now = time.time()
            elapsed = now - self._last_request_time
            delay = (1.0 / self.rate_limit) + random.uniform(0.1, 0.3)
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self._last_request_time = time.time()

    async def execute_request_with_backoff(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_retries: int = 3
    ) -> Optional[httpx.Response]:
        """Send HTTP request with exponential backoff and Retry-After header inspection."""
        await self._throttle()
        req_headers = headers or self.get_random_headers()

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.get(url, params=params, headers=req_headers)

                    if resp.status_code == 200:
                        return resp
                    elif resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        wait_sec = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** (attempt + 1)) + random.uniform(0.5, 1.5)
                        logger.warning(f"Engine [{self.name}] rate-limited (HTTP 429). Retrying after {wait_sec:.1f}s...")
                        await asyncio.sleep(wait_sec)
                    elif resp.status_code in [500, 502, 503, 504]:
                        wait_sec = (1.5 ** (attempt + 1))
                        await asyncio.sleep(wait_sec)
                    else:
                        logger.warning(f"Engine [{self.name}] returned HTTP {resp.status_code} for URL: {url}")
                        return resp
            except Exception as e:
                logger.debug(f"Engine [{self.name}] connection attempt {attempt+1} failed: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(1.0 + attempt)
        return None

    @abstractmethod
    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        """Perform search query and return normalized results."""
        pass
