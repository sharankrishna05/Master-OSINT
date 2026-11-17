from __future__ import annotations
import os
import urllib.parse
from typing import List, Optional
from bs4 import BeautifulSoup
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class GoogleEngine(BaseEngine):
    name = "google"

    def __init__(self, *args, cse_id: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = self.api_key or os.environ.get("GOOGLE_API_KEY")
        self.cse_id = cse_id or os.environ.get("GOOGLE_CSE_ID")

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        async with self.semaphore:
            # 1. Use official API if key & CX are configured
            if self.api_key and self.cse_id:
                return await self._search_api(query, limit)

            # 2. Public endpoint (respecting robots & standard user rate-limits)
            url = "https://www.google.com/search"
            params = {"q": query, "num": min(limit, 20), "hl": "en"}
            resp = await self.execute_request_with_backoff(url, params=params)

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                # Standard search link containers
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    # Parse target link from /url?q=...
                    clean_url = ""
                    if href.startswith("/url?q="):
                        clean_url = href.split("/url?q=")[1].split("&")[0]
                        clean_url = urllib.parse.unquote(clean_url)
                    elif href.startswith("http") and "google.com" not in href:
                        clean_url = href

                    if clean_url and clean_url.startswith("http"):
                        # Extract title & snippet if available
                        h3 = a_tag.find("h3")
                        title = h3.get_text(strip=True) if h3 else clean_url
                        snippet = ""
                        parent = a_tag.find_parent("div")
                        if parent:
                            snippet = parent.get_text(strip=True)[:250]

                        cat, conf = classify_result(title, snippet, clean_url)
                        results.append(SearchResult(
                            title=title,
                            url=clean_url,
                            normalized_url=normalize_url(clean_url),
                            snippet=snippet,
                            engine=self.name,
                            query=query,
                            category=cat,
                            domain=extract_domain(clean_url),
                            confidence=conf
                        ))
                        if len(results) >= limit:
                            break
        return results

    async def _search_api(self, query: str, limit: int) -> List[SearchResult]:
        results = []
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": self.api_key,
            "cx": self.cse_id,
            "q": query,
            "num": min(limit, 10)
        }
        resp = await self.execute_request_with_backoff(url, params=params)
        if resp and resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                link = item.get("link", "")
                title = item.get("title", "")
                snippet = item.get("snippet", "")
                cat, conf = classify_result(title, snippet, link)
                results.append(SearchResult(
                    title=title,
                    url=link,
                    normalized_url=normalize_url(link),
                    snippet=snippet,
                    engine=f"{self.name}_api",
                    query=query,
                    category=cat,
                    domain=extract_domain(link),
                    confidence=conf
                ))
        return results
