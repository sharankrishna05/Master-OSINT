from __future__ import annotations
import os
from typing import List, Optional
from bs4 import BeautifulSoup
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class BraveEngine(BaseEngine):
    name = "brave"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = self.api_key or os.environ.get("BRAVE_API_KEY")

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        async with self.semaphore:
            if self.api_key:
                return await self._search_api(query, limit)

            url = "https://search.brave.com/search"
            params = {"q": query}
            resp = await self.execute_request_with_backoff(url, params=params)

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                snippets = soup.find_all("div", class_="snippet")
                for snip in snippets[:limit]:
                    a_tag = snip.find("a", href=True)
                    if not a_tag:
                        continue
                    link = a_tag["href"]
                    title = a_tag.get_text(strip=True)
                    desc_div = snip.find("div", class_="snippet-description") or snip.find("p")
                    snippet = desc_div.get_text(strip=True) if desc_div else ""

                    if link.startswith("http"):
                        cat, conf = classify_result(title, snippet, link)
                        results.append(SearchResult(
                            title=title,
                            url=link,
                            normalized_url=normalize_url(link),
                            snippet=snippet,
                            engine=self.name,
                            query=query,
                            category=cat,
                            domain=extract_domain(link),
                            confidence=conf
                        ))
        return results

    async def _search_api(self, query: str, limit: int) -> List[SearchResult]:
        results = []
        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {"X-Subscription-Token": self.api_key, "Accept": "application/json"}
        params = {"q": query, "count": limit}
        resp = await self.execute_request_with_backoff(url, params=params, headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            for item in data.get("web", {}).get("results", []):
                link = item.get("url", "")
                title = item.get("title", "")
                snippet = item.get("description", "")
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
