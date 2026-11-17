from __future__ import annotations
import os
import urllib.parse
from typing import List, Optional
from bs4 import BeautifulSoup
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class BingEngine(BaseEngine):
    name = "bing"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = self.api_key or os.environ.get("BING_SEARCH_API_KEY")

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        async with self.semaphore:
            if self.api_key:
                return await self._search_api(query, limit)

            url = "https://www.bing.com/search"
            params = {"q": query, "count": min(limit, 20)}
            resp = await self.execute_request_with_backoff(url, params=params)

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for li in soup.find_all("li", class_="b_algo"):
                    h2 = li.find("h2")
                    if not h2:
                        continue
                    a_tag = h2.find("a")
                    if not a_tag or not a_tag.get("href"):
                        continue

                    link = a_tag["href"]
                    title = a_tag.get_text(strip=True)
                    p_caption = li.find("p") or li.find("div", class_="b_caption")
                    snippet = p_caption.get_text(strip=True) if p_caption else ""

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
                        if len(results) >= limit:
                            break
        return results

    async def _search_api(self, query: str, limit: int) -> List[SearchResult]:
        results = []
        url = "https://api.bing.microsoft.com/v7.0/search"
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}
        params = {"q": query, "count": limit}
        resp = await self.execute_request_with_backoff(url, params=params, headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            for item in data.get("webPages", {}).get("value", []):
                link = item.get("url", "")
                title = item.get("name", "")
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
