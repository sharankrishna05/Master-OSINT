from __future__ import annotations
import re
import urllib.parse
from typing import List
from bs4 import BeautifulSoup
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class DuckDuckGoEngine(BaseEngine):
    name = "duckduckgo"

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        async with self.semaphore:
            url = "https://html.duckduckgo.com/html/"
            headers = self.get_random_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            # DuckDuckGo HTML POST query
            try:
                import httpx
                await self._throttle()
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.post(url, data={"q": query}, headers=headers)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, "html.parser")
                        links = soup.find_all("a", class_="result__url")
                        snippets = soup.find_all("a", class_="result__snippet")
                        titles = soup.find_all("a", class_="result__a")

                        for i in range(min(len(titles), limit)):
                            title_text = titles[i].get_text(strip=True) if i < len(titles) else "Search Result"
                            snippet_text = snippets[i].get_text(strip=True) if i < len(snippets) else ""

                            # Extract target href
                            raw_href = titles[i].get("href", "")
                            target_url = ""
                            if "uddg=" in raw_href:
                                try:
                                    parsed = urllib.parse.urlparse(raw_href)
                                    qs = urllib.parse.parse_qs(parsed.query)
                                    if "uddg" in qs:
                                        target_url = qs["uddg"][0]
                                except Exception:
                                    pass
                            if not target_url:
                                target_url = raw_href

                            if target_url and target_url.startswith("http"):
                                cat, conf = classify_result(title_text, snippet_text, target_url)
                                results.append(SearchResult(
                                    title=title_text,
                                    url=target_url,
                                    normalized_url=normalize_url(target_url),
                                    snippet=snippet_text,
                                    engine=self.name,
                                    query=query,
                                    category=cat,
                                    domain=extract_domain(target_url),
                                    confidence=conf
                                ))
            except Exception as e:
                pass
        return results
