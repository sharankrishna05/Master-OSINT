from __future__ import annotations
import urllib.parse
from typing import List
from bs4 import BeautifulSoup
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class YandexEngine(BaseEngine):
    name = "yandex"

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        async with self.semaphore:
            url = "https://yandex.com/search/"
            params = {"text": query}
            resp = await self.execute_request_with_backoff(url, params=params)

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for li in soup.find_all("li", class_="serp-item"):
                    a_tag = li.find("a", href=True)
                    if not a_tag:
                        continue
                    link = a_tag["href"]
                    title = a_tag.get_text(strip=True)
                    text_div = li.find("div", class_="text-container") or li.find("span")
                    snippet = text_div.get_text(strip=True) if text_div else ""

                    if link.startswith("http") and "yandex" not in link:
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
