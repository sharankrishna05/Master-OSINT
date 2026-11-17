from __future__ import annotations
import os
from typing import List, Optional
from .base import BaseEngine
from ..models import SearchResult
from ..parsers.normalizer import normalize_url, extract_domain
from ..parsers.classifier import classify_result

class SerpApiEngine(BaseEngine):
    name = "serpapi"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = self.api_key or os.environ.get("SERPAPI_API_KEY")

    async def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        results: List[SearchResult] = []
        if not self.api_key:
            return results

        async with self.semaphore:
            url = "https://serpapi.com/search"
            params = {
                "q": query,
                "api_key": self.api_key,
                "engine": "google",
                "num": limit
            }
            resp = await self.execute_request_with_backoff(url, params=params)
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get("organic_results", []):
                    link = item.get("link", "")
                    title = item.get("title", "")
                    snippet = item.get("snippet", "")
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
