from __future__ import annotations
import asyncio
from typing import List, Dict, Type, Optional
from .base import BaseEngine
from .google import GoogleEngine
from .bing import BingEngine
from .duckduckgo import DuckDuckGoEngine
from .brave import BraveEngine
from .yandex import YandexEngine
from .serpapi import SerpApiEngine
from ..models import DorkQuery, SearchResult, RunSummary
from ..parsers.normalizer import deduplicate_results

AVAILABLE_ENGINES: Dict[str, Type[BaseEngine]] = {
    "google": GoogleEngine,
    "bing": BingEngine,
    "duckduckgo": DuckDuckGoEngine,
    "brave": BraveEngine,
    "yandex": YandexEngine,
    "serpapi": SerpApiEngine
}

class EngineDispatcher:
    """Coordinates multi-engine query execution, concurrency, and result aggregation."""

    def __init__(self, engines: Optional[List[str]] = None, config=None):
        self.selected_engines: List[BaseEngine] = []
        engine_names = engines or ["duckduckgo", "google", "bing", "brave"]

        for name in engine_names:
            clean_name = name.lower().strip()
            if clean_name in AVAILABLE_ENGINES:
                engine_cls = AVAILABLE_ENGINES[clean_name]
                # Check for config overrides
                rate_limit = 1.0
                concurrency = 2
                if config and clean_name in config.engines:
                    cfg = config.engines[clean_name]
                    rate_limit = cfg.rate_limit
                    concurrency = cfg.concurrency_cap

                self.selected_engines.append(engine_cls(rate_limit=rate_limit, concurrency_cap=concurrency))

    async def execute_query(self, query: DorkQuery, limit_per_engine: int = 5) -> List[SearchResult]:
        """Execute a single dork query across all configured engines concurrently."""
        tasks = [engine.search(query.query, limit=limit_per_engine) for engine in self.selected_engines]
        engine_results = await asyncio.gather(*tasks, return_exceptions=True)

        combined: List[SearchResult] = []
        for res in engine_results:
            if isinstance(res, list):
                combined.extend(res)
        return combined

    async def execute_batch(
        self,
        queries: List[DorkQuery],
        limit_per_engine: int = 5,
        dry_run: bool = False
    ) -> List[SearchResult]:
        """Execute a batch of queries with controlled rate limiting and aggregation."""
        if dry_run:
            return []

        all_results: List[SearchResult] = []
        for q in queries:
            results = await self.execute_query(q, limit_per_engine=limit_per_engine)
            all_results.extend(results)

        return deduplicate_results(all_results)
