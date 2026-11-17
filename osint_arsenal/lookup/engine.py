from __future__ import annotations
import asyncio
import time
import uuid

import httpx

from ..models import (
    Investigation, InvestigationKind, ModuleResult,
    LookupKind, Status, Verdict,
)
from .modules import registry
from .consensus import compute_verdict
from ..db import DB
from ..events import bus
from ..config import settings


class LookupEngine:
    def __init__(self, db: DB | None = None):
        self.db = db or DB()
        self._client: httpx.AsyncClient | None = None

    async def _client_ctx(self):
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=settings.http_timeout,
                headers={"User-Agent": settings.user_agent},
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _run_one(self, module, query: str,
                       sem: asyncio.Semaphore) -> ModuleResult:
        client = await self._client_ctx()
        start = time.time()
        async with sem:
            try:
                raw = await module.check(client, query)
            except Exception as e:
                raw = {"status": "error", "evidence": {"error": str(e)},
                       "confidence": 0.0, "url": None, "http_status": None}
        dur = int((time.time() - start) * 1000)
        return ModuleResult(
            module=module.name, category=module.category,
            status=Status(raw.get("status", "inconclusive")),
            url=raw.get("url"), http_status=raw.get("http_status"),
            confidence=float(raw.get("confidence", 0.5)),
            evidence=raw.get("evidence") or {}, duration_ms=dur,
        )

    async def scan(self, kind: LookupKind, query: str,
                   api_key: str | None = None,
                   followups: bool = True,
                   max_followups: int | None = None,
                   depth: int | None = None,
                   inv_id: str | None = None) -> Investigation:
        inv = Investigation(
            id=inv_id or str(uuid.uuid4()),
            kind=InvestigationKind.LOOKUP,
            subkind=kind.value,
            query=query,
            api_key=api_key,
        )
        self.db.create_investigation(inv)
        await bus.publish(inv.id, "status", {"status": "running"})

        followup_budget = max_followups if max_followups is not None else settings.max_followups
        max_depth = depth if depth is not None else settings.followup_depth

        await self._scan_recursive(inv, kind, query, followup_budget, max_depth)

        verdict = compute_verdict(kind, query,
                                  [r for r in inv.results if isinstance(r, ModuleResult)])
        inv.verdict = verdict
        inv.status = "done"
        self.db.update_investigation(
            inv.id, status="done", verdict=verdict, followups=inv.followups,
        )
        await bus.publish(inv.id, "status", {
            "status": "done", "verdict": verdict.model_dump(mode="json"),
        })
        return inv

    async def _scan_recursive(self, inv, kind, query, followup_budget, depth):
        modules = registry.for_kind(kind.value)
        await bus.publish(inv.id, "started",
                          {"query": query, "modules": len(modules)})

        sem = asyncio.Semaphore(settings.concurrency)
        tasks = [self._run_one(m, query, sem) for m in modules]
        results: list[ModuleResult] = []
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            inv.results.append(r)
            self.db.add_result(inv.id, r.module, r)
            await bus.publish(inv.id, "result", r.model_dump(mode="json"))

        if depth > 0 and followup_budget > 0 \
           and not settings.disable_followups:
            new_followups = self._extract_followups(results, inv.followups)[:followup_budget]
            inv.followups.extend(new_followups)
            for f in new_followups:
                if "@" in f and "." in f.split("@")[-1]:
                    fkind = LookupKind.EMAIL
                elif f.startswith("+") or f.replace(" ", "").isdigit():
                    fkind = LookupKind.PHONE
                else:
                    fkind = LookupKind.USERNAME
                await bus.publish(inv.id, "followup",
                                  {"query": f, "kind": fkind.value})
                await self._scan_recursive(inv, fkind, f,
                                           followup_budget - 1, depth - 1)

    @staticmethod
    def _extract_followups(results, already) -> list[str]:
        out: list[str] = []
        for r in results:
            for k, v in (r.evidence or {}).items():
                if k in ("email", "emails"):
                    items = v if isinstance(v, list) else [v]
                    out += [str(x) for x in items if x and "@" in str(x)]
                if k in ("username", "usernames", "linked_username"):
                    items = v if isinstance(v, list) else [v]
                    out += [str(x) for x in items if x]
        seen = set(already)
        return [x for x in out if not (x in seen or seen.add(x))]


async def run_lookup(kind: LookupKind, query: str, **kw) -> Investigation:
    e = LookupEngine()
    try:
        return await e.scan(kind, query, **kw)
    finally:
        await e.close()
