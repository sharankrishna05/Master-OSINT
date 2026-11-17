from __future__ import annotations
import asyncio
import time
import uuid
from urllib.parse import urlparse

import httpx

from ..models import (
    Investigation, InvestigationKind, JobResult, Status,
)
from .jobs import registry
from ..db import DB
from ..events import bus
from ..config import settings


def _normalize_url(url: str) -> tuple[str, str, str]:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return url, p.netloc, p.scheme


class WebCheckEngine:
    def __init__(self, db: DB | None = None):
        self.db = db or DB()

    async def scan(self, url: str, api_key: str | None = None,
                   jobs: list[str] | None = None,
                   inv_id: str | None = None) -> Investigation:
        url, host, scheme = _normalize_url(url)
        inv = Investigation(
            id=inv_id or str(uuid.uuid4()),
            kind=InvestigationKind.WEBCHECK,
            subkind="url",
            query=url,
            api_key=api_key,
        )
        self.db.create_investigation(inv)
        await bus.publish(inv.id, "status", {"status": "running"})

        start = time.time()
        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        ) as client:
            if not registry.all():
                from .jobs.loader import load_all
                load_all()
            all_jobs = registry.all()
            if jobs:
                all_jobs = [j for j in all_jobs if j.name in jobs]
            ctx = {
                "client": client,
                "url": url,
                "host": host,
                "scheme": scheme,
            }

            sem = asyncio.Semaphore(settings.concurrency)
            async def _run(job):
                async with sem:
                    return await self._run_one(job, ctx)

            tasks = [asyncio.create_task(_run(j)) for j in all_jobs]
            for coro in asyncio.as_completed(tasks):
                r = await coro
                inv.results.append(r)
                self.db.add_result(inv.id, r.job, r)
                await bus.publish(inv.id, "result", r.model_dump(mode="json"))

        duration = int((time.time() - start) * 1000)
        inv.status = "done"
        inv.duration_ms = duration
        inv.summary = {
            "total": len(inv.results),
            "ok": sum(1 for r in inv.results if r.status == Status.OK),
            "errors": sum(1 for r in inv.results if r.status == Status.ERROR),
            "duration_ms": duration,
        }
        self.db.update_investigation(
            inv.id, status="done", summary=inv.summary, duration_ms=duration,
        )
        await bus.publish(inv.id, "status",
                          {"status": "done", "summary": inv.summary})
        return inv

    async def _run_one(self, job, ctx: dict) -> JobResult:
        start = time.time()
        try:
            data = await job.run(ctx)
            status = Status.OK
            err = None
        except Exception as e:
            data = None
            status = Status.ERROR
            err = str(e)
        dur = int((time.time() - start) * 1000)
        return JobResult(
            job=job.name, label=job.label, group=job.group,
            status=status, data=data, error=err, duration_ms=dur,
        )


async def run_webcheck(url: str, **kw) -> Investigation:
    return await WebCheckEngine().scan(url, **kw)
