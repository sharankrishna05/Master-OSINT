"""Asynchronous worker & SSE streaming generator for IntelBase."""
import json
import asyncio
from typing import AsyncGenerator
import aiohttp

from .models import CheckResult, BreachRecord, LookupResponse
from .checkers import ALL_CHECKERS
from .hibp import HIBPClient
from .scoring import calculate_risk_score
from .config import DEFAULT_TOTAL_TIMEOUT, DEFAULT_CONNECT_TIMEOUT

CONCURRENCY_LIMIT = 10

def format_sse(event_type: str, data: dict) -> str:
    """Format dictionary into standard SSE data frame."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

async def run_checker_with_semaphore(
    sem: asyncio.Semaphore,
    checker,
    session: aiohttp.ClientSession,
    email: str,
    queue: asyncio.Queue
):
    """Run checker bounded by concurrency semaphore and push result to queue."""
    async with sem:
        res = await checker.check(session, email)
        await queue.put(("checker_result", res))

async def stream_email_investigation(email: str) -> AsyncGenerator[str, None]:
    """Asynchronously stream checker updates and breach records via SSE."""
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TOTAL_TIMEOUT, connect=DEFAULT_CONNECT_TIMEOUT)
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    queue = asyncio.Queue()
    hibp_client = HIBPClient()

    # 1. Emit start event
    yield format_sse("start", {
        "email": email,
        "total_checkers": len(ALL_CHECKERS),
        "checkers": [c.site_name for c in ALL_CHECKERS]
    })

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Launch checker tasks
        tasks = [
            asyncio.create_task(run_checker_with_semaphore(sem, checker, session, email, queue))
            for checker in ALL_CHECKERS
        ]

        # Launch HIBP query concurrently
        hibp_task = asyncio.create_task(hibp_client.get_breaches(session, email))

        all_check_results = []
        pending_checkers = len(ALL_CHECKERS)

        # Stream checker results as they complete
        while pending_checkers > 0:
            event_type, res = await queue.get()
            all_check_results.append(res)
            pending_checkers -= 1

            yield format_sse("checker_result", {
                "site_name": res.site_name,
                "category": res.category,
                "exists": res.exists,
                "status": res.status,
                "details": res.details,
                "latency_ms": res.latency_ms,
                "login_url": res.login_url,
                "completed": len(all_check_results),
                "total": len(ALL_CHECKERS)
            })

        # Await HIBP results
        breaches, hibp_meta = await hibp_task
        yield format_sse("hibp_result", {
            "meta": hibp_meta,
            "breaches_count": len(breaches),
            "breaches": [b.model_dump() for b in breaches]
        })

        # Calculate final risk score
        risk = calculate_risk_score(all_check_results, breaches)
        registered_count = sum(1 for r in all_check_results if r.exists is True)

        yield format_sse("complete", {
            "email": email,
            "total_sites_checked": len(all_check_results),
            "registered_sites_count": registered_count,
            "risk_assessment": risk.model_dump(),
            "breaches_count": len(breaches)
        })
