"""FastAPI application for IntelBase OSINT prototype."""
import asyncio
from pathlib import Path
import aiohttp
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .models import LookupResponse, CheckResult
from .checkers import ALL_CHECKERS
from .hibp import HIBPClient
from .scoring import calculate_risk_score
from .worker import stream_email_investigation
from .config import DEFAULT_TOTAL_TIMEOUT, DEFAULT_CONNECT_TIMEOUT

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="IntelBase OSINT Prototype",
    description="Asynchronous email registration checker and breach intelligence API",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "intelbase",
        "registered_checkers": len(ALL_CHECKERS),
        "checkers": [c.site_name for c in ALL_CHECKERS]
    }

@app.get("/")
@app.get("/dashboard")
async def serve_dashboard():
    dashboard_file = STATIC_DIR / "index.html"
    if dashboard_file.exists():
        return FileResponse(str(dashboard_file))
    return {"message": "IntelBase OSINT Engine API Online. Visit /lookup or /lookup/stream"}

@app.get("/lookup", response_model=LookupResponse)
async def lookup_email(email: str = Query(..., description="Target email address to investigate")):
    email = email.strip().lower()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address format")

    timeout = aiohttp.ClientTimeout(total=DEFAULT_TOTAL_TIMEOUT, connect=DEFAULT_CONNECT_TIMEOUT)
    hibp_client = HIBPClient()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Run checkers and HIBP concurrently
        checker_tasks = [checker.check(session, email) for checker in ALL_CHECKERS]
        hibp_task = hibp_client.get_breaches(session, email)

        results, (breaches, hibp_meta) = await asyncio.gather(
            asyncio.gather(*checker_tasks),
            hibp_task
        )

    risk = calculate_risk_score(results, breaches)
    registered_count = sum(1 for r in results if r.exists is True)

    return LookupResponse(
        email=email,
        total_sites_checked=len(results),
        registered_sites_count=registered_count,
        check_results=results,
        breaches=breaches,
        risk_assessment=risk
    )

@app.get("/lookup/stream")
async def stream_lookup(email: str = Query(..., description="Target email address for live SSE push")):
    email = email.strip().lower()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address format")

    return StreamingResponse(
        stream_email_investigation(email),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
