from __future__ import annotations
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .routes import get_current_user_optional, router
from ..config import settings


def create_app() -> FastAPI:
    root = Path(__file__).resolve().parent.parent.parent
    app = FastAPI(
        title="OSINT Arsenal & Unified OSINT-HUB",
        version="2.0.0",
        description="Unified OSINT toolkit: CTI Full-Spectrum Arsenal + 2,466-Tool OSINT-HUB & Forensic Suite",
    )
    cors_origins = [o.strip() for o in settings.cors_origin.split(",") if o.strip()] or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.middleware("http")
    async def require_user_for_sensitive_routes(request: Request, call_next):
        path = request.url.path
        is_v2_api = path.startswith("/api/v2/") and path not in {
            "/api/v2/auth/login",
            "/api/v2/auth/register",
            "/api/v2/auth/google",
            "/api/v2/auth/me",
            "/api/v2/auth/logout",
        }
        is_sensitive_route = (
            is_v2_api
            or path.startswith(("/api/investigations", "/api/stream/"))
            or path.startswith(("/hub/api/", "/reports/"))
            or path in {"/intelbase/lookup", "/intelbase/lookup/stream"}
        )
        if settings.require_auth and is_sensitive_route:
            if not get_current_user_optional(request):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required"},
                )
        return await call_next(request)

    try:
        from osint_hub.web import create_app as create_hub_app
        hub_app = create_hub_app()
        app.mount("/hub", hub_app)
    except Exception as e:
        print(f"Warning: Failed to mount /hub: {e}")

    try:
        from intelbase.app import app as intelbase_app
        app.mount("/intelbase", intelbase_app)
    except Exception as e:
        print(f"Warning: Failed to mount /intelbase: {e}")

    static_dir = root / "web" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    reports_dir = Path(os.getenv("ARSENAL_REPORTS_DIR", str(root / "reports")))
    reports_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/reports", StaticFiles(directory=reports_dir, html=True), name="reports")

    return app
