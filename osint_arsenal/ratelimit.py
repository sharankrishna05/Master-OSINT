from __future__ import annotations
from fastapi import HTTPException

from .db import DB
from .config import settings


def check_rate(key: str, db: DB | None = None):
    db = db or DB()
    if db.count_usage(key, settings.rate_window) >= settings.rate_limit:
        raise HTTPException(
            429,
            f"Rate limit exceeded ({settings.rate_limit}/{settings.rate_window}s)",
        )
    db.record_usage(key)
