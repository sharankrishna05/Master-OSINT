from __future__ import annotations
from fastapi import Header, HTTPException, Query

from .db import DB

_db: DB | None = None


def get_db() -> DB:
    global _db
    if _db is None:
        _db = DB()
    return _db


def require_key(
    key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    k = key or x_api_key
    if not k:
        raise HTTPException(401, "Missing API key")
    if not get_db().is_valid_key(k):
        raise HTTPException(401, "Invalid or revoked API key")
    return k
