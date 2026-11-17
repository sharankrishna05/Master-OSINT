from __future__ import annotations
from datetime import date, datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, HttpUrl


# ============ Shared enums ============

class Status(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    OK = "ok"
    SKIPPED = "skipped"


class LookupKind(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    CRYPTO = "crypto"
    URL = "url"
    HASH = "hash"
    COMPANY = "company"


# ============ Directory ============

class Tool(BaseModel):
    id: str
    name: str
    description: str
    url: str
    source: str | None = None
    category: str
    platforms: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    free: bool = True
    open_source: bool = False
    license: str | None = None
    added: str | None = None


class Category(BaseModel):
    id: str
    name: str
    icon: str = "🔧"


class Platform(BaseModel):
    id: str
    name: str


# ============ Lookups ============

class ModuleResult(BaseModel):
    module: str
    category: str = "uncategorized"
    status: Status
    url: str | None = None
    http_status: int | None = None
    confidence: float = 0.5
    evidence: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Verdict(BaseModel):
    kind: LookupKind
    query: str
    total_modules: int
    checked: int
    found: int
    not_found: int
    inconclusive: int
    errors: int
    confidence: float
    label: str            # high | medium | low | insufficient
    notes: list[str] = Field(default_factory=list)


# ============ WebCheck ============

class JobResult(BaseModel):
    job: str
    label: str
    group: str
    status: Status
    data: Any = None
    error: str | None = None
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============ Investigations (unified record) ============

class InvestigationKind(str, Enum):
    LOOKUP = "lookup"           # username/email/phone/domain/ip
    WEBCHECK = "webcheck"       # URL scan
    DIRECTORY = "directory"     # directory query (read-only, no persist needed)


class Investigation(BaseModel):
    id: str
    kind: InvestigationKind
    query: str
    subkind: str | None = None   # e.g. "username", "url"
    status: str = "running"      # running | done | error
    created_at: datetime = Field(default_factory=datetime.utcnow)
    verdict: Verdict | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    results: list[ModuleResult | JobResult] = Field(default_factory=list)
    followups: list[str] = Field(default_factory=list)
    api_key: str | None = None
    duration_ms: int = 0
