from __future__ import annotations
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class DorkQuery(BaseModel):
    """Represents a generated search dork."""
    query: str
    category: str
    template_id: str
    description: str = ""
    parameters: Dict[str, Any] = Field(default_factory=dict)
    generated_at: str = Field(default_factory=_utc_now_iso)

class SearchResult(BaseModel):
    """Normalized search engine result across all supported providers."""
    title: str
    url: str
    normalized_url: str
    snippet: str
    engine: str
    query: str
    category: str = "Uncategorized"
    domain: str = ""
    timestamp: str = Field(default_factory=_utc_now_iso)
    confidence: float = 0.85
    metadata: Dict[str, Any] = Field(default_factory=dict)

class DorkTemplate(BaseModel):
    """Template blueprint for combinatorial dork synthesis."""
    id: str
    name: str
    category: str
    description: str
    pattern: str
    required_vars: List[str] = Field(default_factory=lambda: ["domain"])
    default_vars: Dict[str, List[str]] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

class RunSummary(BaseModel):
    """High-level summary statistics of an execution run."""
    target_domain: str
    total_queries: int
    executed_queries: int
    total_results: int
    unique_results: int
    results_by_engine: Dict[str, int] = Field(default_factory=dict)
    results_by_category: Dict[str, int] = Field(default_factory=dict)
    execution_time_seconds: float = 0.0
    timestamp: str = Field(default_factory=_utc_now_iso)
