"""Pydantic data models for IntelBase email OSINT intelligence."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class CheckResult(BaseModel):
    site_name: str
    category: str
    exists: Optional[bool] = None
    status: str  # "EXISTS", "NOT_FOUND", "RATE_LIMITED", "ERROR"
    details: str
    latency_ms: float = 0.0
    login_url: str = ""

class BreachRecord(BaseModel):
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    pwn_count: int
    data_classes: List[str] = Field(default_factory=list)
    is_verified: bool = True
    is_sensitive: bool = False
    has_passwords: bool = False

class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reasoning: str
    breach_count: int = 0
    password_compromised: bool = False
    registered_sites_count: int = 0

class LookupResponse(BaseModel):
    email: str
    total_sites_checked: int
    registered_sites_count: int
    check_results: List[CheckResult]
    breaches: List[BreachRecord] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
