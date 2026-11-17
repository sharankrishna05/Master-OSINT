"""Comprehensive unit tests for IntelBase OSINT prototype."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from intelbase.models import CheckResult, BreachRecord, RiskAssessment, LookupResponse
from intelbase.checkers.check_github import GitHubChecker
from intelbase.hibp import HIBPClient
from intelbase.scoring import calculate_risk_score
from intelbase.app import app

client = TestClient(app)

class MockAsyncContextManager:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "intelbase"
    assert data["registered_checkers"] >= 1

def test_check_result_model():
    result = CheckResult(
        site_name="GitHub",
        category="Developer",
        exists=True,
        status="EXISTS",
        details="Account found",
        latency_ms=124.5,
        login_url="https://github.com/login"
    )
    assert result.site_name == "GitHub"
    assert result.exists is True
    assert result.status == "EXISTS"
    assert result.latency_ms == 124.5

def test_invalid_email_validation():
    response = client.get("/lookup?email=invalid-email")
    assert response.status_code == 400
    assert "Invalid email" in response.json()["detail"]

@pytest.mark.asyncio
async def test_github_checker_account_found():
    checker = GitHubChecker()
    mock_session = MagicMock()

    mock_get_resp = AsyncMock()
    mock_get_resp.status = 200
    mock_get_resp.text.return_value = '<html><input name="authenticity_token" value="dummy_csrf_token_123"/></html>'
    mock_session.get.return_value = MockAsyncContextManager(mock_get_resp)

    mock_post_resp = AsyncMock()
    mock_post_resp.status = 200
    mock_post_resp.url = "https://github.com/password_reset/done"
    mock_post_resp.text.return_value = "<html><body>Check your email for reset instructions</body></html>"
    mock_session.post.return_value = MockAsyncContextManager(mock_post_resp)

    res = await checker.check(mock_session, "test@example.com")
    assert res.site_name == "GitHub"
    assert res.exists is True
    assert res.status == "EXISTS"
    assert "Account confirmed" in res.details

@pytest.mark.asyncio
async def test_github_checker_account_not_found():
    checker = GitHubChecker()
    mock_session = MagicMock()

    mock_get_resp = AsyncMock()
    mock_get_resp.status = 200
    mock_get_resp.text.return_value = '<html><input name="authenticity_token" value="dummy_csrf_token_123"/></html>'
    mock_session.get.return_value = MockAsyncContextManager(mock_get_resp)

    mock_post_resp = AsyncMock()
    mock_post_resp.status = 200
    mock_post_resp.url = "https://github.com/password_reset"
    mock_post_resp.text.return_value = "<html><body>Can't find that email, sorry.</body></html>"
    mock_session.post.return_value = MockAsyncContextManager(mock_post_resp)

    res = await checker.check(mock_session, "nonexistent@example.com")
    assert res.site_name == "GitHub"
    assert res.exists is False
    assert res.status == "NOT_FOUND"

@pytest.mark.asyncio
async def test_github_checker_rate_limited():
    checker = GitHubChecker()
    mock_session = MagicMock()

    mock_get_resp = AsyncMock()
    mock_get_resp.status = 429
    mock_session.get.return_value = MockAsyncContextManager(mock_get_resp)

    res = await checker.check(mock_session, "ratelimited@example.com")
    assert res.site_name == "GitHub"
    assert res.exists is None
    assert res.status == "RATE_LIMITED"

@pytest.mark.asyncio
async def test_hibp_client_unconfigured():
    # If no key, should return unconfigured gracefully without raising
    hibp = HIBPClient(api_key="")
    mock_session = MagicMock()
    breaches, meta = await hibp.get_breaches(mock_session, "test@example.com")
    assert breaches == []
    assert meta["status"] == "UNCONFIGURED"
    assert meta["has_key"] is False

@pytest.mark.asyncio
async def test_hibp_client_breaches_found():
    hibp = HIBPClient(api_key="mock_test_key")
    mock_session = MagicMock()

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json.return_value = [
        {
            "Name": "Adobe",
            "Title": "Adobe Corp",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04",
            "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": True,
            "IsSensitive": False
        }
    ]
    mock_session.get.return_value = MockAsyncContextManager(mock_resp)

    breaches, meta = await hibp.get_breaches(mock_session, "victim@example.com")
    assert meta["status"] == "SUCCESS"
    assert len(breaches) == 1
    assert breaches[0].name == "Adobe"
    assert breaches[0].has_passwords is True

def test_risk_scoring_clean_account():
    checks = [
        CheckResult(site_name="GitHub", category="Developer", exists=False, status="NOT_FOUND", details="", latency_ms=10)
    ]
    risk = calculate_risk_score(checks, [])
    assert risk.score == 0
    assert risk.level == "LOW"
    assert risk.password_compromised is False

def test_risk_scoring_critical_account():
    checks = [
        CheckResult(site_name="GitHub", category="Developer", exists=True, status="EXISTS", details="", latency_ms=10),
        CheckResult(site_name="Twitter", category="Social Media", exists=True, status="EXISTS", details="", latency_ms=10),
        CheckResult(site_name="Discord", category="Communication", exists=True, status="EXISTS", details="", latency_ms=10)
    ]
    breaches = [
        BreachRecord(
            name="BreachOne",
            title="Breach One",
            domain="corp.com",
            breach_date="2025-01-01",
            added_date="2025-01-02",
            pwn_count=1000,
            data_classes=["Passwords", "Email addresses"],
            has_passwords=True
        ),
        BreachRecord(
            name="BreachTwo",
            title="Breach Two",
            domain="service.com",
            breach_date="2024-05-01",
            added_date="2024-05-02",
            pwn_count=5000,
            data_classes=["Email addresses"],
            has_passwords=False
        )
    ]
    risk = calculate_risk_score(checks, breaches)
    assert risk.score >= 65  # High or Critical
    assert risk.password_compromised is True
    assert "credentials/passwords exposed" in risk.reasoning

def test_sse_endpoint_stream():
    # Verify SSE streaming endpoint returns 200 text/event-stream
    with client.stream("GET", "/lookup/stream?email=streamtest@example.com") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
