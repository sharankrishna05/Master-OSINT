import pytest
from fastapi.testclient import TestClient
from osint_arsenal.api.server import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_api_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "OPERATIONAL"
    assert data["zero_fabrication_policy"] == "ENFORCED"
    assert data["registered_cti_providers"] >= 14


def test_cti_providers_list(client):
    r = client.get("/api/v2/providers")
    assert r.status_code == 200
    assert len(r.json()) >= 14


def test_mitre_matrix(client):
    r = client.get("/api/v2/analytics/mitre-matrix")
    assert r.status_code == 200
    data = r.json()
    assert "tactics" in data
    assert len(data["tactics"]) >= 4


def test_typosquat_analytics(client):
    r = client.get("/api/v2/analytics/typosquat/paypal.com")
    assert r.status_code == 200
    data = r.json()
    assert data["original_domain"] == "paypal.com"
    assert len(data["active_lookalikes"]) > 0


def test_attribution_analytics(client):
    r = client.get("/api/v2/analytics/attribution/0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
    assert r.status_code == 200
    data = r.json()
    assert "primary_attributed_group" in data


def test_breach_analytics(client):
    r = client.get("/api/v2/analytics/breach/test@example.com")
    assert r.status_code == 200
    data = r.json()
    assert data["total_exposures_identified"] > 0


def test_nexus_ui_route(client):
    r = client.get("/nexus")
    assert r.status_code == 200
    assert "NOSTROMO" in r.text or "OSINT" in r.text
