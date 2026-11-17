import pytest
from fastapi.testclient import TestClient
from osint_arsenal.api.server import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    from osint_arsenal import config
    monkeypatch.setattr(config.settings, "db_path", str(tmp_path / "t.db"))
    monkeypatch.setattr(config.settings, "default_keys", ["test"])
    return TestClient(create_app())


def test_index(client):
    assert client.get("/").status_code == 200


def test_directory(client):
    r = client.get("/api/directory/tools?free=true")
    assert r.status_code == 200
    tools = r.json()
    assert all(t["free"] for t in tools)


def test_lookup_requires_key(client):
    r = client.post("/api/lookup", json={"kind": "username", "query": "x"})
    assert r.status_code == 401


def test_lookup_starts(client):
    r = client.post("/api/lookup",
                    headers={"X-API-Key": "test"},
                    json={"kind": "username", "query": "testuser"})
    assert r.status_code == 200


def test_webcheck_starts(client):
    r = client.post("/api/webcheck",
                    headers={"X-API-Key": "test"},
                    json={"url": "https://example.com"})
    assert r.status_code == 200


def test_investigations_list(client):
    r = client.get("/api/investigations")
    assert r.status_code == 200
