from fastapi.testclient import TestClient
from osint_arsenal.api.server import create_app


def test_health_and_subapps_mounted(tmp_path, monkeypatch):
    from osint_arsenal import config
    monkeypatch.setattr(config.settings, "db_path", str(tmp_path / "deploy.db"))
    monkeypatch.setenv("ARSENAL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARSENAL_REPORTS_DIR", str(tmp_path / "reports"))

    client = TestClient(create_app())

    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["osint_hub_available"] is True
    assert data["dorkforge_available"] is True

    r_status = client.get("/api/status")
    assert r_status.status_code == 200
    assert r_status.json()["status"] == "OPERATIONAL"

    r_hub = client.get("/api/v2/osint-hub/stats")
    assert r_hub.status_code == 200
    assert r_hub.json()["stats"]["total_tools"] > 0

    r_dork = client.get("/api/v2/dorkforge/templates")
    assert r_dork.status_code == 200

    r_ib_health = client.get("/intelbase/health")
    assert r_ib_health.status_code == 200
    assert r_ib_health.json()["status"] == "healthy"

    r_ib_ui = client.get("/intelbase/")
    assert r_ib_ui.status_code == 200

    r_ib_js = client.get("/intelbase/static/js/sse_client.js")
    assert r_ib_js.status_code == 200


def test_osint_hub_auto_seeds_fresh_db(tmp_path):
    from osint_hub.parse import get_db_stats
    fresh_db = tmp_path / "fresh_osint.db"
    stats = get_db_stats(db_path=fresh_db)
    assert stats["total_tools"] > 1000
    assert stats["total_sections"] >= 20


def test_auth_manager_respects_env_and_temp_db(tmp_path, monkeypatch):
    from osint_arsenal.auth_manager import AuthManager

    monkeypatch.delenv("ARSENAL_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ARSENAL_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ARSENAL_SEED_DEMO", "0")

    am = AuthManager(db_path=tmp_path / "auth.db")
    assert am.get_user_by_email("sharan.vaka@gmail.com") is None
    assert am.get_user_by_email("admin@nostromo.sec") is None

    monkeypatch.setenv("ARSENAL_ADMIN_EMAIL", "ops@example.com")
    monkeypatch.setenv("ARSENAL_ADMIN_PASSWORD", "StrongTestPass!23")
    am2 = AuthManager(db_path=tmp_path / "auth2.db")
    admin = am2.get_user_by_email("ops@example.com")
    assert admin is not None
    assert admin["role"] == "admin"


def test_admin_access_removed_from_ui_and_api(tmp_path, monkeypatch):
    from osint_arsenal import config
    monkeypatch.setattr(config.settings, "db_path", str(tmp_path / "no_admin.db"))
    monkeypatch.setenv("ARSENAL_DATA_DIR", str(tmp_path))

    client = TestClient(create_app())

    assert client.get("/admin").status_code == 404
    assert client.get("/api/v2/admin/stats").status_code == 404

    me = client.get("/api/v2/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["role"] == "user"
    assert me.json()["user"]["email"] == "operator@workspace"

    html = client.get("/").text
    assert "ADMIN PORTAL" not in html
    assert "user-role-badge" not in html
    assert "SHARAN.VAKA" not in html
    assert "Sharan@OSINT2026" not in html


def test_production_auth_gate_and_disabled_auth_flows(monkeypatch):
    from osint_arsenal import config
    import osint_arsenal.api.server as server

    monkeypatch.setattr(config.settings, "require_auth", True)
    monkeypatch.setattr(server, "get_current_user_optional", lambda request: None)
    monkeypatch.setenv("ARSENAL_ALLOW_REGISTRATION", "0")
    monkeypatch.setenv("ARSENAL_ALLOW_GOOGLE_AUTH", "0")
    client = TestClient(create_app())

    assert client.get("/api/v2/providers").status_code == 401
    assert client.post("/hub/api/scan", json={}).status_code == 401
    assert client.get("/intelbase/lookup?email=test@example.com").status_code == 401
    assert client.get("/reports/private.html").status_code == 401
    assert client.get("/api/v2/auth/me").status_code == 200
    assert client.post(
        "/api/v2/auth/register",
        json={"email": "new@example.com", "password": "long-enough", "name": "New"},
    ).status_code == 403
    assert client.post(
        "/api/v2/auth/google",
        json={"email": "new@example.com"},
    ).status_code == 403


def test_authenticated_api_allowed_in_production(monkeypatch):
    from osint_arsenal import config
    import osint_arsenal.api.server as server

    monkeypatch.setattr(config.settings, "require_auth", True)
    monkeypatch.setattr(
        server,
        "get_current_user_optional",
        lambda request: {"id": "test-user", "role": "admin"},
    )
    client = TestClient(create_app())

    assert client.get("/api/v2/providers").status_code == 200
