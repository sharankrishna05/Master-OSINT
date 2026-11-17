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


def test_admin_page_and_api_require_admin_role(monkeypatch):
    from osint_arsenal import config
    from osint_arsenal.api import routes
    import osint_arsenal.api.server as server
    monkeypatch.setattr(config.settings, "require_auth", True)
    monkeypatch.setattr(routes, "get_current_user_optional", lambda request: None)
    monkeypatch.setattr(server, "get_current_user_optional", lambda request: None)

    client = TestClient(create_app())

    assert client.get("/admin").status_code == 401
    assert client.get("/api/v2/admin/stats").status_code == 401

    me = client.get("/api/v2/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["role"] == "user"
    assert me.json()["user"]["email"] == "operator@workspace"

    html = client.get("/").text
    assert 'id="admin-panel-link"' in html
    assert 'id="admin-panel-link" onclick="window.location.href=\'/admin\'" class="hidden' in html

    regular_user = {"id": "regular-user", "email": "user@example.com", "role": "user"}
    monkeypatch.setattr(routes, "get_current_user_optional", lambda request: regular_user)
    monkeypatch.setattr(server, "get_current_user_optional", lambda request: regular_user)
    assert client.get("/admin").status_code == 403
    assert client.get("/api/v2/admin/stats").status_code == 403


def test_admin_dashboard_uses_admin_data_without_vault_secrets(monkeypatch):
    from osint_arsenal.api import routes
    admin = {"id": "admin-user", "email": "admin@example.com", "role": "admin"}
    monkeypatch.setattr(routes, "get_current_user_optional", lambda request: admin)
    monkeypatch.setattr(routes.auth_manager, "get_security_stats", lambda: {"total_users": 2})
    monkeypatch.setattr(routes.auth_manager, "list_users", lambda search="": [{"id": "user-1", "role": "user"}])
    monkeypatch.setattr(routes.auth_manager, "list_activity_logs", lambda **kwargs: [{"action": "LOGIN"}])
    monkeypatch.setattr(
        routes.auth_manager,
        "list_all_vault_inventory",
        lambda: [{
            "id": "vault-1",
            "user_email": "user@example.com",
            "service": "Example",
            "masked_secret": "ab****yz",
            "secret_key": "must-never-be-returned",
            "notes": "private note",
        }],
    )
    client = TestClient(create_app())

    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert "NEXUS OSINT / ADMINISTRATION" in dashboard.text

    assert client.get("/api/v2/admin/stats").json() == {"total_users": 2}
    assert client.get("/api/v2/admin/users").json()["users"][0]["id"] == "user-1"
    vault = client.get("/api/v2/admin/vault-inventory").json()["inventory"][0]
    assert vault["masked_secret"] == "ab****yz"
    assert "secret_key" not in vault
    assert "notes" not in vault


def test_platform_alias_renders_the_authenticated_app_template(monkeypatch):
    monkeypatch.setenv("ARSENAL_ALLOW_REGISTRATION", "0")
    monkeypatch.setenv("ARSENAL_ALLOW_GOOGLE_AUTH", "0")
    client = TestClient(create_app())

    response = client.get("/platform")

    assert response.status_code == 200
    assert 'id="admin-panel-link"' in response.text
    assert "{% if auth_allow_registration %}" not in response.text


def test_admin_cannot_demote_own_account(monkeypatch):
    from osint_arsenal.api import routes
    admin = {"id": "admin-user", "email": "admin@example.com", "role": "admin"}
    monkeypatch.setattr(routes, "get_current_user_optional", lambda request: admin)
    monkeypatch.setattr(routes.auth_manager, "get_user_by_id", lambda user_id: admin)

    def reject_role_change(*args, **kwargs):
        raise AssertionError("role change must be blocked")

    monkeypatch.setattr(routes.auth_manager, "set_user_role", reject_role_change)
    client = TestClient(create_app())

    response = client.patch(
        "/api/v2/admin/users/admin-user/role",
        json={"role": "user"},
    )

    assert response.status_code == 409


def test_auth_manager_preserves_last_verified_admin_and_bootstraps_configured_admin(tmp_path, monkeypatch):
    from osint_arsenal.auth_manager import AuthManager

    monkeypatch.delenv("ARSENAL_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ARSENAL_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ARSENAL_SEED_DEMO", "0")
    manager = AuthManager(db_path=tmp_path / "admin-guard.db")
    admin_id = manager.create_user(
        email="admin@example.com",
        password=None,
        name="Admin",
        role="admin",
        is_verified=True,
    )

    assert manager.set_user_role(admin_id, "user") is False
    assert manager.set_user_verified(admin_id, False) is False
    assert manager.toggle_user_active(admin_id, False) is False
    verified_user_id = manager.create_user(
        email="verified@example.com",
        password=None,
        name="Verified",
        role="user",
        is_verified=True,
    )
    verified_user = manager.get_user_by_id(verified_user_id)
    assert verified_user is not None
    token = manager.create_token(verified_user)
    assert manager.verify_token(token) is not None
    assert manager.set_user_verified(verified_user_id, False)
    assert manager.verify_token(token) is None

    user_id = manager.create_user(
        email="new@example.com",
        password=None,
        name="New",
        role="user",
        is_verified=True,
    )
    monkeypatch.setenv("ARSENAL_ADMIN_EMAIL", "new@example.com")
    monkeypatch.setenv("ARSENAL_ADMIN_PASSWORD", "configured-admin-password")
    AuthManager(db_path=tmp_path / "admin-guard.db")
    promoted = manager.get_user_by_id(user_id)
    assert promoted is not None
    assert promoted["role"] == "admin"
    assert promoted["is_verified"] == 1
    assert manager.authenticate_local("new@example.com", "configured-admin-password")[0] is True


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


def test_login_page_hides_disabled_auth_options(monkeypatch):
    from osint_arsenal import config

    monkeypatch.setattr(config.settings, "require_auth", True)
    monkeypatch.setenv("ARSENAL_ALLOW_REGISTRATION", "0")
    monkeypatch.setenv("ARSENAL_ALLOW_GOOGLE_AUTH", "0")
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="auth-tab-btn-register"' not in response.text
    assert 'id="auth-register-form"' not in response.text
    assert "Sign in with Google" not in response.text
    assert "ARSENAL_ADMIN_EMAIL" in response.text


def test_registration_creates_only_user_role(monkeypatch):
    from osint_arsenal.api import routes

    monkeypatch.setenv("ARSENAL_ALLOW_REGISTRATION", "1")
    created = {}
    monkeypatch.setattr(routes.auth_manager, "get_user_by_email", lambda email: None)

    def create_user(**kwargs):
        created.update(kwargs)
        return "new-user-id"

    monkeypatch.setattr(routes.auth_manager, "create_user", create_user)
    client = TestClient(create_app())

    response = client.post(
        "/api/v2/auth/register",
        json={"email": "new@example.com", "password": "long-enough", "name": "New User"},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == "new-user-id"
    assert created["role"] == "user"


def test_google_auth_rejects_unverified_email_claim(monkeypatch):
    monkeypatch.setenv("ARSENAL_ALLOW_GOOGLE_AUTH", "1")
    monkeypatch.setenv("ARSENAL_GOOGLE_CLIENT_ID", "configured-client-id")
    client = TestClient(create_app())

    response = client.post(
        "/api/v2/auth/google",
        json={"email": "admin@example.com", "name": "Admin"},
    )

    assert response.status_code == 401
    assert "verified Google sign-in credential" in response.json()["detail"]


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
