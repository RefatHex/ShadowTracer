import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.db import make_session_factory
from app.main import create_app
from app.models import users


@pytest.fixture
def app_settings(lab_env, test_postgres_db, test_clickhouse_db):
    return Settings(
        jwt_secret="test-jwt-secret-" + "x" * 40,
        database_url=(
            f"postgresql+psycopg2://shadowtracer_app:{lab_env['APP_DB_PASSWORD']}"
            f"@127.0.0.1:5432/{test_postgres_db}"
        ),
        clickhouse_host="127.0.0.1", clickhouse_port=8123,
        clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
        clickhouse_database=test_clickhouse_db,
        kafka_bootstrap_servers="127.0.0.1:9094",
        writer_consumer_group="shadowtracer-writer",
    )


@pytest.fixture
def client(app_settings, db):
    app = create_app()
    app.state.settings = app_settings
    app.state.session_factory = make_session_factory(app_settings)
    return TestClient(app, base_url="https://testserver")


def _login_and_get_token(client, email, password) -> str:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def viewer_token(client, db, tenant_id):
    db.execute(users.insert().values(
        tenant_id=tenant_id, email="viewer@example.com",
        password_hash=security.hash_password("correct horse battery staple"), role="viewer",
    ))
    db.commit()
    return _login_and_get_token(client, "viewer@example.com", "correct horse battery staple")


@pytest.fixture
def admin_token(client, db, tenant_id):
    db.execute(users.insert().values(
        tenant_id=tenant_id, email="admin@example.com",
        password_hash=security.hash_password("correct horse battery staple"), role="admin",
    ))
    db.commit()
    return _login_and_get_token(client, "admin@example.com", "correct horse battery staple")


def test_health_liveness_requires_no_auth(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_ready_requires_no_auth_and_reports_healthy(client):
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["checks"]["postgres"]["ok"] is True
    assert body["checks"]["clickhouse"]["ok"] is True
    assert body["checks"]["kafka"]["ok"] is True


def test_health_detail_requires_auth(client):
    resp = client.get("/health/detail")
    assert resp.status_code == 401


def test_health_detail_viewer_gets_403(client, viewer_token):
    resp = client.get("/health/detail", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp.status_code == 403


def test_health_detail_admin_gets_200(client, admin_token):
    resp = client.get("/health/detail", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert "shipper_lag" in body
    assert "writer_consumer_lag" in body
    assert "last_event_time_per_tenant" in body
    assert "dead_letter_counts" in body
    assert body["dead_letter_counts"]["alert"] is False
