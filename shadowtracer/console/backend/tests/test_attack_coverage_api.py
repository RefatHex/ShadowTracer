import os

import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.db import make_session_factory
from app.main import create_app
from app.models import users

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
REAL_RULESET_DIR = os.path.join(REPO_ROOT, "ruleset", "rules")
REAL_MITRE_JSON = os.path.join(REPO_ROOT, "ruleset", "mitre", "enterprise-attack.json")


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
        ruleset_dir=REAL_RULESET_DIR,
        mitre_json_path=REAL_MITRE_JSON,
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


def test_attack_coverage_requires_auth(client):
    resp = client.get("/api/attack-coverage")
    assert resp.status_code == 401


def test_attack_coverage_viewer_gets_200_real_data(client, viewer_token):
    """Read-only reference data - a viewer can see it, same as alerts."""
    resp = client.get("/api/attack-coverage", headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert "NOT a claim" in body["label"]
    assert body["technique_count"] > 100
    assert "T1110" in body["techniques"]
    assert "credential-access" in body["techniques"]["T1110"]["tactics"]
    assert len(body["techniques"]["T1110"]["rule_ids"]) > 0
    # the one known non-static templated id must never leak into the API
    assert "$(threat.software.id)" not in body["techniques"]
