import os

import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.db import make_session_factory
from app.main import create_app
from app.models import tenants, users


@pytest.fixture
def app_settings(lab_env):
    return Settings(
        jwt_secret="test-jwt-secret-" + "x" * 40,
        # The restricted role, matching what the real app connects as -
        # not the table owner. If this test suite passes, the API works
        # under the same DB permissions production actually has.
        database_url=(
            f"postgresql+psycopg2://shadowtracer_app:{lab_env['APP_DB_PASSWORD']}"
            f"@127.0.0.1:5432/{lab_env['POSTGRES_DB']}"
        ),
        clickhouse_host="127.0.0.1", clickhouse_port=8123,
        clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
        clickhouse_database="shadowtracer",
        kafka_bootstrap_servers="127.0.0.1:9094",
        writer_consumer_group="shadowtracer-writer",
        access_token_ttl_seconds=2,  # short, for the expiry test
        refresh_token_ttl_seconds=3600,
        lockout_threshold=5,
        lockout_window_seconds=900,
    )


@pytest.fixture
def client(app_settings, monkeypatch, db):
    os.environ.setdefault("JWT_SECRET", app_settings.jwt_secret)
    app = create_app()
    app.state.settings = app_settings
    app.state.session_factory = make_session_factory(app_settings)
    # base_url must be https:// - the refresh cookie is Secure (as it
    # should be), and httpx's cookie jar correctly withholds Secure
    # cookies over the default plain-http://testserver base url, same as
    # a real browser would. This isn't a workaround for a test quirk, it's
    # confirming the Secure flag actually does what it's supposed to.
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def test_user(db, tenant_id):
    db.execute(
        users.insert().values(
            tenant_id=tenant_id, email="bob@example.com",
            password_hash=security.hash_password("correct horse battery staple"),
            role="analyst",
        )
    )
    db.commit()
    return "bob@example.com"


def test_login_success_sets_httponly_secure_refresh_cookie(client, test_user):
    resp = client.post("/auth/login", json={"email": test_user, "password": "correct horse battery staple"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["role"] == "analyst"

    cookie_header = resp.headers.get("set-cookie", "")
    assert "refresh_token=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "access_token" not in cookie_header  # access token never goes in a cookie


def test_login_wrong_password_401(client, test_user):
    resp = client.post("/auth/login", json={"email": test_user, "password": "wrong"})
    assert resp.status_code == 401


def test_login_nonexistent_user_401_not_500(client):
    resp = client.post("/auth/login", json={"email": "nobody@example.com", "password": "whatever"})
    assert resp.status_code == 401


def test_refresh_rotates_token_and_replay_revokes_family(client, test_user):
    login_resp = client.post("/auth/login", json={"email": test_user, "password": "correct horse battery staple"})
    old_cookie = client.cookies.get("refresh_token")
    assert old_cookie

    refresh_resp = client.post("/auth/refresh")
    assert refresh_resp.status_code == 200
    new_cookie = client.cookies.get("refresh_token")
    assert new_cookie != old_cookie

    # Replay the OLD (already-rotated-away) cookie directly.
    client.cookies.set("refresh_token", old_cookie)
    replay_resp = client.post("/auth/refresh")
    assert replay_resp.status_code == 401

    # The legitimate rotated-to token must now be rejected too - the
    # whole family was revoked by the replay, not just the old token.
    client.cookies.set("refresh_token", new_cookie)
    revoked_resp = client.post("/auth/refresh")
    assert revoked_resp.status_code == 401


def test_refresh_without_cookie_401(client):
    resp = client.post("/auth/refresh")
    assert resp.status_code == 401


def test_logout_clears_cookie(client, test_user):
    client.post("/auth/login", json={"email": test_user, "password": "correct horse battery staple"})
    resp = client.post("/auth/logout")
    assert resp.status_code == 200
    cookie_header = resp.headers.get("set-cookie", "")
    assert "refresh_token=" in cookie_header
    assert "Max-Age=0" in cookie_header or 'refresh_token=""' in cookie_header
