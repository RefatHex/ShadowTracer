import datetime
import uuid

import clickhouse_connect
import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.db import make_session_factory
from app.main import create_app
from app.models import users

COLUMNS = [
    "tenant_id", "time", "cluster_node", "manager_name", "alert_id",
    "agent_id", "agent_name", "agent_ip",
    "rule_id", "rule_level", "rule_description", "rule_groups",
    "mitre_ids", "mitre_tactics", "mitre_techniques",
    "src_endpoint_ip", "src_endpoint_port", "dst_endpoint_ip", "dst_endpoint_port",
    "actor_user", "target_user",
    "decoder_name", "location", "message", "extra_fields", "raw_event",
]


def _event_row(tenant_id: str, alert_id: str, time: datetime.datetime, message: str = "test alert"):
    return [
        tenant_id, time, "testnode", "wazuh-testnode", alert_id,
        "001", "test-agent", "10.0.0.1",
        "5710", 5, "test rule", [], [], [], [],
        "", 0, "", 0, "", "",
        "test", "test", message, {}, "{}",
    ]


@pytest.fixture
def ch_client(lab_env):
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database="shadowtracer",
    )
    yield client
    client.close()


@pytest.fixture
def app_settings(lab_env):
    return Settings(
        jwt_secret="test-jwt-secret-" + "x" * 40,
        database_url=(
            f"postgresql+psycopg2://shadowtracer_app:{lab_env['APP_DB_PASSWORD']}"
            f"@127.0.0.1:5432/{lab_env['POSTGRES_DB']}"
        ),
        clickhouse_host="127.0.0.1", clickhouse_port=8123,
        clickhouse_user=lab_env["CLICKHOUSE_USER"], clickhouse_password=lab_env["CLICKHOUSE_PASSWORD"],
        clickhouse_database="shadowtracer",
        kafka_bootstrap_servers="127.0.0.1:9094",
        writer_consumer_group="shadowtracer-writer",
    )


@pytest.fixture
def client(app_settings, db):
    app = create_app()
    app.state.settings = app_settings
    app.state.session_factory = make_session_factory(app_settings)
    return TestClient(app, base_url="https://testserver")


def _token_for_tenant(client, db, tenant_pg_id, email, role="viewer"):
    db.execute(users.insert().values(
        tenant_id=tenant_pg_id, email=email,
        password_hash=security.hash_password("correct horse battery staple"), role=role,
    ))
    db.commit()
    resp = client.post("/auth/login", json={"email": email, "password": "correct horse battery staple"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(autouse=True)
def _clean_test_events(ch_client):
    yield
    ch_client.command("ALTER TABLE events DELETE WHERE cluster_node = 'testnode'")


def test_alerts_scoped_to_callers_tenant(client, db, ch_client):
    """Postgres's tenant_id (relational, used in the JWT) and ClickHouse's
    tenant_id column (a string the shipper stamps on each event) are
    different types in this lab - using str(pg_tenant_id) as the CH
    column value for both tenants here makes the scoping comparison exact
    without conflating the two concepts."""
    from app.models import tenants

    marker = uuid.uuid4().hex[:8]
    now = datetime.datetime.now(datetime.timezone.utc)

    tenant_a_id = db.execute(tenants.insert().values(name=f"tenant-a-{marker}").returning(tenants.c.id)).scalar_one()
    tenant_b_id = db.execute(tenants.insert().values(name=f"tenant-b-{marker}").returning(tenants.c.id)).scalar_one()
    db.commit()

    rows_a = [_event_row(str(tenant_a_id), f"a-{marker}-{i}", now - datetime.timedelta(seconds=i), f"alert-a-{i}") for i in range(3)]
    rows_b = [_event_row(str(tenant_b_id), f"b-{marker}-{i}", now - datetime.timedelta(seconds=i), f"alert-b-{i}") for i in range(3)]
    ch_client.insert("events", rows_a + rows_b, column_names=COLUMNS)

    token_a = _token_for_tenant(client, db, tenant_a_id, f"viewer-a-{marker}@example.com")

    resp = client.get("/api/alerts", headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 200
    body = resp.json()
    messages = {a["message"] for a in body["alerts"]}
    assert messages == {"alert-a-0", "alert-a-1", "alert-a-2"}
    assert "alert-b-0" not in messages


def test_alerts_requires_auth(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 401


def test_alerts_keyset_pagination(client, db, ch_client):
    from app.models import tenants

    marker = uuid.uuid4().hex[:8]
    now = datetime.datetime.now(datetime.timezone.utc)
    tenant_pg_id = db.execute(tenants.insert().values(name=f"tenant-page-{marker}").returning(tenants.c.id)).scalar_one()
    db.commit()

    rows = [_event_row(str(tenant_pg_id), f"p-{marker}-{i}", now - datetime.timedelta(seconds=i), f"alert-{i}") for i in range(5)]
    ch_client.insert("events", rows, column_names=COLUMNS)

    token = _token_for_tenant(client, db, tenant_pg_id, f"viewer-page-{marker}@example.com")

    page1 = client.get("/api/alerts", params={"limit": 2}, headers={"Authorization": f"Bearer {token}"}).json()
    assert len(page1["alerts"]) == 2
    assert page1["next_cursor"] is not None
    # Most recent first: alert-0 (seconds=0) is newest.
    assert page1["alerts"][0]["message"] == "alert-0"
    assert page1["alerts"][1]["message"] == "alert-1"

    page2 = client.get(
        "/api/alerts", params={"limit": 2, "cursor": page1["next_cursor"]},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert len(page2["alerts"]) == 2
    assert page2["alerts"][0]["message"] == "alert-2"
    assert page2["alerts"][1]["message"] == "alert-3"

    # No overlap between pages.
    page1_ids = {a["alert_id"] for a in page1["alerts"]}
    page2_ids = {a["alert_id"] for a in page2["alerts"]}
    assert not (page1_ids & page2_ids)


def test_security_headers_present_on_every_response(client):
    resp = client.get("/health")
    assert resp.headers["Content-Security-Policy"]
    assert resp.headers["Strict-Transport-Security"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_generic_error_body_has_no_stack_trace():
    """A route that genuinely raises an unhandled exception must still
    come back as a generic 500 with no traceback/exception text leaked."""
    from fastapi import FastAPI
    from app.security_headers import install_generic_error_handler

    app = FastAPI()
    install_generic_error_handler(app)

    @app.get("/boom")
    def boom():
        raise ValueError("some internal detail that must never reach the client")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 500
    assert resp.json() == {"detail": "internal server error"}
    assert "some internal detail" not in resp.text
    assert "ValueError" not in resp.text
    assert "Traceback" not in resp.text
