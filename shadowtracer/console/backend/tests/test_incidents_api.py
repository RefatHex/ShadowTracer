import datetime
import uuid

import clickhouse_connect
import pytest
from fastapi.testclient import TestClient

from app import security
from app.config import Settings
from app.db import make_session_factory
from app.main import create_app
from app.models import audit_log, fingerprints, incident_alerts, incidents, tenant_alert_settings, tenants, users

COLUMNS = [
    "tenant_id", "time", "cluster_node", "manager_name", "alert_id",
    "agent_id", "agent_name", "agent_ip",
    "rule_id", "rule_level", "rule_description", "rule_groups",
    "mitre_ids", "mitre_tactics", "mitre_techniques",
    "src_endpoint_ip", "src_endpoint_port", "dst_endpoint_ip", "dst_endpoint_port",
    "actor_user", "target_user",
    "decoder_name", "location", "message", "extra_fields", "raw_event",
]


def _event_row(tenant_key, alert_id, time, message="test alert", cluster_node="testnode"):
    return [
        tenant_key, time, cluster_node, "wazuh-testnode", alert_id,
        "001", "test-agent", "10.0.0.1",
        "5710", 5, "test rule", [], [], [], [],
        "", 0, "", 0, "", "",
        "test", "test", message, {}, "{}",
    ]


@pytest.fixture
def ch_client(lab_env, test_clickhouse_db):
    client = clickhouse_connect.get_client(
        host="127.0.0.1", port=8123,
        username=lab_env["CLICKHOUSE_USER"], password=lab_env["CLICKHOUSE_PASSWORD"],
        database=test_clickhouse_db,
    )
    yield client
    client.close()


@pytest.fixture(autouse=True)
def _clean_test_events(ch_client):
    yield
    ch_client.command("ALTER TABLE events DELETE WHERE cluster_node = 'testnode'")


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


@pytest.fixture
def tenant(db):
    marker = uuid.uuid4().hex[:8]
    tenant_key = f"key-{marker}"
    tenant_id = db.execute(
        tenants.insert().values(name=f"tenant-{marker}", tenant_key=tenant_key).returning(tenants.c.id)
    ).scalar_one()
    db.commit()
    return tenant_id, tenant_key


def _token_for(client, db, tenant_pg_id, email, role="viewer"):
    db.execute(users.insert().values(
        tenant_id=tenant_pg_id, email=email,
        password_hash=security.hash_password("correct horse battery staple"), role=role,
    ))
    db.commit()
    resp = client.post("/auth/login", json={"email": email, "password": "correct horse battery staple"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _make_incident(
    db, tenant_key, agent_id="agent-1", alert_count=10, fingerprint_key=None, state="open",
    rare_pattern_flag=False, prior_occurrences=None, rare_pattern_reason=None,
):
    now = datetime.datetime.now(datetime.timezone.utc)
    incident_id = db.execute(
        incidents.insert().values(
            tenant_key=tenant_key, correlation_key=f"{agent_id}|srcip:8.8.8.8", correlation_basis="source_ip",
            agent_id=agent_id, first_seen=now, last_seen=now, alert_count=alert_count, max_level=5,
            state=state, fingerprint_key=fingerprint_key,
            rare_pattern_flag=rare_pattern_flag, prior_occurrences=prior_occurrences,
            rare_pattern_reason=rare_pattern_reason,
        ).returning(incidents.c.id)
    ).scalar_one()
    db.commit()  # the route handler uses a different session/connection - must be committed to be visible to it
    return incident_id


def test_incident_list_and_detail_include_real_clickhouse_alert_content(client, db, ch_client, tenant):
    tenant_id, tenant_key = tenant
    marker = uuid.uuid4().hex[:8]
    now = datetime.datetime.now(datetime.timezone.utc)

    incident_id = _make_incident(db, tenant_key, agent_id=f"agent-{marker}")
    db.execute(incident_alerts.insert().values(
        incident_id=incident_id, tenant_key=tenant_key, node="testnode", alert_id=f"a-{marker}", alert_time=now,
    ))
    db.commit()
    ch_client.insert(
        "events", [_event_row(tenant_key, f"a-{marker}", now, message=f"real-alert-{marker}")], column_names=COLUMNS,
    )

    token = _token_for(client, db, tenant_id, f"viewer-{marker}@example.com")

    list_resp = client.get("/api/incidents", headers={"Authorization": f"Bearer {token}"})
    assert list_resp.status_code == 200
    assert any(i["id"] == incident_id for i in list_resp.json()["incidents"])

    detail_resp = client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {token}"})
    assert detail_resp.status_code == 200
    body = detail_resp.json()
    assert body["id"] == incident_id
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["message"] == f"real-alert-{marker}"


def test_viewer_cannot_triage_gets_403(client, db, tenant):
    tenant_id, tenant_key = tenant
    marker = uuid.uuid4().hex[:8]
    incident_id = _make_incident(db, tenant_key)
    token = _token_for(client, db, tenant_id, f"viewer-{marker}@example.com", role="viewer")

    resp = client.post(
        f"/api/incidents/{incident_id}/triage", json={"action": "acknowledge"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_analyst_triage_updates_status_and_is_audited(client, db, tenant):
    tenant_id, tenant_key = tenant
    marker = uuid.uuid4().hex[:8]
    incident_id = _make_incident(db, tenant_key)
    token = _token_for(client, db, tenant_id, f"analyst-{marker}@example.com", role="analyst")

    resp = client.post(
        f"/api/incidents/{incident_id}/triage", json={"action": "acknowledge"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["triage_status"] == "acknowledged"

    audit_rows = db.execute(
        audit_log.select().where(audit_log.c.action == "incident_triage:acknowledge")
    ).mappings().all()
    assert len(audit_rows) == 1
    assert audit_rows[0]["target"] == str(incident_id)


def test_suppression_flow_via_the_real_api(client, db, tenant):
    """5 false-positive triages from 2 distinct analysts -> proposed (via
    the triage endpoint), then an admin activates it via the suppress
    endpoint - the full Step 4 state machine driven entirely through
    HTTP, not by calling the business logic module directly."""
    tenant_id, tenant_key = tenant
    marker = uuid.uuid4().hex[:8]
    fingerprint_key = f"fp-{marker}"
    db.execute(fingerprints.insert().values(tenant_key=tenant_key, fingerprint_key=fingerprint_key))
    db.commit()

    analyst_a_token = _token_for(client, db, tenant_id, f"analyst-a-{marker}@example.com", role="analyst")
    analyst_b_token = _token_for(client, db, tenant_id, f"analyst-b-{marker}@example.com", role="analyst")
    admin_token = _token_for(client, db, tenant_id, f"admin-{marker}@example.com", role="admin")

    tokens = [analyst_a_token] * 4 + [analyst_b_token]
    last_resp = None
    for token in tokens:
        incident_id = _make_incident(db, tenant_key, fingerprint_key=fingerprint_key, state="closed")
        last_resp = client.post(
            f"/api/incidents/{incident_id}/triage", json={"action": "false_positive"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert last_resp.status_code == 200

    assert last_resp.json()["suppression_state_changed_to"] == "proposed"

    fp_resp = client.get(f"/api/fingerprints/{fingerprint_key}", headers={"Authorization": f"Bearer {admin_token}"})
    assert fp_resp.status_code == 200
    assert fp_resp.json()["suppression_state"] == "proposed"
    assert fp_resp.json()["verdicts"]["false_positive"] == 5
    assert fp_resp.json()["verdicts"]["distinct_false_positive_analysts"] == 2

    # Analyst cannot approve suppression - admin only.
    forbidden = client.post(
        f"/api/fingerprints/{fingerprint_key}/suppress", json={},
        headers={"Authorization": f"Bearer {analyst_a_token}"},
    )
    assert forbidden.status_code == 403

    approve_resp = client.post(
        f"/api/fingerprints/{fingerprint_key}/suppress", json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["suppression_state"] == "active"

    audit_actions = {
        row["action"] for row in db.execute(audit_log.select()).mappings().all()
    }
    assert "fingerprint_suppression_proposed" in audit_actions
    assert "fingerprint_suppression_activated" in audit_actions


def test_fresh_tenant_warmup_status_is_incomplete(client, db, tenant):
    """Phase 5B Step 3: a fresh tenant with no incidents at all must show
    an incomplete warm-up status via the real API, no row required in
    tenant_alert_settings to get the default (7 days, 30 incidents)."""
    tenant_id, tenant_key = tenant
    token = _token_for(client, db, tenant_id, f"viewer-{uuid.uuid4().hex[:8]}@example.com")

    resp = client.get("/api/rare-pattern-warmup-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["complete"] is False
    assert body["incident_count"] == 0
    assert body["warmup_days"] == 7
    assert body["warmup_min_incidents"] == 30


def test_warmup_status_respects_per_tenant_override(client, db, tenant):
    tenant_id, tenant_key = tenant
    db.execute(tenant_alert_settings.insert().values(
        tenant_key=tenant_key, rare_alert_warmup_days=1, rare_alert_warmup_min_incidents=1,
    ))
    db.commit()
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
    db.execute(incidents.insert().values(
        tenant_key=tenant_key, correlation_key="k", correlation_basis="source_ip", agent_id="agent-1",
        first_seen=old_time, last_seen=old_time, created_at=old_time,
    ))
    db.commit()
    token = _token_for(client, db, tenant_id, f"viewer-{uuid.uuid4().hex[:8]}@example.com")

    resp = client.get("/api/rare-pattern-warmup-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["complete"] is True
    assert body["warmup_days"] == 1
    assert body["warmup_min_incidents"] == 1


def test_warmup_override_is_admin_only_and_audited(client, db, tenant):
    """Phase 5C Step 0: loosening/tightening warm-up changes which
    incidents get a rare-pattern flag at all - same bar as any other
    tenant-wide alerting config change, so it's admin-only and audited,
    same pattern as agents.py's role-tag endpoint."""
    tenant_id, tenant_key = tenant
    analyst_token = _token_for(client, db, tenant_id, f"analyst-{uuid.uuid4().hex[:8]}@example.com", role="analyst")
    admin_token = _token_for(client, db, tenant_id, f"admin-{uuid.uuid4().hex[:8]}@example.com", role="admin")

    forbidden = client.put(
        "/api/rare-pattern-warmup-override", json={"warmup_days": 0, "warmup_min_incidents": 1},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert forbidden.status_code == 403

    resp = client.put(
        "/api/rare-pattern-warmup-override", json={"warmup_days": 0, "warmup_min_incidents": 1},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["warmup_days"] == 0
    assert resp.json()["warmup_min_incidents"] == 1

    row = db.execute(
        tenant_alert_settings.select().where(tenant_alert_settings.c.tenant_key == tenant_key)
    ).mappings().one()
    assert row["rare_alert_warmup_days"] == 0
    assert row["rare_alert_warmup_min_incidents"] == 1

    audit_rows = db.execute(
        audit_log.select().where(audit_log.c.action == "rare_pattern_warmup_override_changed")
    ).mappings().all()
    assert len(audit_rows) == 1
    assert audit_rows[0]["outcome"] == "success"
    assert audit_rows[0]["tenant_id"] == tenant_id
    assert "warmup_days=0" in audit_rows[0]["target"]

    # Calling it again (an update, not an insert) must overwrite in place,
    # not add a second row - and audit the second change too.
    resp2 = client.put(
        "/api/rare-pattern-warmup-override", json={"warmup_days": 3, "warmup_min_incidents": 5},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp2.status_code == 200
    rows_after = db.execute(
        tenant_alert_settings.select().where(tenant_alert_settings.c.tenant_key == tenant_key)
    ).mappings().all()
    assert len(rows_after) == 1
    assert rows_after[0]["rare_alert_warmup_days"] == 3
    audit_rows_after = db.execute(
        audit_log.select().where(audit_log.c.action == "rare_pattern_warmup_override_changed")
    ).mappings().all()
    assert len(audit_rows_after) == 2


def test_rare_pattern_flag_surfaces_in_list_and_detail(client, db, tenant):
    """A rare-pattern flag is additive - the incident appears in the list
    and detail exactly as any other would, with the flag/count/reason
    alongside everything else, never hiding or replacing anything."""
    tenant_id, tenant_key = tenant
    incident_id = _make_incident(
        db, tenant_key, rare_pattern_flag=True, prior_occurrences=0,
        rare_pattern_reason="Never seen before for this tenant - this is the first occurrence of this fingerprint.",
    )
    token = _token_for(client, db, tenant_id, f"viewer-{uuid.uuid4().hex[:8]}@example.com")

    list_resp = client.get("/api/incidents", headers={"Authorization": f"Bearer {token}"})
    assert list_resp.status_code == 200
    item = next(i for i in list_resp.json()["incidents"] if i["id"] == incident_id)
    assert item["rare_pattern_flag"] is True
    assert item["prior_occurrences"] == 0

    detail_resp = client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {token}"})
    assert detail_resp.status_code == 200
    body = detail_resp.json()
    assert body["rare_pattern_flag"] is True
    assert "Never seen before" in body["rare_pattern_reason"]
