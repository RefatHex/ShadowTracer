"""Phase 7.8 demo: Live view overview + the demo fast-close setting (RBAC, validation, persistence),
against the real isolated CH + PG test DBs (same harness as test_incidents_api)."""
import datetime
import uuid

from sqlalchemy import text

from test_incidents_api import (  # noqa: F401
    COLUMNS, _event_row, _make_incident, _token_for, app_settings, ch_client, client, tenant,
)


def _hdr(client, db, tenant, role="viewer"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def test_overview_counts_tenant_events_and_incidents(client, db, ch_client, tenant):
    _tid, tkey = tenant
    now = datetime.datetime.now(datetime.timezone.utc)
    ch_client.insert("events", [_event_row(tkey, f"a{i}", now, message=f"m{i}") for i in range(3)], column_names=COLUMNS)
    _make_incident(db, tkey, agent_id="060", alert_count=4)

    r = client.get("/api/live/overview", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    body = r.json()
    assert body["tenant"] == tkey
    assert body["events_total"] >= 3
    assert body["incidents_total"] >= 1
    assert [s["name"] for s in body["stages"]] == ["Agent events", "Alerts → Kafka", "Stored", "Incidents"]
    # upstream stages are null without LIVE_SHIPPER_METRICS_URL; stored/incidents come from the stores
    assert body["stages"][2]["value"] == body["events_total"]
    assert any(a["message"].startswith("m") for a in body["recent_alerts"])
    assert any(inc["agent_id"] == "060" for inc in body["recent_incidents"])


def test_demo_settings_roundtrip_rbac_and_validation(client, db, tenant):
    admin = _hdr(client, db, tenant, role="admin")
    viewer = _hdr(client, db, tenant, role="viewer")

    # default: off
    assert client.get("/api/live/demo-settings", headers=viewer).json()["fast_close_seconds"] is None
    # admin sets it
    assert client.put("/api/live/demo-settings", json={"fast_close_seconds": 60}, headers=admin).status_code == 200
    assert client.get("/api/live/demo-settings", headers=viewer).json()["fast_close_seconds"] == 60
    # viewer cannot change it
    assert client.put("/api/live/demo-settings", json={"fast_close_seconds": 30}, headers=viewer).status_code == 403
    # out of range rejected
    assert client.put("/api/live/demo-settings", json={"fast_close_seconds": 5}, headers=admin).status_code == 422
    # admin clears it
    assert client.put("/api/live/demo-settings", json={"fast_close_seconds": None}, headers=admin).status_code == 200
    assert client.get("/api/live/demo-settings", headers=viewer).json()["fast_close_seconds"] is None


def test_overview_is_tenant_scoped(client, db, ch_client, tenant):
    _tid, tkey = tenant
    now = datetime.datetime.now(datetime.timezone.utc)
    ch_client.insert("events", [_event_row(tkey, "secret", now, message="secret")], column_names=COLUMNS)
    # a brand-new unrelated tenant sees none of tkey's events
    m = uuid.uuid4().hex[:8]
    other_id = db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :k) RETURNING id"),
                          {"n": f"other-{m}", "k": f"key-other-{m}"}).scalar_one()
    db.commit()
    hdr = {"Authorization": f"Bearer {_token_for(client, db, other_id, f'o-{m}@x.io')}"}
    body = client.get("/api/live/overview", headers=hdr).json()
    assert body["events_total"] == 0 and body["incidents_total"] == 0
