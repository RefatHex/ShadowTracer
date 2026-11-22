"""Phase 7.8: recurrence-forecast API tests. Deterministic - inserts incidents at controlled first_seen
timestamps (events >1h apart so burst-collapse keeps them) and checks the forecast."""
import datetime
import uuid

from sqlalchemy import text

from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401

from app.models import fingerprints, incidents

UTC = datetime.timezone.utc


def _hdr(client, db, tenant, role="analyst"):
    tid, _ = tenant
    return {"Authorization": f"Bearer {_token_for(client, db, tid, f'{role}-{uuid.uuid4().hex[:8]}@x.io', role=role)}"}


def _fp(db, tenant_key) -> str:
    key = f"fpfc-{uuid.uuid4().hex[:12]}"
    db.execute(fingerprints.insert().values(tenant_key=tenant_key, fingerprint_key=key))
    db.commit()
    return key


def _occ(db, tenant_key, fp, when, agent="001"):
    db.execute(incidents.insert().values(
        tenant_key=tenant_key, correlation_key=f"{agent}|srcip:8.8.8.8", correlation_basis="source_ip",
        agent_id=agent, first_seen=when, last_seen=when, alert_count=5, max_level=5, state="closed",
        fingerprint_key=fp))
    db.commit()


def test_fingerprint_forecast_happy_path(client, db, tenant):
    _tid, tkey = tenant
    fp = _fp(db, tkey)
    base = datetime.datetime.now(UTC) - datetime.timedelta(days=10)
    for i in range(5):                                   # 5 events, ~2 days apart
        _occ(db, tkey, fp, base + datetime.timedelta(days=2 * i))
    r = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant))
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["occurrences"] == 5
    assert body["confidence"] in ("low", "medium", "high")
    assert body["predicted_start"] and body["predicted_end"]
    assert body["predicted_end"] >= body["predicted_start"]
    assert len(body["events"]) == 5                      # timeline data


def test_bursts_collapse_to_events(client, db, tenant):
    # 10 incidents within one hour = ONE event -> not enough distinct events.
    _tid, tkey = tenant
    fp = _fp(db, tkey)
    base = datetime.datetime.now(UTC) - datetime.timedelta(days=1)
    for i in range(10):
        _occ(db, tkey, fp, base + datetime.timedelta(minutes=i))   # all within 10 min
    r = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant)).json()
    assert r["status"] == "not_enough_history"
    assert r["raw_occurrences"] == 10                    # raw incidents counted, but only 1 event


def test_not_enough_history(client, db, tenant):
    _tid, tkey = tenant
    fp = _fp(db, tkey)
    base = datetime.datetime.now(UTC) - datetime.timedelta(days=5)
    for i in range(2):
        _occ(db, tkey, fp, base + datetime.timedelta(days=i))
    r = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant)).json()
    assert r["status"] == "not_enough_history"
    assert r["raw_occurrences"] == 2


def test_new_occurrence_updates_forecast(client, db, tenant):
    _tid, tkey = tenant
    fp = _fp(db, tkey)
    base = datetime.datetime.now(UTC) - datetime.timedelta(days=20)
    for i in range(5):
        _occ(db, tkey, fp, base + datetime.timedelta(days=2 * i))
    first = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant)).json()
    # a brand-new occurrence after the last one
    _occ(db, tkey, fp, datetime.datetime.now(UTC))
    second = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant)).json()
    assert second["occurrences"] == first["occurrences"] + 1
    assert second["last_occurrence"] > first["last_occurrence"]     # recompute-on-view picked it up


def test_cross_tenant_fingerprint_is_404(client, db, tenant):
    _tid, tkey = tenant
    r = client.get(f"/api/fingerprints/does-not-exist-{uuid.uuid4().hex}/forecast",
                   headers=_hdr(client, db, tenant))
    assert r.status_code == 404


def test_forecast_requires_analyst(client, db, tenant):
    _tid, tkey = tenant
    fp = _fp(db, tkey)
    r = client.get(f"/api/fingerprints/{fp}/forecast", headers=_hdr(client, db, tenant, role="viewer"))
    assert r.status_code == 403


def test_campaign_forecast(client, db, tenant):
    _tid, tkey = tenant
    # build a campaign with 4 member incidents spread over days
    base = datetime.datetime.now(UTC) - datetime.timedelta(days=12)
    cid = db.execute(text(
        "INSERT INTO campaigns (tenant_key, fingerprint_key, actor_type, actor_value, first_seen, last_seen, "
        "incident_count) VALUES (:t, :f, 'source_ip', :v, :fs, :ls, 0) RETURNING id"),
        {"t": tkey, "f": "fp-camp", "v": f"9.9.9.{uuid.uuid4().int % 250}",
         "fs": base, "ls": base + datetime.timedelta(days=9)}).scalar()
    for i in range(4):
        iid = db.execute(incidents.insert().values(
            tenant_key=tkey, correlation_key=f"c|{i}", correlation_basis="source_ip", agent_id="001",
            first_seen=base + datetime.timedelta(days=3 * i), last_seen=base + datetime.timedelta(days=3 * i),
            alert_count=5, max_level=5, state="closed").returning(incidents.c.id)).scalar_one()
        db.execute(text("INSERT INTO campaign_incidents (campaign_id, incident_id, tenant_key) "
                        "VALUES (:c, :i, :t)"), {"c": cid, "i": iid, "t": tkey})
    db.commit()
    r = client.get(f"/api/campaigns/{cid}/forecast", headers=_hdr(client, db, tenant)).json()
    assert r["status"] == "ok" and r["occurrences"] == 4
    # cross-tenant / missing campaign
    bad = client.get("/api/campaigns/999999999/forecast", headers=_hdr(client, db, tenant))
    assert bad.status_code == 404
