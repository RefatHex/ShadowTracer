"""Phase 6.4: TI in the console (incident TI section, false positives, IOC browser, settings)
and retro-hunt, against the real test database."""
import datetime
import os
import sys
import uuid
from types import SimpleNamespace

from sqlalchemy import text

from app.models import audit_log, incident_alerts
from app.routers import ti as ti_router
from test_incidents_api import _clean_test_events, _make_incident, _token_for, app_settings, ch_client, client, tenant  # noqa: F401

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "intel"))
from shadowtracer_intel import listgen, retro  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)


def _source(db, name, tenant_key=None):
    return db.execute(text(
        "INSERT INTO ti_sources (name, kind, tenant_key, stix_identity, trust, default_tlp) VALUES (:n, 'manual', :t, :sid, 1.0, 'clear') "
        "ON CONFLICT (name) DO UPDATE SET enabled = true RETURNING id"), {"n": name, "t": tenant_key, "sid": f"identity--{name}"}).scalar_one()


def _ioc(db, value, source_id, tenant_key=None, typ="ipv4", created=None, ref="https://feed.example/x"):
    ioc_id = db.execute(text(
        "INSERT INTO iocs (stix_id, tenant_key, type, value, pattern, tlp, labels, mitre, confidence, valid_from, last_seen, valid_until, created) "
        "VALUES (:sid, :t, :ty, :v, 'p', 'clear', ARRAY['botnet_cc'], ARRAY['T1071'], 90, :now, :now, :now, :c) RETURNING id"),
        {"sid": f"indicator--{uuid.uuid4()}", "t": tenant_key, "ty": typ, "v": value, "now": NOW,
         "c": created or NOW}).scalar_one()
    db.execute(text("INSERT INTO ioc_sightings (ioc_id, source_id, source_ref, reference_url, source_info, source_confidence, tlp, "
                    "first_seen, last_seen) VALUES (:i, :s, 'ref', :url, 'Example pulse', 0.9, 'clear', :now, :now)"),
               {"i": ioc_id, "s": source_id, "url": ref, "now": NOW})
    db.commit()
    return ioc_id


def _ip():
    return f"45.33.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250 + 1}"


def test_backend_ttl_table_matches_list_generation():
    assert ti_router.HARD_TTL_DAYS == listgen.HARD_TTL_DAYS


def test_incident_ti_section_and_false_positive_is_tenant_only(client, db, tenant, engine):
    tenant_id, tenant_key = tenant
    other = f"key-{uuid.uuid4().hex[:8]}"
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :n)"), {"n": other})
    src = _source(db, f"test-feed-{uuid.uuid4().hex[:6]}")
    ip = _ip()
    ioc_id = _ioc(db, ip, src)
    incident_id = _make_incident(db, tenant_key)
    db.execute(incident_alerts.insert().values(incident_id=incident_id, tenant_key=tenant_key, node="n1", alert_id="a1", alert_time=NOW))
    ti_id = db.execute(text(
        "INSERT INTO incident_ti (tenant_key, node, alert_id, alert_time, rule_id, incident_id, ioc_id, field, observable_type, "
        "observable, ioc_value, sources, confidence) VALUES (:t, 'n1', 'a1', now(), '5710', :inc, :ioc, 'data.srcip', 'ipv4', :ip, :ip, "
        ":s, 90) RETURNING id"), {"t": tenant_key, "inc": incident_id, "ioc": ioc_id, "ip": ip,
                                  "s": [db.execute(text("SELECT name FROM ti_sources WHERE id = :i"), {"i": src}).scalar_one()]}).scalar_one()
    db.commit()
    analyst = _token_for(client, db, tenant_id, f"a-{uuid.uuid4().hex[:8]}@example.com", role="analyst")
    viewer = _token_for(client, db, tenant_id, f"v-{uuid.uuid4().hex[:8]}@example.com")

    m = client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {viewer}"}).json()["ti_matches"][0]
    assert (m["observable"], m["ioc_type"], m["tlp"], m["labels"], m["mitre"], m["origin"], m["false_positive"]) == \
        (ip, "ipv4", "clear", ["botnet_cc"], ["T1071"], "matcher", False)
    assert m["source_details"][0]["reference_url"] == "https://feed.example/x" and m["source_details"][0]["source_info"] == "Example pulse"

    assert client.post("/api/ti/false-positives", json={"incident_ti_id": ti_id, "reason": "our scanner"},
                       headers={"Authorization": f"Bearer {viewer}"}).status_code == 403
    r = client.post("/api/ti/false-positives", json={"incident_ti_id": ti_id, "reason": "our scanner"},
                    headers={"Authorization": f"Bearer {analyst}"})
    assert r.status_code == 200 and r.json()["status"] == "allowlisted"
    assert client.get(f"/api/incidents/{incident_id}", headers={"Authorization": f"Bearer {viewer}"}).json()["ti_matches"][0]["false_positive"]
    row = db.execute(text("SELECT tenant_key, kind FROM ti_allowlist WHERE value = :ip"), {"ip": ip}).one()
    assert row == (tenant_key, "fp_marking")
    assert db.execute(text("SELECT label FROM ti_feedback WHERE incident_ti_id = :i"), {"i": ti_id}).scalar_one() == "false_positive"
    assert db.execute(audit_log.select().where(audit_log.c.action == "ti_false_positive", audit_log.c.target == f"ipv4:{ip}")).first()

    # List generation: the IOC is gone for this tenant only.
    with engine.begin() as conn:
        mine = listgen.generate(conn, tenant_key)[1]["entries"]
        theirs = listgen.generate(conn, other)[1]["entries"]
        conn.rollback()
    with engine.connect() as conn:
        rows, allow = listgen.load(conn, tenant_key, NOW)
        mine_ids = {ioc for ioc, *_ in listgen.evaluate(rows, allow, NOW)}
        rows, allow = listgen.load(conn, other, NOW)
        theirs_ids = {ioc for ioc, *_ in listgen.evaluate(rows, allow, NOW)}
    assert ioc_id not in mine_ids and ioc_id in theirs_ids
    assert mine.get("ipv4-high", 0) == theirs.get("ipv4-high", 0) - 1


def test_ioc_browser_scope_and_filters(client, db, tenant):
    tenant_id, tenant_key = tenant
    other = f"key-{uuid.uuid4().hex[:8]}"
    db.execute(text("INSERT INTO tenants (name, tenant_key) VALUES (:n, :n)"), {"n": other})
    gsrc, mysrc, theirsrc = _source(db, f"g-{uuid.uuid4().hex[:6]}"), _source(db, f"m-{uuid.uuid4().hex[:6]}", tenant_key), \
        _source(db, f"o-{uuid.uuid4().hex[:6]}", other)
    tag = uuid.uuid4().hex[:6]
    _ioc(db, f"{tag}-global.example", gsrc, typ="domain")
    _ioc(db, f"{tag}-mine.example", mysrc, tenant_key, typ="domain")
    _ioc(db, f"{tag}-theirs.example", theirsrc, other, typ="domain")
    tok = _token_for(client, db, tenant_id, f"v-{uuid.uuid4().hex[:8]}@example.com")
    H = {"Authorization": f"Bearer {tok}"}
    vals = lambda **p: {i["value"]: i["scope"] for i in client.get("/api/ti/iocs", params={"q": tag, **p}, headers=H).json()["iocs"]}  # noqa: E731
    assert vals() == {f"{tag}-global.example": "global", f"{tag}-mine.example": "tenant"}           # never another tenant's
    assert vals(scope="tenant") == {f"{tag}-mine.example": "tenant"}
    assert vals(type="ipv4") == {} and vals(min_confidence=95) == {} and vals(expiry="expired") == {}
    r = client.get("/api/ti/iocs", params={"q": tag, "scope": "global"}, headers=H).json()
    assert r["total"] == 1 and r["iocs"][0]["sources"] and r["iocs"][0]["expires_at"]


def test_settings_viewer_reads_but_cannot_change(client, db, tenant):
    tenant_id, _ = tenant
    viewer = _token_for(client, db, tenant_id, f"v-{uuid.uuid4().hex[:8]}@example.com")
    admin = _token_for(client, db, tenant_id, f"ad-{uuid.uuid4().hex[:8]}@example.com", role="admin")
    feed = f"feed-{uuid.uuid4().hex[:6]}"
    _source(db, feed)
    _, tenant_key = tenant
    db.execute(text("INSERT INTO ti_key_status (name, tenant_key, configured) VALUES ('virustotal', :t, true) "
                    "ON CONFLICT (name, tenant_key) DO NOTHING"), {"t": tenant_key})
    db.commit()
    assert client.get("/api/ti/settings", headers={"Authorization": f"Bearer {viewer}"}).status_code == 200
    assert client.get("/api/ti/overview", headers={"Authorization": f"Bearer {viewer}"}).status_code == 200
    assert client.put("/api/ti/settings", json={"vt_enabled": True}, headers={"Authorization": f"Bearer {viewer}"}).status_code == 403
    assert client.put("/api/ti/settings", json={"disabled_sources": ["no-such-feed"]},
                      headers={"Authorization": f"Bearer {admin}"}).status_code == 422
    r = client.put("/api/ti/settings", json={"disabled_sources": [feed]}, headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 200 and r.json()["disabled_sources"] == [feed]
    src = {s["name"]: s for s in client.get("/api/ti/overview", headers={"Authorization": f"Bearer {admin}"}).json()["sources"]}
    assert src[feed]["disabled_for_tenant"] is True
    keys = client.get("/api/ti/overview", headers={"Authorization": f"Bearer {viewer}"}).json()["keys"]
    assert keys["virustotal"] is True and all(isinstance(v, bool) for v in keys.values())   # yes/no only


class FakeCH:
    def __init__(self, rows):
        self.rows, self.inserted, self.queries = rows, [], []

    def query(self, sql, parameters=None, settings=None):
        self.queries.append(parameters)
        return SimpleNamespace(result_rows=self.rows)

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, rows, column_names))


def test_retro_hunt_matches_new_iocs_against_stored_events(db, engine, tenant):
    _, tenant_key = tenant
    ip = _ip()
    incident_id = _make_incident(db, tenant_key)
    old = NOW - datetime.timedelta(days=2)
    db.execute(incident_alerts.insert().values(incident_id=incident_id, tenant_key=tenant_key, node="n1", alert_id="old-1", alert_time=old))
    db.commit()
    assert retro.run(engine, FakeCH([]), tenant_key, now=NOW - datetime.timedelta(minutes=30))["retro"] == "initialised"
    src = _source(db, f"retro-{uuid.uuid4().hex[:6]}")
    _ioc(db, ip, src, created=NOW - datetime.timedelta(minutes=5))
    event = ("n1", "old-1", old.strftime("%Y-%m-%d %H:%M:%S.000"), "5710", ["syslog", "sshd"], {"data.srcip": ip})
    ch = FakeCH([event])
    out = retro.run(engine, ch, tenant_key, now=NOW, days=7)
    assert out["retro"]["matches"] == 1 and ip in ch.queries[0]["ips"]
    row = db.execute(text("SELECT origin, incident_id FROM incident_ti WHERE tenant_key = :t AND alert_id = 'old-1'"),
                     {"t": tenant_key}).one()
    assert row == ("retro", incident_id)
    table, rows, cols = ch.inserted[0]
    assert table == "ti_matches" and dict(zip(cols, rows[0]))["retro"] is True and dict(zip(cols, rows[0]))["origin"] == "retro"
    assert retro.run(engine, FakeCH([event]), tenant_key, now=NOW + datetime.timedelta(minutes=1))["retro"] == "skipped (interval)"
    again = retro.run(engine, FakeCH([event]), tenant_key, now=NOW + datetime.timedelta(minutes=20))
    assert again["retro"]["matches"] == 0                       # already matched: not written twice
