"""Phase 6.3: VirusTotal worker (real Postgres, fake VirusTotal and fake managers) and
the analyst lookup / admin settings API."""
import datetime
import json
import os
import sys
import uuid

from sqlalchemy import text

from app import health as health_checks
from app.models import audit_log, incident_alerts, incidents
from test_incidents_api import _clean_test_events, _make_incident, _token_for, app_settings, ch_client, client, tenant  # noqa: F401

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "intel"))
from shadowtracer_intel import vt  # noqa: E402

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
OTHER = "a" * 64


def hl_http(known=()):
    """Fake CIRCL hashlookup bulk endpoint: records (known-good) only for sha1s in `known`."""
    known = {h.upper() for h in known}
    import json as _j

    def post(url, payload, timeout):
        recs = [{"SHA-1": h, "db": "nsrl", "source": "RDS", "RDS:package_id": "1"} for h in payload["hashes"] if h in known]
        return 200, _j.dumps(recs).encode()
    return post
REPORT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 62, "suspicious": 0, "undetected": 8, "harmless": 0},
                                  "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"},
                                  "first_submission_date": 1148301722, "last_analysis_date": 1793900000,
                                  "last_analysis_results": {"A": {"category": "malicious", "result": "EICAR-Test-File"}}}}}


class FakeNode:
    def __init__(self, name):
        self.name, self.spool, self.sent = name, {}, []

    def deployed(self):
        return True

    def spool_take(self, limit=500):
        return list(self.spool.items())[:limit]

    def spool_delete(self, names):
        for n in names:
            self.spool.pop(n, None)

    def spool_discard(self):
        n = len(self.spool)
        self.spool.clear()
        return n

    def send_event(self, message):
        self.sent.append(message)

    def fim(self, alert_id, sha256, agent_id="002", sha1="s", path=None):
        self.spool[f"{sha256}.{alert_id}.json"] = {
            "sha256": sha256, "md5": "m", "sha1": sha1, "path": path or f"/fim/{alert_id}", "alert_id": alert_id,
            "alert_time": "2026-11-06T12:00:00.000+0000", "rule_id": "554", "node": self.name,
            "agent": {"id": agent_id, "name": "agent-x", "ip": "any"}}


def _new_tenant(db):
    from app.models import tenants
    key = f"vt-{uuid.uuid4().hex[:8]}"
    tid = db.execute(tenants.insert().values(name=key, tenant_key=key).returning(tenants.c.id)).scalar_one()
    db.commit()
    return tid, key


def _settings(db, tenant_key, enabled, budget=500, disabled=None):
    db.execute(text("INSERT INTO ti_tenant_settings (tenant_key, vt_enabled, vt_daily_budget, disabled_sources, updated_by) "
                    "VALUES (:t, :e, :b, :d, 'test') ON CONFLICT (tenant_key) DO UPDATE SET vt_enabled = :e, "
                    "vt_daily_budget = :b, disabled_sources = :d"),
               {"t": tenant_key, "e": enabled, "b": budget, "d": disabled or []})
    db.commit()


def test_worker_lookup_once_cache_budget_opt_out_and_incident_link(db, engine):
    _, on = _new_tenant(db)
    _, off = _new_tenant(db)
    _settings(db, on, True, budget=500)
    _settings(db, off, False, disabled=["hashlookup"])   # fully opted out: free layer off too, so it discards
    n_on, n_off = FakeNode("n-on"), FakeNode("n-off")
    calls = []

    def fake_http(url, headers, timeout=20):
        calls.append(url)
        return 200, json.dumps(REPORT).encode()

    worker = vt.VTWorker(engine, [{"tenant_key": on, "nodes": [["n-on", "c1"]]}, {"tenant_key": off, "nodes": [["n-off", "c2"]]}],
                         {on: "key-1", off: "key-1"}, lambda name, c: {"n-on": n_on, "n-off": n_off}[name], http=fake_http,
                         hashlookup_http=hl_http())
    incident_id = _make_incident(db, on, agent_id="002")
    db.execute(incident_alerts.insert().values(incident_id=incident_id, tenant_key=on, node="n-on", alert_id="a1",
                                               alert_time=datetime.datetime.now(datetime.timezone.utc)))
    db.commit()

    # Two FIM alerts with the same new hash, plus one from a tenant that has not opted in.
    n_on.fim("a1", EICAR)
    n_on.fim("a2", EICAR)
    n_off.fim("z1", EICAR)
    worker.step()
    assert len(calls) == 1 and calls[0].endswith(EICAR)                 # ONE lookup for the hash
    assert n_off.spool == {} and worker.stats["discarded_opt_in_off"] == 1
    assert db.execute(text("SELECT count(*) FROM vt_requests WHERE tenant_key = :t"), {"t": off}).scalar_one() == 0
    assert len(n_on.sent) == 2 and all("->virustotal:" in m and '"malicious": 1' in m for m in n_on.sent)
    v = db.execute(text("SELECT status, malicious, total, labels, expires_at - fetched_at AS ttl FROM vt_verdicts "
                        "WHERE tenant_key = :t"), {"t": on}).mappings().one()
    assert (v["status"], v["malicious"], v["total"], v["ttl"]) == ("malicious", 62, 70, datetime.timedelta(days=30))
    ti = db.execute(text("SELECT incident_id, sources, confidence FROM incident_ti WHERE tenant_key = :t AND alert_id = 'a1'"),
                    {"t": on}).mappings().one()
    assert (ti["incident_id"], ti["sources"], ti["confidence"]) == (incident_id, ["virustotal"], 90)
    inc = db.execute(incidents.select().where(incidents.c.id == incident_id)).mappings().one()
    assert (inc["ti_confidence"], inc["priority"]) == (90, 12)
    ioc = db.execute(text("SELECT i.tenant_key, i.tlp FROM iocs i WHERE i.value = :h AND i.tenant_key = :t"),
                     {"h": EICAR, "t": on}).mappings().one()
    assert ioc["tlp"] == "amber"                                         # tenant-private, never global

    # The same hash again: answered from the cache, no call.
    n_on.fim("a3", EICAR)
    worker.step()
    assert len(calls) == 1 and len(n_on.sent) == 3
    assert db.execute(text("SELECT served_from FROM vt_requests WHERE tenant_key = :t AND alert_id = 'a3'"), {"t": on}).scalar_one() == "cache"

    # Budget forced to 1 (already spent): a second distinct hash waits, health shows it.
    _settings(db, on, True, budget=1)
    n_on.fim("a4", OTHER)
    worker.step()
    assert len(calls) == 1
    assert db.execute(text("SELECT state FROM vt_requests WHERE tenant_key = :t AND alert_id = 'a4'"), {"t": on}).scalar_one() == "pending"
    h = health_checks.virustotal(db)["tenants"][on]
    assert (h["queued"], h["calls_today"], h["daily_budget"], h["budget_reached"]) == (1, 1, 1, True)
    assert on in health_checks.virustotal(db)["budget_reached"]


def test_budget_reasons_and_quota_cooldown(db, engine):
    _, t = _new_tenant(db)
    now = datetime.datetime.now(datetime.timezone.utc)
    fp = vt.key_fp(f"k-{t}")
    with engine.begin() as conn:
        assert vt.budget(conn, t, fp, now, 10)["allowed"]
        for i in range(4):
            conn.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, called_at, outcome) VALUES (:k, :t, :h, :at, 'clean')"),
                         {"k": fp, "t": t, "h": OTHER, "at": now - datetime.timedelta(seconds=10 + i)})
        assert vt.budget(conn, t, fp, now, 10)["reason"] == "key per-minute limit"          # public API: 4/min
        assert vt.budget(conn, t, fp, now + datetime.timedelta(seconds=70), 10)["allowed"]
        assert vt.budget(conn, t, fp, now + datetime.timedelta(seconds=70), 4)["reason"] == "tenant daily budget"
    _settings(db, t, True)
    node = FakeNode("n")
    node.fim("q1", OTHER)
    w = vt.VTWorker(engine, [{"tenant_key": t, "nodes": [["n", "c"]]}], {t: "k2"}, lambda n, c: node,
                    hashlookup_http=hl_http(),
                    http=lambda url, headers, timeout=20: (429, b"{}"))
    w.step()
    w.step()                                                             # in cooldown: no second call
    rows = db.execute(text("SELECT http_status, outcome FROM vt_calls WHERE tenant_key = :t AND key_fp = :k"), {"t": t, "k": vt.key_fp("k2")}).all()
    assert rows == [(429, "quota_exceeded")]


def test_lookup_api_opt_in_cache_queue_budget_and_audit(client, db, tenant):
    tenant_id, tenant_key = tenant
    admin = _token_for(client, db, tenant_id, f"admin-{uuid.uuid4().hex[:8]}@example.com", role="admin")
    analyst = _token_for(client, db, tenant_id, f"analyst-{uuid.uuid4().hex[:8]}@example.com", role="analyst")
    viewer = _token_for(client, db, tenant_id, f"viewer-{uuid.uuid4().hex[:8]}@example.com")
    H = lambda tok: {"Authorization": f"Bearer {tok}"}  # noqa: E731

    assert client.get("/api/ti/settings", headers=H(admin)).json() == {"vt_enabled": False, "vt_daily_budget": 500, "disabled_sources": []}
    assert client.post("/api/ti/virustotal/lookups", json={"sha256": EICAR}, headers=H(viewer)).status_code == 403
    assert client.post("/api/ti/virustotal/lookups", json={"sha256": EICAR}, headers=H(analyst)).status_code == 409
    assert client.put("/api/ti/settings", json={"vt_enabled": True, "vt_daily_budget": 2}, headers=H(analyst)).status_code == 403
    r = client.put("/api/ti/settings", json={"vt_enabled": True, "vt_daily_budget": 2}, headers=H(admin))
    assert r.status_code == 200 and r.json()["vt_enabled"] is True
    assert client.post("/api/ti/virustotal/lookups", json={"sha256": "nothex"}, headers=H(analyst)).status_code == 422

    r = client.post("/api/ti/virustotal/lookups", json={"sha256": EICAR.upper()}, headers=H(analyst))
    assert r.status_code == 202 and r.json() == {"status": "queued", "sha256": EICAR}
    client.post("/api/ti/virustotal/lookups", json={"sha256": EICAR}, headers=H(analyst))
    assert db.execute(text("SELECT count(*) FROM vt_requests WHERE tenant_key = :t AND state = 'pending'"),
                      {"t": tenant_key}).scalar_one() == 1                # one queued lookup per hash
    assert client.get(f"/api/ti/virustotal/{EICAR}", headers=H(analyst)).json()["status"] == "queued"

    now = datetime.datetime.now(datetime.timezone.utc)
    with db.begin_nested():
        vt.store_verdict(db.connection(), tenant_key, {
            "sha256": EICAR, "status": "malicious", "malicious": 62, "suspicious": 0, "total": 70, "labels": ["virus.eicar/test"],
            "first_submission": None, "last_analysis": now, "permalink": vt.GUI.format(EICAR), "fetched_at": now,
            "expires_at": now + vt.TTL["malicious"]})
    db.commit()
    r = client.post("/api/ti/virustotal/lookups", json={"sha256": EICAR}, headers=H(analyst))
    assert r.status_code == 200 and r.json()["status"] == "cached" and r.json()["verdict"]["malicious"] == 62

    for i in range(2):
        db.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, outcome) VALUES ('fp', :t, :h, 'clean')"),
                   {"t": tenant_key, "h": OTHER})
    db.commit()
    r = client.post("/api/ti/virustotal/lookups", json={"sha256": OTHER}, headers=H(analyst))
    assert r.status_code == 202 and r.json()["status"] == "budget_reached"

    actions = [a for (a,) in db.execute(audit_log.select().with_only_columns(audit_log.c.outcome).where(
        audit_log.c.action == "virustotal_lookup", audit_log.c.target.in_([EICAR, OTHER]))).all()]
    assert actions[:1] == ["refused:disabled"] and "queued" in actions and "cached" in actions and "budget_reached" in actions
    assert db.execute(audit_log.select().where(audit_log.c.action == "ti_settings_changed")).first() is not None


def test_quota_backoff_doubles_and_survives_a_restart(db, engine):
    """6.4: a key refused with HTTP 429 waits 65 s, then 130 s, ... (cap 6 h), computed from
    vt_calls - a restarted worker does not retry a refused key early."""
    fp = vt.key_fp(f"backoff-{uuid.uuid4().hex}")
    t0 = datetime.datetime(2026, 11, 6, 8, 31, tzinfo=datetime.timezone.utc)
    with engine.begin() as conn:
        assert vt.quota_cooldown_until(conn, fp) is None
        for i in range(3):
            conn.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, called_at, http_status, outcome) "
                              "VALUES (:k, 'x', :h, :at, 429, 'quota_exceeded')"),
                         {"k": fp, "h": OTHER, "at": t0 + datetime.timedelta(minutes=i)})
        assert vt.quota_cooldown_until(conn, fp) == t0 + datetime.timedelta(minutes=2, seconds=260)   # 65 s x 2^2
        conn.execute(text("INSERT INTO vt_calls (key_fp, tenant_key, sha256, called_at, http_status, outcome) "
                          "VALUES (:k, 'x', :h, :at, 200, 'clean')"), {"k": fp, "h": OTHER, "at": t0 + datetime.timedelta(hours=1)})
        assert vt.quota_cooldown_until(conn, fp) is None                                             # a success resets it


def test_free_layer_known_good_downranks_only_in_expected_paths(db, engine):
    """Phase 6.5 A1 gap fix: a known-good binary in /usr/bin is down-ranked (priority lowered, "known
    file"); the same binary in /tmp keeps its priority and is labelled "known file in unusual
    location". Neither is sent to VirusTotal (tenant is VT-off; free layer on)."""
    _, t = _new_tenant(db)
    _settings(db, t, False)
    node = FakeNode("n")
    kg_sha1, kg_sha256 = "b" * 40, "c" * 64
    node.fim("good", kg_sha256, sha1=kg_sha1, path="/usr/bin/ls")
    node.fim("tmp", kg_sha256, sha1=kg_sha1, path="/tmp/ls")
    inc_good = _make_incident(db, t, agent_id="002")
    inc_tmp = _make_incident(db, t, agent_id="002")
    for iid, aid in ((inc_good, "good"), (inc_tmp, "tmp")):
        db.execute(incident_alerts.insert().values(incident_id=iid, tenant_key=t, node="n", alert_id=aid,
                                                   alert_time=datetime.datetime.now(datetime.timezone.utc)))
    db.commit()
    tmp_before = db.execute(incidents.select().where(incidents.c.id == inc_tmp)).mappings().one()["priority"]

    worker = vt.VTWorker(engine, [{"tenant_key": t, "nodes": [["n", "c"]]}], {}, lambda n, c: node,
                         http=lambda *a, **k: (_ for _ in ()).throw(AssertionError("VT must not be called")),
                         hashlookup_http=hl_http(known={kg_sha1}))
    worker.step()

    good = db.execute(incidents.select().where(incidents.c.id == inc_good)).mappings().one()
    tmp = db.execute(incidents.select().where(incidents.c.id == inc_tmp)).mappings().one()
    assert good["known_good"] and good["known_good_safe"] and good["known_good_note"] == "known file"
    assert good["priority"] <= 2                                   # down-ranked in an expected path
    assert tmp["known_good"] and not tmp["known_good_safe"] and tmp["known_good_note"] == "known file in unusual location"
    assert tmp["priority"] == tmp_before and tmp["priority"] > 2   # priority kept in /tmp
    assert node.sent == [] and db.execute(text("SELECT count(*) FROM vt_calls WHERE tenant_key = :t"), {"t": t}).scalar_one() == 0


def test_malwarebazaar_checked_before_virustotal(db, engine):
    """6.5 C: MalwareBazaar runs before VirusTotal. A hit resolves the hash malicious without a VT
    call (served_from=malwarebazaar) and links the incident; a miss falls through to VirusTotal."""
    _, t = _new_tenant(db)
    _settings(db, t, True)                        # VT enabled: a MBZ miss must fall through to VT
    db.execute(text("INSERT INTO tenant_source_keys (tenant_key, source, enabled, sealed_key, key_fingerprint, key_last4, key_version) "
                    "VALUES (:t, 'malwarebazaar', true, 'sealed-x', 'fp', 'last', 1)"), {"t": t})
    db.commit()
    mal_sha, unk_sha = "a" * 64, "b" * 64
    node = FakeNode("n")
    node.fim("mal", mal_sha, path="/tmp/evil")
    node.fim("unk", unk_sha, path="/tmp/maybe")
    inc_mal, inc_unk = _make_incident(db, t, agent_id="002"), _make_incident(db, t, agent_id="002")
    for iid, aid in ((inc_mal, "mal"), (inc_unk, "unk")):
        db.execute(incident_alerts.insert().values(incident_id=iid, tenant_key=t, node="n", alert_id=aid,
                                                   alert_time=datetime.datetime.now(datetime.timezone.utc)))
    db.commit()

    def mbz_http(url, data, headers, timeout=20):
        if mal_sha in data.decode():
            return 200, json.dumps({"query_status": "ok", "data": [{"sha256_hash": mal_sha, "signature": "AgentTesla",
                                    "tags": ["exe"], "first_seen": "2024-01-02 03:04:05"}]}).encode()
        return 200, json.dumps({"query_status": "hash_not_found"}).encode()

    def vt_http(url, headers, timeout=20):
        assert mal_sha not in url, "a MalwareBazaar hit must short-circuit VirusTotal"
        return 200, json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 70},
                                "last_analysis_results": {}}}}).encode()

    worker = vt.VTWorker(engine, [{"tenant_key": t, "nodes": [["n", "c"]]}], {t: "vtkey"}, lambda n, c: node,
                         http=vt_http, hashlookup_http=hl_http(known=set()),
                         source_key_loader=lambda tk, s: "MBZ-KEY" if (tk == t and s == "malwarebazaar") else None,
                         mbz_http=mbz_http)
    worker.step()

    mal = db.execute(text("SELECT state, served_from, funnel_reason, mbz_checked FROM vt_requests "
                          "WHERE tenant_key=:t AND alert_id='mal'"), {"t": t}).mappings().one()
    assert mal["state"] == "resolved" and mal["served_from"] == "malwarebazaar" and mal["funnel_reason"] == "mbz_malicious"
    unk = db.execute(text("SELECT served_from, funnel_reason, mbz_checked FROM vt_requests "
                          "WHERE tenant_key=:t AND alert_id='unk'"), {"t": t}).mappings().one()
    assert unk["mbz_checked"] and unk["funnel_reason"] == "mbz_unknown" and unk["served_from"] == "api"
    # the incident for the malicious hash is annotated with a MalwareBazaar TI match
    assert db.execute(text("SELECT count(*) FROM incident_ti WHERE tenant_key=:t AND 'malwarebazaar' = ANY(sources)"),
                      {"t": t}).scalar_one() >= 1
    # both verdicts cached; a second cycle makes no new MalwareBazaar call (cache hit)
    assert db.execute(text("SELECT count(*) FROM source_verdicts WHERE tenant_key=:t AND source='malwarebazaar'"),
                      {"t": t}).scalar_one() == 2
    before = db.execute(text("SELECT count(*) FROM source_calls WHERE tenant_key=:t"), {"t": t}).scalar_one()
    worker.step()
    assert db.execute(text("SELECT count(*) FROM source_calls WHERE tenant_key=:t"), {"t": t}).scalar_one() == before
